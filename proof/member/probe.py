"""Probe the live proof stack and write the results as JSON.

Usage:
    terraform output -json probe > probe-inputs.json
    python probe.py probe-inputs.json > ../../docs/proof/member-run.json

Read-back checks ask AWS what was actually created. Behavior checks send
one synthetic CloudTrail event, import one Security Hub finding and invoke
both auditor Lambdas, then wait for each module's SNS topic to deliver to
the capture queue. Account IDs in the output are replaced with 111122223333.
"""

import datetime
import json
import pathlib
import re
import sys
import time

import boto3

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
session = boto3.Session(region_name=cfg["region"])
account = session.client("sts").get_caller_identity()["Account"]
results = []


def check(module, name, fn):
    """fn returns (passed, observed). An exception is a failed check."""
    try:
        passed, observed = fn()
    except Exception as exc:  # noqa: BLE001 - the error text is the evidence
        passed, observed = False, f"{type(exc).__name__}: {exc}"
    results.append({"module": module, "check": name, "passed": bool(passed), "observed": observed})


def client(name):
    return session.client(name)


# --- read-back ----------------------------------------------------------------


def password_policy():
    p = client("iam").get_account_password_policy()["PasswordPolicy"]
    seen = {k: p.get(k) for k in ("MinimumPasswordLength", "PasswordReusePrevention", "ExpirePasswords")}
    return p["MinimumPasswordLength"] >= 15 and p.get("PasswordReusePrevention") == 24 and not p["ExpirePasswords"], seen


def ebs_default_encryption():
    ec2 = client("ec2")
    on = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    key = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    return on and "alias/aws/ebs" not in key, {"enabled": on, "customer_managed_key": "alias/aws/ebs" not in key}


def s3_public_access_block():
    c = client("s3control").get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
    return all(c.values()), c


def default_sgs_closed():
    groups = client("ec2").describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    default_vpcs = {v["VpcId"] for v in client("ec2").describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]}
    managed = [g for g in groups if g["VpcId"] in default_vpcs | {cfg["vpc_id"]}]
    rules = {g["VpcId"]: len(g["IpPermissions"]) + len(g["IpPermissionsEgress"]) for g in managed}
    return len(managed) == 2 and not any(rules.values()), {"default_security_groups": len(managed), "rules": sum(rules.values())}


def cmk_with_rotation(key_id):
    kms = client("kms")
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    return meta["KeyManager"] == "CUSTOMER" and kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]


def backup_vault():
    name = cfg["backup_vault_arn"].split(":")[-1]
    vault = client("backup").describe_backup_vault(BackupVaultName=name)
    ok = cmk_with_rotation(vault["EncryptionKeyArn"])
    return ok, {"vault": name, "rotating_customer_managed_key": ok}


def flow_logs():
    logs = client("ec2").describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [cfg["vpc_id"]]}])["FlowLogs"]
    seen = [{k: f[k] for k in ("FlowLogStatus", "TrafficType", "DeliverLogsStatus", "MaxAggregationInterval")} for f in logs]
    group = client("logs").describe_log_groups(logGroupNamePrefix=logs[0]["LogGroupName"])["logGroups"][0]
    seen.append({"log_group_kms": bool(group.get("kmsKeyId")), "retention_days": group.get("retentionInDays")})
    ok = logs[0]["FlowLogStatus"] == "ACTIVE" and logs[0]["TrafficType"] == "ALL" and logs[0]["DeliverLogsStatus"] == "SUCCESS"
    return ok and bool(group.get("kmsKeyId")), seen


def vpc_endpoints():
    ids = list(cfg["fips_endpoint_ids"].values()) + list(cfg["standard_endpoint_ids"].values())
    eps = client("ec2").describe_vpc_endpoints(VpcEndpointIds=ids)["VpcEndpoints"]
    seen = {e["ServiceName"].split(".", 3)[-1]: e["State"] for e in eps}
    fips = [s for s in seen if s.endswith("-fips")]
    return len(eps) == len(ids) and set(seen.values()) == {"available"} and len(fips) == len(cfg["fips_endpoint_ids"]), seen


def ecr():
    r = client("ecr").describe_repositories(repositoryNames=[cfg["ecr_repository"]])["repositories"][0]
    seen = {
        "imageTagMutability": r["imageTagMutability"],
        "scanOnPush": r["imageScanningConfiguration"]["scanOnPush"],
        "encryptionType": r["encryptionConfiguration"]["encryptionType"],
    }
    ok = seen == {"imageTagMutability": "IMMUTABLE", "scanOnPush": True, "encryptionType": "KMS"}
    return ok and cmk_with_rotation(r["encryptionConfiguration"]["kmsKey"]), seen


def ecs():
    c = client("ecs").describe_clusters(clusters=[cfg["ecs_cluster"]], include=["CONFIGURATIONS", "SETTINGS"])["clusters"][0]
    execute = c["configuration"]["executeCommandConfiguration"]
    insights = {s["name"]: s["value"] for s in c["settings"]}.get("containerInsights")
    seen = {"status": c["status"], "exec_logging": execute["logging"], "exec_kms": bool(execute.get("kmsKeyId")), "containerInsights": insights}
    return c["status"] == "ACTIVE" and execute["logging"] == "OVERRIDE" and seen["exec_kms"] and insights in ("enabled", "enhanced"), seen


def waf():
    waf2 = client("wafv2")
    name, acl_id = cfg["web_acl_arn"].split("/")[-2:]
    acl = waf2.get_web_acl(Name=name, Scope="REGIONAL", Id=acl_id)["WebACL"]
    logging = waf2.get_logging_configuration(ResourceArn=cfg["web_acl_arn"])["LoggingConfiguration"]
    rules = sorted(r["Name"] for r in acl["Rules"])
    redacted = sorted(f["SingleHeader"]["Name"] for f in logging.get("RedactedFields", []) if "SingleHeader" in f)
    seen = {"rules": rules, "default_action": next(iter(acl["DefaultAction"])), "logging_destinations": len(logging["LogDestinationConfigs"]), "redacted_headers": redacted}
    return len(rules) == 4 and seen["logging_destinations"] == 1 and "authorization" in redacted, seen


def rds_hardened():
    rds = client("rds")
    db = rds.describe_db_instances(DBInstanceIdentifier=cfg["hardened_db"])["DBInstances"][0]
    group = db["DBParameterGroups"][0]["DBParameterGroupName"]
    pages = rds.get_paginator("describe_db_parameters").paginate(DBParameterGroupName=group, Source="user")
    params = {p["ParameterName"]: p.get("ParameterValue") for page in pages for p in page["Parameters"]}
    seen = {
        "status": db["DBInstanceStatus"],
        "engine_version": db["EngineVersion"],
        "StorageEncrypted": db["StorageEncrypted"],
        "MultiAZ": db["MultiAZ"],
        "PubliclyAccessible": db["PubliclyAccessible"],
        "IAMDatabaseAuthenticationEnabled": db["IAMDatabaseAuthenticationEnabled"],
        "DeletionProtection": db["DeletionProtection"],
        "BackupRetentionPeriod": db["BackupRetentionPeriod"],
        "managed_master_secret": bool(db.get("MasterUserSecret")),
        "rds.force_ssl": params.get("rds.force_ssl"),
        "log_exports": db.get("EnabledCloudwatchLogsExports", []),
    }
    ok = (
        db["StorageEncrypted"] and db["MultiAZ"] and not db["PubliclyAccessible"] and db["IAMDatabaseAuthenticationEnabled"]
        and db["DeletionProtection"] and db["BackupRetentionPeriod"] == 35 and seen["managed_master_secret"]
        and params.get("rds.force_ssl") == "1" and cmk_with_rotation(db["KmsKeyId"])
    )
    return ok, seen


check("account-baseline", "Password policy follows NIST SP 800-63B-4", password_policy)
check("account-baseline", "EBS encryption is on by default with a customer managed key", ebs_default_encryption)
check("account-baseline", "S3 account-level public access block is fully on", s3_public_access_block)
check("account-baseline, network-perimeter-vpc", "Default security groups have no rules", default_sgs_closed)
check("account-baseline", "Backup vault uses a rotating customer managed key", backup_vault)
check("network-perimeter-vpc", "VPC flow log is active, captures all traffic, and its log group is encrypted", flow_logs)
check("fips-vpc-endpoints", "Every interface endpoint is available, including the -fips services", vpc_endpoints)
check("ecr-hardened", "Repository is immutable, scans on push and uses a rotating customer managed key", ecr)
check("ecs-fargate-hardened", "Cluster logs ECS Exec sessions with KMS and has Container Insights on", ecs)
check("waf-hardened", "Web ACL has its four rules and logs with the authorization header redacted", waf)
check("rds-postgres-hardened", "Instance is encrypted, Multi-AZ, private, TLS-only, IAM-authenticated and delete-protected", rds_hardened)

# --- behavior -----------------------------------------------------------------

now = datetime.datetime.now(datetime.timezone.utc)
sqs = client("sqs")
sqs.purge_queue(QueueUrl=cfg["capture_queue_url"])
time.sleep(60)  # a purge takes up to 60 seconds; messages sent sooner can be lost

# 1. A root-usage event in the CloudTrail stand-in group should trip the CIS alarm.
client("logs").create_log_stream(logGroupName=cfg["stand_in_log_group"], logStreamName=f"probe-{int(now.timestamp())}")
client("logs").put_log_events(
    logGroupName=cfg["stand_in_log_group"],
    logStreamName=f"probe-{int(now.timestamp())}",
    logEvents=[{
        "timestamp": int(time.time() * 1000),
        "message": json.dumps({"eventType": "AwsApiCall", "eventName": "ProofProbe", "userIdentity": {"type": "Root"}}),
    }],
)

# 2. A HIGH Security Hub finding should reach the incident topic.
finding_id = f"ftlproof/{int(now.timestamp())}"
finding = {
    "SchemaVersion": "2018-10-08",
    "Id": finding_id,
    "ProductArn": f"arn:{session.client('sts').meta.partition}:securityhub:{cfg['region']}:{account}:product/{account}/default",
    "GeneratorId": "ftlproof",
    "AwsAccountId": account,
    "Types": ["Software and Configuration Checks"],
    "CreatedAt": now.isoformat(),
    "UpdatedAt": now.isoformat(),
    "Severity": {"Label": "HIGH"},
    "Title": "Live proof probe (synthetic)",
    "Description": "Synthetic finding imported by proof/member/probe.py. Safe to ignore.",
    "Resources": [{"Type": "Other", "Id": "ftlproof"}],
}
imported = client("securityhub").batch_import_findings(Findings=[finding])


def invoke(arn):
    response = client("lambda").invoke(FunctionName=arn, Payload=b"{}")
    body = json.loads(response["Payload"].read())
    if response.get("FunctionError"):
        raise RuntimeError(json.dumps(body)[:500])
    return body


def trust_auditor():
    body = invoke(cfg["trust_auditor_lambda"])
    hits = [f for f in body["findings"] if f["resource"] == cfg["fixture_role_arn"]]
    seen = {"counts": body["counts"], "errors": body["errors"], "fixture_findings": [{k: f[k] for k in ("severity", "check", "detail")} for f in hits]}
    return len(hits) == 1 and hits[0]["severity"] == "HIGH" and hits[0]["check"] == "cross-account-trust" and not body["errors"], seen


def rds_auditor():
    body = invoke(cfg["rds_auditor_lambda"])
    by_db = {name: sorted(f["check"] for f in body["findings"] if f["resource"].endswith(f":db:{cfg[name]}")) for name in ("weak_db", "hardened_db")}
    seen = {"counts": body["counts"], "errors": body["errors"], "weak_fixture": by_db["weak_db"], "hardened_module": by_db["hardened_db"]}
    return by_db["weak_db"] == ["iam-auth", "master-credentials", "transport"] and not by_db["hardened_db"] and not body["errors"], seen


check("trust-policy-auditor", "Deployed Lambda flags the fixture role that trusts an outside account without sts:ExternalId", trust_auditor)
check("rds-access-auditor", "Deployed Lambda reports three findings on the weak fixture and none on rds-postgres-hardened", rds_auditor)

# Wait for each topic to deliver. The CIS alarm evaluates a 5 minute period.
arrived = {}
by_arn = {arn: name for name, arn in cfg["topics"].items()}
deadline = time.time() + 900
while time.time() < deadline and len(arrived) < len(by_arn):
    batch = sqs.receive_message(QueueUrl=cfg["capture_queue_url"], MaxNumberOfMessages=10, WaitTimeSeconds=20)
    for message in batch.get("Messages", []):
        envelope = json.loads(message["Body"])
        arrived.setdefault(by_arn.get(envelope.get("TopicArn"), "unknown"), envelope)
        sqs.delete_message(QueueUrl=cfg["capture_queue_url"], ReceiptHandle=message["ReceiptHandle"])


def delivered(topic, needle):
    def fn():
        if topic not in arrived:
            return False, "nothing delivered within 15 minutes"
        envelope = arrived[topic]
        text = f"{envelope.get('Subject') or ''} {envelope['Message']}"
        return needle in text, {"subject": envelope.get("Subject"), "message_excerpt": envelope["Message"][:300]}
    return fn


check("logging-monitoring", "A root-usage event raises cis-root-account-usage and the KMS-encrypted topic delivers it", delivered("cis", "cis-root-account-usage"))
check("incident-notifications", "A HIGH Security Hub finding is routed to the KMS-encrypted incident topic", delivered("incident", finding_id))
check("trust-policy-auditor", "Findings are published to the auditor's KMS-encrypted topic", delivered("trust", "ftlproof-external-trust-fixture"))
check("rds-access-auditor", "Findings are published to the auditor's KMS-encrypted topic", delivered("rds", "ftlproof-weak"))

# Take the synthetic finding out of the active set.
client("securityhub").batch_update_findings(
    FindingIdentifiers=[{"Id": finding_id, "ProductArn": finding["ProductArn"]}],
    Workflow={"Status": "RESOLVED"},
    Note={"Text": "Synthetic proof finding", "UpdatedBy": "probe.py"},
)

report = {
    "run_at": now.isoformat(timespec="seconds"),
    "region": cfg["region"],
    "passed": sum(r["passed"] for r in results),
    "total": len(results),
    "security_hub_import": {"failed": imported["FailedCount"], "succeeded": imported["SuccessCount"]},
    "results": results,
}
print(re.sub(account, "111122223333", json.dumps(report, indent=2, default=str)))
sys.exit(0 if report["passed"] == report["total"] else 1)
