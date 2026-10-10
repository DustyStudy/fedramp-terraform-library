"""Probe the patching, CloudTrail-key and access-control proof stacks.

Usage, from a stack directory, with that account's credentials exported:
    terraform output -json probe > probe-inputs.json
    python ../controls_probe.py probe-inputs.json > run.json

    # Before terraform destroy: the proof buckets are versioned and the
    # modules do not set force_destroy.
    python ../controls_probe.py probe-inputs.json --empty-buckets

The checks that run depend on which keys the inputs file has, so the same
script serves all three stacks. Account IDs in the output are replaced
with 111122223333.
"""

import datetime
import json
import pathlib
import re
import sys
import time

import boto3
from botocore.exceptions import ClientError

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
session = boto3.Session(region_name=cfg["region"])
account = session.client("sts").get_caller_identity()["Account"]
started = datetime.datetime.now(datetime.timezone.utc)
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


def wait_for(fn, seconds, every=15):
    """Poll fn until it returns something truthy; return the last value."""
    deadline = time.time() + seconds
    while True:
        value = fn()
        if value or time.time() > deadline:
            return value
        time.sleep(every)


def conditions(statement):
    """{condition key: values} across every operator of one statement."""
    return {key: values for keyed in statement.get("Condition", {}).values() for key, values in keyed.items()}


def bucket_key(bucket):
    rules = client("s3").get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    return rules[0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"]


def first_object(bucket, prefix):
    return client("s3").list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1).get("Contents")


def encrypted_with_bucket_key(bucket, key):
    head = client("s3").head_object(Bucket=bucket, Key=key)
    return head.get("ServerSideEncryption") == "aws:kms" and head.get("SSEKMSKeyId") == bucket_key(bucket)


# --- ssm-patching-hardened ----------------------------------------------------


def node_is_managed():
    def online():
        found = client("ssm").describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [cfg["instance_id"]]}]
        )["InstanceInformationList"]
        return found if found and found[0]["PingStatus"] == "Online" else None

    found = wait_for(online, 600)
    seen = {k: found[0][k] for k in ("PingStatus", "PlatformName", "PlatformVersion")} if found else "not registered"
    return bool(found), seen


def patch_group_uses_module_baseline():
    baseline = client("ssm").get_patch_baseline_for_patch_group(
        PatchGroup="FedRAMPCompliance", OperatingSystem="AMAZON_LINUX_2023"
    )["BaselineId"]
    return baseline == cfg["patch_baseline_id"], {"baseline": baseline, "module_baseline": cfg["patch_baseline_id"]}


scan = {}


def patch_scan_runs_under_module_baseline():
    ssm = client("ssm")
    scan["id"] = ssm.send_command(
        InstanceIds=[cfg["instance_id"]],
        DocumentName="AWS-RunPatchBaseline",
        Parameters={"Operation": ["Scan"]},
        OutputS3BucketName=cfg["patch_logs_bucket"],
        OutputS3KeyPrefix="probe",
    )["Command"]["CommandId"]

    def finished():
        try:
            invocation = ssm.get_command_invocation(CommandId=scan["id"], InstanceId=cfg["instance_id"])
        except ClientError:
            return None  # not visible yet
        return invocation if invocation["Status"] not in ("Pending", "InProgress", "Delayed") else None

    invocation = wait_for(finished, 900)
    status = invocation["Status"] if invocation else "timed out"
    state = ssm.describe_instance_patch_states(InstanceIds=[cfg["instance_id"]])["InstancePatchStates"]
    baseline = state[0]["BaselineId"] if state else None
    seen = {"scan": status, "baseline": baseline, "module_baseline": cfg["patch_baseline_id"]}
    if state:
        seen.update({k: state[0][k] for k in ("InstalledCount", "MissingCount", "FailedCount")})
    return status == "Success" and baseline == cfg["patch_baseline_id"], seen


def patch_output_reaches_encrypted_bucket():
    prefix = f"probe/{scan['id']}/"
    found = wait_for(lambda: first_object(cfg["patch_logs_bucket"], prefix), 120)
    seen = {"writer_policy_attached": cfg["writer_policy_attached"], "objects_under_prefix": bool(found)}
    if not found:
        return False, seen
    seen["encrypted_with_bucket_key"] = encrypted_with_bucket_key(cfg["patch_logs_bucket"], found[0]["Key"])
    return seen["encrypted_with_bucket_key"], seen


def window_role_trust():
    document = client("iam").get_role(RoleName=cfg["maintenance_window_role"])["Role"]["AssumeRolePolicyDocument"]
    seen = conditions(document["Statement"][0])
    return seen.get("aws:SourceAccount") == account and "aws:SourceArn" in seen, seen


def window_runs_patch_task():
    ssm = client("ssm")

    def done():
        runs = ssm.describe_maintenance_window_executions(WindowId=cfg["maintenance_window_id"])["WindowExecutions"]
        # Only a window that opened during this probe run counts.
        return [r for r in runs if r["StartTime"] >= started and r["Status"] not in ("PENDING", "IN_PROGRESS")] or None

    # The proof window opens every 15 minutes and the task installs patches.
    runs = wait_for(done, 2400, every=30)
    if not runs:
        return False, "no finished execution in 40 minutes"
    run = runs[0]
    tasks = ssm.describe_maintenance_window_execution_tasks(WindowExecutionId=run["WindowExecutionId"])[
        "WindowExecutionTaskIdentities"
    ]
    seen = {"execution": run["Status"], "tasks": [{"task": t["TaskArn"], "status": t["Status"]} for t in tasks]}
    return run["Status"] == "SUCCESS" and bool(tasks), seen


# --- vpc-flow-logs ------------------------------------------------------------


def flow_log_key_is_scoped():
    key = bucket_key(cfg["flow_log_bucket"])
    policy = json.loads(client("kms").get_key_policy(KeyId=key, PolicyName="default")["Policy"])
    grant = next(s for s in policy["Statement"] if s.get("Principal", {}).get("Service") == "delivery.logs.amazonaws.com")
    seen = conditions(grant)
    return seen.get("aws:SourceAccount") == account and "aws:SourceArn" in seen, seen


def flow_log_delivers_encrypted():
    # Records arrive within one 10-minute aggregation interval plus delivery.
    found = wait_for(lambda: first_object(cfg["flow_log_bucket"], "AWSLogs/"), 1500, every=30)
    log = client("ec2").describe_flow_logs(FlowLogIds=[cfg["flow_log_id"]])["FlowLogs"][0]
    seen = {"status": log["FlowLogStatus"], "delivery": log["DeliverLogsStatus"], "objects_in_bucket": bool(found)}
    if not found:
        return False, seen
    seen["encrypted_with_bucket_key"] = encrypted_with_bucket_key(cfg["flow_log_bucket"], found[0]["Key"])
    return log["DeliverLogsStatus"] == "SUCCESS" and seen["encrypted_with_bucket_key"], seen


# --- org-cloudtrail (key and log group only) ----------------------------------


def log_group_round_trip():
    logs = client("logs")
    name = cfg["cloudtrail_log_group"]
    group = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]
    policy = json.loads(client("kms").get_key_policy(KeyId=group["kmsKeyId"], PolicyName="default")["Policy"])
    grant = next(s for s in policy["Statement"] if str(s.get("Principal", {}).get("Service", "")).startswith("logs."))
    stream = f"probe-{int(time.time())}"
    logs.create_log_stream(logGroupName=name, logStreamName=stream)
    logs.put_log_events(
        logGroupName=name,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "controls_probe round trip"}],
    )
    read = wait_for(
        lambda: logs.get_log_events(logGroupName=name, logStreamName=stream, startFromHead=True)["events"], 60, every=5
    )
    seen = {
        "customer_managed_key": bool(group.get("kmsKeyId")),
        "key_statement_conditions": conditions(grant),
        "event_read_back": bool(read),
    }
    return bool(group.get("kmsKeyId")) and bool(read), seen


# --- iam-access-control -------------------------------------------------------


def analyzers_are_active():
    analyzer = client("accessanalyzer")
    seen = {}
    for label in ("external_access_analyzer", "unused_access_analyzer"):
        found = analyzer.get_analyzer(analyzerName=cfg[label].rsplit("/", 1)[1])["analyzer"]
        seen[label] = {"type": found["type"], "status": found["status"]}
    types = {seen["external_access_analyzer"]["type"], seen["unused_access_analyzer"]["type"]}
    active = all(a["status"] == "ACTIVE" for a in seen.values())
    return active and types == {"ACCOUNT", "ACCOUNT_UNUSED_ACCESS"}, seen


def _as_boundary_fixture():
    credentials = client("sts").assume_role(RoleArn=cfg["boundary_fixture_role"], RoleSessionName="controls-probe")[
        "Credentials"
    ]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=cfg["region"],
    )


def _outcome(call):
    try:
        call()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "allowed"


def boundary_allows_s3_in_this_account():
    buckets = client("s3").list_buckets()["Buckets"]
    if not buckets:
        return False, "the account has no bucket to read"
    capped = _as_boundary_fixture()
    # Any existing bucket will do; only whether the call is allowed is kept.
    outcome = _outcome(lambda: capped.client("s3").list_objects_v2(Bucket=buckets[0]["Name"], MaxKeys=1))
    return outcome == "allowed", {"s3:ListBucket on a bucket this account owns": outcome}


def boundary_refuses_other_services():
    capped = _as_boundary_fixture()
    # The fixture's identity policy is ReadOnlyAccess, so these refusals come
    # from the boundary: neither service is in its allow list.
    seen = {
        "ec2:DescribeVpcs": _outcome(lambda: capped.client("ec2").describe_vpcs()),
        "iam:ListRoles": _outcome(lambda: capped.client("iam").list_roles(MaxItems=1)),
    }
    return all(v in ("UnauthorizedOperation", "AccessDenied") for v in seen.values()), seen


# --- run ----------------------------------------------------------------------


def empty_buckets():
    s3 = session.resource("s3")
    names = [cfg[k] for k in ("patch_logs_bucket", "flow_log_bucket", "flow_log_access_log_bucket") if k in cfg]
    for bucket in names:
        try:
            s3.Bucket(bucket).object_versions.delete()
            print(f"emptied {bucket}", file=sys.stderr)
        except ClientError as exc:
            print(f"{bucket}: {exc.response['Error']['Code']}", file=sys.stderr)


if "--empty-buckets" in sys.argv:
    empty_buckets()
    sys.exit(0)

if "instance_id" in cfg:
    check("ssm-patching-hardened", "The instance registers as a managed node through the VPC endpoints", node_is_managed)
    check("ssm-patching-hardened", "The FedRAMPCompliance patch group resolves to the module's baseline", patch_group_uses_module_baseline)
    check("ssm-patching-hardened", "AWS-RunPatchBaseline scans the node under the module's baseline", patch_scan_runs_under_module_baseline)
    check("ssm-patching-hardened", "Run Command output reaches the bucket, encrypted with its customer managed key", patch_output_reaches_encrypted_bucket)
    check("ssm-patching-hardened", "The maintenance-window role trust has source conditions", window_role_trust)
    check("ssm-patching-hardened", "The maintenance window ran its patch task under that role", window_runs_patch_task)
if "flow_log_id" in cfg:
    check("vpc-flow-logs", "The log-delivery grant on the key has source conditions", flow_log_key_is_scoped)
    check("vpc-flow-logs", "Flow log records are delivered to the bucket, encrypted with its customer managed key", flow_log_delivers_encrypted)
if "cloudtrail_log_group" in cfg:
    check("org-cloudtrail", "CloudWatch Logs writes and reads the trail log group under the trail key", log_group_round_trip)
if "unused_access_analyzer" in cfg:
    check("iam-access-control", "Both analyzers are active, one for external and one for unused access", analyzers_are_active)
    check("iam-access-control", "A role under the developer boundary can read S3 in its own account", boundary_allows_s3_in_this_account)
    check("iam-access-control", "The same role is refused services outside the boundary", boundary_refuses_other_services)

output = {
    "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "region": cfg["region"],
    "passed": sum(r["passed"] for r in results),
    "total": len(results),
    "results": results,
}
print(re.sub(account, "111122223333", json.dumps(output, indent=2, default=str)))
