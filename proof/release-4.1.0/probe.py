"""Probe the release 4.1.0 proof stacks (burst/ and backup/).

Usage, from this directory, after `terraform output -json probe >
probe-inputs.json` in the stack directory (see README.md):

    python probe.py burst          # denied calls + one secret read, as the actor role
    python probe.py burst-check    # 5-15 minutes later: run the detector, look for the finding
    python probe.py backup-start   # on-demand backup of the fixture table into the vault
    python probe.py backup-status  # jobs and recovery points in the vault
    python probe.py backup-deny    # the non-exempt role must be denied all three calls

The profile and region come from the inputs file. The probe never deletes
anything as the administrator; the only delete attempts are made as the
ftl410-backup-deleter role and are expected to be denied.
"""

import base64
import datetime
import json
import pathlib
import subprocess
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

HERE = pathlib.Path(__file__).resolve().parent
SESSION_NAME = "ftl410-probe"
FINDING_SUBJECT = "Secret read after denied-call burst"  # the detector's SNS subject


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load(stack):
    path = HERE / stack / "probe-inputs.json"
    if path.exists():
        cfg = json.loads(path.read_text(encoding="utf-8-sig"))
    else:  # no inputs file: read the stack's output directly
        out = subprocess.run(["terraform", f"-chdir={HERE / stack}", "output", "-json", "probe"],
                             capture_output=True, text=True, check=True).stdout
        cfg = json.loads(out)
    return cfg, boto3.Session(profile_name=cfg["profile"], region_name=cfg["region"])


def assume(session, role_arn):
    creds = session.client("sts").assume_role(RoleArn=role_arn, RoleSessionName=SESSION_NAME)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=session.region_name,
    )


def error_of(fn):
    """(error code, message) of a call, or (None, None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    return None, None


def burst():
    cfg, session = load("burst")
    actor = assume(session, cfg["actor_role_arn"])
    # Eight management-event calls the actor has no permission for. The two
    # EC2 calls fail with Client.UnauthorizedOperation, the rest with
    # AccessDenied*, so both halves of the detector's errorCode filter are hit.
    calls = [
        ("iam:ListUsers", lambda: actor.client("iam").list_users()),
        ("iam:ListRoles", lambda: actor.client("iam").list_roles()),
        ("s3:ListBuckets", lambda: actor.client("s3").list_buckets()),
        ("ec2:DescribeInstances", lambda: actor.client("ec2").describe_instances()),
        ("ec2:DescribeVpcs", lambda: actor.client("ec2").describe_vpcs()),
        ("kms:ListKeys", lambda: actor.client("kms").list_keys()),
        ("lambda:ListFunctions", lambda: actor.client("lambda").list_functions()),
        ("dynamodb:ListTables", lambda: actor.client("dynamodb").list_tables()),
    ]
    denied = 0
    for name, call in calls:
        code, _ = error_of(call)
        denied += bool(code)
        print(f"{now()}  {name:24} {code or 'ALLOWED (unexpected)'}")
    code, message = error_of(lambda: actor.client("secretsmanager").get_secret_value(SecretId=cfg["secret_id"]))
    print(f"{now()}  secretsmanager:GetSecretValue {code or 'OK'} {message or ''}")
    ok = denied == len(calls) and code is None
    print(f"\n{'PASS' if ok else 'FAIL'}: {denied}/{len(calls)} calls denied, secret read {'succeeded' if code is None else 'failed'}.")
    print("CloudTrail delivers to CloudWatch Logs 5-15 minutes after the calls. Wait, then run: python probe.py burst-check")
    return ok


def burst_check():
    cfg, session = load("burst")
    # No retry and a read timeout past the function's 300 s: a retried invoke
    # would run the queries twice.
    lam = session.client("lambda", config=Config(read_timeout=330, retries={"max_attempts": 0}))
    response = lam.invoke(FunctionName=cfg["detector_lambda"], InvocationType="RequestResponse", LogType="Tail")
    payload = response["Payload"].read().decode("utf-8")
    print(f"{now()}  invoke status {response['StatusCode']}, FunctionError: {response.get('FunctionError', 'none')}")
    print(f"payload: {payload}")
    print("--- log tail ---")
    print(base64.b64decode(response.get("LogResult", "")).decode("utf-8", "replace"))
    if response.get("FunctionError"):
        # AccessDenied on GetQueryResults or a rejected query string lands here.
        print("FAIL: the detector raised. See the payload and log tail above.")
        return False
    counts = json.loads(json.loads(payload)["body"])

    # The scheduled runs publish to the same topic, and so do the module's
    # failure alarms, so match on subject and on the actor's session ARN.
    # VisibilityTimeout=0 leaves the messages in the queue as evidence.
    actor = f"assumed-role/{cfg['actor_role_arn'].rsplit('/', 1)[1]}/{SESSION_NAME}"
    sqs = session.client("sqs")
    seen, published = set(), None
    for _ in range(4):
        batch = sqs.receive_message(
            QueueUrl=cfg["capture_queue_url"], MaxNumberOfMessages=10, WaitTimeSeconds=10, VisibilityTimeout=0
        )
        for message in batch.get("Messages", []):
            if message["MessageId"] in seen:
                continue
            seen.add(message["MessageId"])
            body = json.loads(message["Body"])
            print(f"queue message: {body.get('Timestamp')}  {body.get('Subject')}")
            if body.get("Subject", "").startswith(FINDING_SUBJECT) and actor in body.get("Message", ""):
                published = body
        if published:
            break

    if published:
        print(f"\n--- finding ---\n{published['Message']}\n")
        print(f"PASS: finding published for {actor} (this run: {counts}).")
        return True
    if counts["suspect_count"]:
        print(f"\nNO FINDING: this run saw {counts['suspect_count']} suspect(s) over the denied-call threshold but no "
              "secret read for them. The read may not be delivered yet; rerun in a few minutes.")
    else:
        print("\nNO FINDING: no principal over the denied-call threshold. Either the events are not in the log group "
              "yet (wait 5-15 minutes after `burst`) or they are older than the 60 minute window (rerun `burst`).")
    return False


def backup_start():
    cfg, session = load("backup")
    job = session.client("backup").start_backup_job(
        BackupVaultName=cfg["vault_name"],
        ResourceArn=cfg["table_arn"],
        IamRoleArn=cfg["backup_role_arn"],
        Lifecycle={"DeleteAfterDays": 1},  # the vault lock's minimum retention
    )
    print(f"{now()}  started backup job {job['BackupJobId']}")
    print("Run `python probe.py backup-status` until the recovery point is COMPLETED, then `backup-deny`.")
    return True


def backup_status():
    cfg, session = load("backup")
    backup = session.client("backup")
    for job in backup.list_backup_jobs(ByBackupVaultName=cfg["vault_name"])["BackupJobs"]:
        print(f"job {job['BackupJobId']}  {job['State']}  created {job['CreationDate']}  {job.get('StatusMessage', '')}")
    points = backup.list_recovery_points_by_backup_vault(BackupVaultName=cfg["vault_name"])["RecoveryPoints"]
    for point in points:
        delete_at = point.get("CalculatedLifecycle", {}).get("DeleteAt", "not calculated yet")
        print(f"recovery point {point['RecoveryPointArn']}\n  status {point['Status']}  created {point['CreationDate']}  delete at {delete_at}")
    if not points:
        print("No recovery points in the vault.")
    return True


def backup_deny():
    cfg, session = load("backup")
    vault = cfg["vault_name"]
    points = session.client("backup").list_recovery_points_by_backup_vault(BackupVaultName=vault)["RecoveryPoints"]
    if not points:
        print("FAIL: no recovery point in the vault. Run backup-start and wait for it to complete.")
        return False
    point = points[0]["RecoveryPointArn"]
    deleter = assume(session, cfg["deleter_role_arn"]).client("backup")
    attempts = [
        ("DeleteRecoveryPoint", lambda: deleter.delete_recovery_point(BackupVaultName=vault, RecoveryPointArn=point)),
        # Lengthens, never shortens: harmless if the deny were missing.
        ("UpdateRecoveryPointLifecycle", lambda: deleter.update_recovery_point_lifecycle(
            BackupVaultName=vault, RecoveryPointArn=point, Lifecycle={"DeleteAfterDays": 2})),
        ("DeleteBackupVault", lambda: deleter.delete_backup_vault(BackupVaultName=vault)),
    ]
    print(f"recovery point: {point}")
    ok = True
    for name, call in attempts:
        code, message = error_of(call)
        # Only an authorization error proves the vault policy: the lock or a
        # non-empty vault refuse with other codes, after authorization.
        passed = bool(code) and code.startswith("AccessDenied")
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'}  {name}: {code or 'SUCCEEDED'}  {message or ''}")
    print("The role's IAM policy allows all three calls, so each message should name an explicit deny in a resource-based policy.")
    return ok


COMMANDS = {
    "burst": burst,
    "burst-check": burst_check,
    "backup-start": backup_start,
    "backup-status": backup_status,
    "backup-deny": backup_deny,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        sys.exit(f"usage: python probe.py {{{'|'.join(COMMANDS)}}}")
    sys.exit(0 if COMMANDS[sys.argv[1]]() else 1)
