"""Data-plane checks for the live proof stack. Writes the results as JSON.

Usage:
    terraform output -json dataplane > dataplane-inputs.json
    python dataplane_probe.py dataplane-inputs.json > ../../docs/proof/dataplane-run.json

probe.py reads configuration back from AWS. This script uses the
resources: it pushes an image to the ECR repository, sends requests
through the web ACL, and has a function inside the VPC connect to the
hardened database. Account IDs in the output are replaced with
111122223333.
"""

import datetime
import gzip
import hashlib
import io
import json
import pathlib
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request

import boto3
from botocore.exceptions import ClientError

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
session = boto3.Session(region_name=cfg["region"])
account = session.client("sts").get_caller_identity()["Account"]
results = []
MANIFEST_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


def check(module, name, fn):
    """fn returns (passed, observed). An exception is a failed check."""
    try:
        passed, observed = fn()
    except Exception as exc:  # noqa: BLE001 - the error text is the evidence
        passed, observed = False, f"{type(exc).__name__}: {exc}"
    results.append({"module": module, "check": name, "passed": bool(passed), "observed": observed})


# --- ECR: push an image without Docker ---------------------------------------

ecr = session.client("ecr")
RUN = int(time.time())
repo = cfg["ecr_repository"]


def upload(data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(repositoryName=repo, uploadId=upload_id, partFirstByte=0, partLastByte=len(data) - 1, layerPartBlob=data)
    try:
        ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    except ecr.exceptions.LayerAlreadyExistsException:
        pass  # left by an earlier run: deleting an image does not delete its layers at once
    return {"digest": digest, "size": len(data)}


def image(content):
    """Upload a one-file image and return its manifest."""
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as archive:
        info = tarfile.TarInfo("proof.txt")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    layer = gzip.compress(tar.getvalue(), mtime=0)
    config = json.dumps({
        "architecture": "amd64", "os": "linux", "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(tar.getvalue()).hexdigest()]},
    }).encode()
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", **upload(config)},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", **upload(layer)}],
    })


def ecr_push():
    pushed = ecr.put_image(repositoryName=repo, imageManifest=image(f"first {RUN}".encode()), imageManifestMediaType=MANIFEST_TYPE, imageTag="v1")
    return True, {"tag": "v1", "digest": pushed["image"]["imageId"]["imageDigest"]}


def ecr_tag_is_immutable():
    try:
        ecr.put_image(repositoryName=repo, imageManifest=image(f"second {RUN}".encode()), imageManifestMediaType=MANIFEST_TYPE, imageTag="v1")
    except ClientError as err:
        return err.response["Error"]["Code"] == "ImageTagAlreadyExistsException", err.response["Error"]["Code"]
    return False, "a second image was accepted under the same tag"


def ecr_scanned_on_push():
    deadline = time.time() + 120
    while True:
        detail = ecr.describe_images(repositoryName=repo, imageIds=[{"imageTag": "v1"}])["imageDetails"][0]
        status = detail.get("imageScanStatus", {})
        if status.get("status") not in (None, "IN_PROGRESS", "PENDING") or time.time() > deadline:
            # Any status shows that the push started a scan. A one-file image
            # has no operating system for the scanner to recognise.
            if not status:
                try:
                    status = ecr.describe_image_scan_findings(
                        repositoryName=repo, imageId={"imageTag": "v1"})["imageScanStatus"]
                except ClientError as err:
                    status = {"no_scan": err.response["Error"]["Code"], "message": err.response["Error"]["Message"][:200]}
                    return False, status
            return bool(status), status
        time.sleep(10)


check("ecr-hardened", "An image can be pushed", ecr_push)
check("ecr-hardened", "A second image under the same tag is rejected", ecr_tag_is_immutable)
check("ecr-hardened", "The push started a scan", ecr_scanned_on_push)
images = ecr.list_images(repositoryName=repo)["imageIds"]
if images:
    ecr.batch_delete_image(repositoryName=repo, imageIds=images)

# --- WAF: requests through the web ACL ---------------------------------------

MARKER = f"proof-bearer-{int(time.time())}"


def get(query="", headers=None):
    request = urllib.request.Request(cfg["waf_target_url"] + query, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


def waf_status(expected, **kwargs):
    def fn():
        status = get(**kwargs)
        return status == expected, {"http_status": status}
    return fn


def waf_log_redacts_authorization():
    logs = session.client("logs")
    start = int((time.time() - 900) * 1000)
    deadline = time.time() + 600
    while time.time() < deadline:
        events = logs.filter_log_events(logGroupName=cfg["waf_log_group"], startTime=start)["events"]
        records = [json.loads(e["message"]) for e in events]
        with_header = [
            h["value"] for r in records for h in r["httpRequest"]["headers"] if h["name"].lower() == "authorization"
        ]
        if with_header:
            leaked = any(MARKER in e["message"] for e in events)
            actions = sorted({r["action"] for r in records})
            return not leaked and set(with_header) == {"REDACTED"}, {
                "log_records": len(records), "actions_logged": actions,
                "authorization_values_logged": sorted(set(with_header)), "bearer_value_found_in_log": leaked,
            }
        time.sleep(20)
    return False, "no log record with an authorization header within 10 minutes"


time.sleep(60)  # a new web ACL association takes a moment to take effect
check("waf-hardened", "A plain request passes", waf_status(200, headers={"Authorization": f"Bearer {MARKER}"}))
check("waf-hardened", "A cross-site scripting query string is blocked (common rule set)",
      waf_status(403, query="?q=%3Cscript%3Ealert(1)%3C/script%3E"))
check("waf-hardened", "A Log4j lookup in a header is blocked (known bad inputs)",
      waf_status(403, headers={"X-Api-Version": "${jndi:ldap://proof.invalid/a}"}))
check("waf-hardened", "The log records requests with the authorization header redacted", waf_log_redacts_authorization)

# --- RDS: connections from inside the VPC ------------------------------------

response = session.client("lambda").invoke(FunctionName=cfg["db_client"], Payload=b"{}")
db = json.loads(response["Payload"].read())
if response.get("FunctionError"):
    db = {"error": json.dumps(db)[:800]}


def db_step(key, accepted):
    def fn():
        step = db[key]
        return step["accepted"] is accepted, step
    return fn


def role_audit():
    queries = db["role_audit_sql"]
    return bool(queries) and all(q["accepted"] for q in queries), [
        {"query": q["query"], "ran": q["accepted"], "rows": len(q["observed"]) if q["accepted"] else q["observed"]}
        for q in queries
    ]


check("rds-postgres-hardened", "A connection without TLS is refused", db_step("master_without_tls", False))
check("rds-postgres-hardened", "A connection with TLS, verified against the RDS certificate bundle, is accepted",
      db_step("master_with_verified_tls", True))
check("rds-postgres-hardened", "A database user in rds_iam signs in with an IAM token", db_step("iam_token_with_tls", True))
check("rds-postgres-hardened", "The same user is refused with a password", db_step("iam_user_with_a_password", False))
check("rds-postgres-hardened", "The same token is refused without TLS", db_step("iam_token_without_tls", False))
check("rds-access-auditor", "audit_postgres_roles.sql runs on RDS PostgreSQL", role_audit)

report = {
    "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "region": cfg["region"],
    "passed": sum(r["passed"] for r in results),
    "total": len(results),
    "results": results,
}
print(re.sub(account, "111122223333", json.dumps(report, indent=2, default=str)))
sys.exit(0 if report["passed"] == report["total"] else 1)
