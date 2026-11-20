"""
Finds principals that were denied many API calls and also read a secret
or parameter in the same window, and publishes them to SNS. Detective
only - it never disables a credential or changes a policy.

A stolen credential is usually tried against everything it might reach.
Most calls are denied; the one that matters is the GetSecretValue that
works. Each half is ordinary by itself (denied calls happen all day,
applications read secrets all day), so this joins them per principal:

1. Logs Insights query over the CloudTrail log group: denied calls
   (errorCode AccessDenied* or *UnauthorizedOperation) counted per
   userIdentity.arn.
2. Only when a principal reaches DENIED_CALL_THRESHOLD: successful
   secretsmanager GetSecretValue and ssm GetParameter, GetParameters and
   GetParametersByPath calls, per principal.

A principal in both results is a finding. No findings, no message. A
query that fails, or a read result too large to be complete, fails the
invocation: a detective control that swallows the error reports a false
"nothing found".

Records without userIdentity.arn (AWS service events) are not correlated.

Env vars:
  SNS_TOPIC_ARN             - where findings are sent
  CLOUDTRAIL_LOG_GROUP_NAME - log group receiving CloudTrail events
  QUERY_WINDOW_MINUTES      - how far back each run looks (default 30)
  DENIED_CALL_THRESHOLD     - denied calls that make a principal a
                              suspect (default 20)
  IGNORED_PRINCIPAL_ARNS    - JSON list of userIdentity.arn values to
                              skip; "*" matches any run of characters
"""

import fnmatch
import json
import logging
import os
import time

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

logs = boto3.client("logs")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
LOG_GROUP_NAME = os.environ.get("CLOUDTRAIL_LOG_GROUP_NAME")
WINDOW_MINUTES = int(os.environ.get("QUERY_WINDOW_MINUTES", "30"))
DENIED_CALL_THRESHOLD = int(os.environ.get("DENIED_CALL_THRESHOLD", "20"))
IGNORED_PRINCIPAL_ARNS = json.loads(os.environ.get("IGNORED_PRINCIPAL_ARNS", "[]"))
MAX_ROWS = 10_000  # the most rows a Logs Insights query returns
MAX_MESSAGE_BYTES = 250_000  # SNS rejects a message over 256 KB

# Same error codes as logging-monitoring's UnauthorizedApiCalls filter.
# Sorted so that a result cut at MAX_ROWS drops only the lowest counts.
DENIED_QUERY = (
    "filter errorCode like /^AccessDenied/ or errorCode like /UnauthorizedOperation$/"
    " | stats count(*) as denied, min(@timestamp) as first_denied, max(@timestamp) as last_denied"
    " by userIdentity.arn"
    " | sort denied desc"
)

# Same events as logging-monitoring's UnexpectedSecretReads filter, minus
# the ones that failed.
READS_QUERY = (
    "filter not ispresent(errorCode) and ("
    '(eventSource = "secretsmanager.amazonaws.com" and eventName = "GetSecretValue")'
    ' or (eventSource = "ssm.amazonaws.com"'
    ' and eventName in ["GetParameter", "GetParameters", "GetParametersByPath"]))'
    # One always-present target field: grouping on fields some events lack
    # could leave those reads out of the result.
    ' | fields coalesce(requestParameters.secretId, requestParameters.name, requestParameters.path, "-") as target'
    " | stats count(*) as reads, min(@timestamp) as first_read, max(@timestamp) as last_read"
    " by userIdentity.arn, eventName, target"
)


def _run_query(query, start, end):
    """Rows of a finished query as dicts. Errors propagate, and a query
    that ends any way but Complete raises: an unread log must not look
    like a quiet one. The Lambda timeout bounds the wait."""
    query_id = logs.start_query(logGroupName=LOG_GROUP_NAME, startTime=start, endTime=end, queryString=query)["queryId"]
    while True:
        response = logs.get_query_results(queryId=query_id)
        status = response["status"]
        if status == "Complete":
            return [{field["field"]: field["value"] for field in row} for row in response["results"]]
        if status not in ("Scheduled", "Running"):
            raise RuntimeError(f"Logs Insights query {query_id} ended with status {status}")
        time.sleep(1)


def _ignored(arn):
    return any(fnmatch.fnmatchcase(arn, pattern) for pattern in IGNORED_PRINCIPAL_ARNS)


def _notify(subject, message):
    body = message.encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        message = body[:MAX_MESSAGE_BYTES].decode("utf-8", "ignore") + "\n... report truncated to fit SNS. The rest is not shown."
    # A publish error propagates: a finding nobody received must fail the run.
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)


def lambda_handler(event, context):
    end = int(time.time())
    start = end - WINDOW_MINUTES * 60

    suspects = {
        row["userIdentity.arn"]: row
        for row in _run_query(DENIED_QUERY, start, end)
        if row.get("userIdentity.arn")
        and int(row["denied"]) >= DENIED_CALL_THRESHOLD
        and not _ignored(row["userIdentity.arn"])
    }

    findings = []
    if suspects:  # the second query is only paid for when there is someone to look up
        reads = _run_query(READS_QUERY, start, end)
        # shortcut: a full result may be missing a suspect's reads, so fail
        # rather than guess. Upgrade to one query per suspect if a log group
        # is busy enough to hit this with a short window.
        if len(reads) >= MAX_ROWS:
            raise RuntimeError(
                f"The secret-read query returned {len(reads)} rows, the Logs Insights maximum, so it may be "
                "incomplete. Shorten query_window_minutes."
            )
        for arn, denied in suspects.items():
            principal_reads = [row for row in reads if row.get("userIdentity.arn") == arn]
            if principal_reads:
                findings.append((arn, denied, principal_reads))

    if findings:
        lines = [
            f"{len(findings)} principal(s) had at least {DENIED_CALL_THRESHOLD} denied API calls and read a "
            f"secret or parameter in the last {WINDOW_MINUTES} minutes (times are UTC). Check whether the "
            "credential is stolen. Nothing was changed.",
        ]
        for arn, denied, principal_reads in findings:
            lines.append(f"\nPrincipal: {arn}")
            lines.append(
                f"  Denied calls: {denied['denied']} (first {denied.get('first_denied')}, last {denied.get('last_denied')})"
            )
            lines.append("  Successful reads:")
            for row in principal_reads:
                target = row.get("target") if row.get("target") not in (None, "", "-") else "(name not in the event)"
                lines.append(
                    f"  - {row.get('eventName')} {target} x{row.get('reads')} "
                    f"(first {row.get('first_read')}, last {row.get('last_read')})"
                )
        _notify(
            subject=f"Secret read after denied-call burst: {len(findings)} principal(s)",
            message="\n".join(lines),
        )
    else:
        logger.info("No findings: %d principal(s) over the denied-call threshold, none read a secret", len(suspects))

    return {
        "statusCode": 200,
        "body": json.dumps({"suspect_count": len(suspects), "finding_count": len(findings)}),
    }
