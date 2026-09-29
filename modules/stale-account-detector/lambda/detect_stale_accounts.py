"""
Scans an AWS Organization for accounts with no CloudTrail activity in
the last N days ("stale accounts") and emails a report via SNS - but
only when it actually finds something. Queries an organization-wide
CloudTrail Lake event data store with SQL, rather than parsing raw
CloudTrail S3/CloudWatch Logs event-by-event, since Lake is purpose-built
for exactly this kind of ad-hoc cross-account query.

How "stale" is determined:
  1. List every ACTIVE account in the Organization.
  2. Run one CloudTrail Lake query covering the last ACTIVITY_LOOKBACK_DAYS
     days, grouped by recipientAccountId, returning each account's most
     recent event of any kind and its most recent ConsoleLogin event
     specifically.
  3. Any ACTIVE account with NO row in those results had zero recorded
     CloudTrail activity (management events) in the lookback window -
     that's what gets reported as stale. An account that shows up with
     only non-interactive API activity (no ConsoleLogin) is not treated
     as stale, but is called out separately in the report for context -
     it may be a legitimate automation-only account, or it may be a
     human-owned account nobody has manually reviewed in a while.

This only sees what's actually in the event data store: if it was just
created, "no activity in N days" for a brand-new store means "no
activity since the store started ingesting," not necessarily "no
activity ever." See this tool's README.

Env vars:
  SNS_TOPIC_ARN            - where to send the stale-account report
  EVENT_DATA_STORE_ARN     - ARN of the organization CloudTrail Lake
                             event data store to query (the bare ID used
                             in the SQL FROM clause is parsed from this
                             at runtime)
  ACTIVITY_LOOKBACK_DAYS   - accounts with no activity in this many days
                             are reported as stale (default 90)
  EXCLUDED_ACCOUNT_IDS     - comma-separated account IDs to always skip
                             (break-glass accounts, intentionally-idle
                             sandboxes, etc.)
  EXEMPT_TAG_KEY           - optional Organizations account tag key;
                             accounts carrying this tag are skipped
  EXEMPT_TAG_VALUE         - optional value EXEMPT_TAG_KEY must match;
                             if unset, the tag's presence alone exempts
  QUERY_MAX_WAIT_SECONDS   - how long to poll for the Lake query to
                             finish before giving up (default 240)
  QUERY_POLL_INTERVAL_SECONDS - seconds between polls (default 5)
"""

import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

organizations = boto3.client("organizations")
cloudtrail = boto3.client("cloudtrail")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
EVENT_DATA_STORE_ARN = os.environ["EVENT_DATA_STORE_ARN"]
# The SQL FROM clause takes the bare event data store ID (the UUID),
# not the full ARN - e.g. "FROM fc19d5bd-9dd5-4cbf-9071-4a7546954a7a".
EVENT_DATA_STORE_ID = EVENT_DATA_STORE_ARN.rsplit("/", 1)[-1]
ACTIVITY_LOOKBACK_DAYS = int(os.environ.get("ACTIVITY_LOOKBACK_DAYS", "90"))
EXCLUDED_ACCOUNT_IDS = {
    a.strip() for a in os.environ.get("EXCLUDED_ACCOUNT_IDS", "").split(",") if a.strip()
}
EXEMPT_TAG_KEY = os.environ.get("EXEMPT_TAG_KEY")
# Terraform always sets this variable, to "" when unused, so treat empty
# as unset: otherwise only tags with an empty value would exempt.
EXEMPT_TAG_VALUE = os.environ.get("EXEMPT_TAG_VALUE") or None
QUERY_MAX_WAIT_SECONDS = int(os.environ.get("QUERY_MAX_WAIT_SECONDS", "240"))
QUERY_POLL_INTERVAL_SECONDS = int(os.environ.get("QUERY_POLL_INTERVAL_SECONDS", "5"))

TERMINAL_FAILURE_STATUSES = {"FAILED", "CANCELLED", "TIMED_OUT"}


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def _iter_active_accounts():
    paginator = organizations.get_paginator("list_accounts")
    for page in paginator.paginate():
        for account in page.get("Accounts", []):
            if account.get("Status") == "ACTIVE":
                yield account


def _is_tag_exempt(account_id):
    if not EXEMPT_TAG_KEY:
        return False
    try:
        tags = organizations.list_tags_for_resource(ResourceId=account_id).get("Tags", [])
    except ClientError:
        logger.exception("Failed to list tags for account %s", account_id)
        return False
    return any(
        tag.get("Key") == EXEMPT_TAG_KEY and (EXEMPT_TAG_VALUE is None or tag.get("Value") == EXEMPT_TAG_VALUE)
        for tag in tags
    )


def _run_activity_query():
    query = f"""
        SELECT
          recipientAccountId,
          MAX(eventTime) AS last_activity_time,
          MAX(CASE WHEN eventName = 'ConsoleLogin' THEN eventTime END) AS last_console_login_time
        FROM {EVENT_DATA_STORE_ID}
        WHERE eventTime > date_add('day', -{ACTIVITY_LOOKBACK_DAYS}, current_timestamp)
        GROUP BY recipientAccountId
    """
    start_resp = cloudtrail.start_query(QueryStatement=query)
    query_id = start_resp["QueryId"]
    logger.info("Started CloudTrail Lake query %s", query_id)

    waited = 0
    while waited < QUERY_MAX_WAIT_SECONDS:
        status_resp = cloudtrail.describe_query(EventDataStore=EVENT_DATA_STORE_ARN, QueryId=query_id)
        status = status_resp["QueryStatus"]
        if status == "FINISHED":
            break
        if status in TERMINAL_FAILURE_STATUSES:
            raise RuntimeError(f"CloudTrail Lake query {query_id} ended with status {status}")
        time.sleep(QUERY_POLL_INTERVAL_SECONDS)
        waited += QUERY_POLL_INTERVAL_SECONDS
    else:
        raise TimeoutError(f"CloudTrail Lake query {query_id} did not finish within {QUERY_MAX_WAIT_SECONDS}s")

    activity_by_account = {}
    next_token = None
    while True:
        kwargs = {"QueryId": query_id, "MaxQueryResults": 1000}
        if next_token:
            kwargs["NextToken"] = next_token
        results_resp = cloudtrail.get_query_results(**kwargs)
        for row in results_resp.get("QueryResultRows", []):
            parsed = {}
            for cell in row:
                parsed.update(cell)
            account_id = parsed.get("recipientaccountid") or parsed.get("recipientAccountId")
            if account_id:
                activity_by_account[account_id] = {
                    "last_activity_time": parsed.get("last_activity_time"),
                    "last_console_login_time": parsed.get("last_console_login_time"),
                }
        next_token = results_resp.get("NextToken")
        if not next_token:
            break

    return activity_by_account


def lambda_handler(event, context):
    logger.info("Starting stale-account scan (lookback: %d days)", ACTIVITY_LOOKBACK_DAYS)

    activity_by_account = _run_activity_query()

    stale_accounts = []
    no_login_accounts = []

    for account in _iter_active_accounts():
        account_id = account["Id"]
        if account_id in EXCLUDED_ACCOUNT_IDS:
            continue
        if _is_tag_exempt(account_id):
            continue

        activity = activity_by_account.get(account_id)
        if activity is None:
            stale_accounts.append(account)
            continue

        if not activity.get("last_console_login_time"):
            no_login_accounts.append({"account": account, "last_activity_time": activity.get("last_activity_time")})

    if stale_accounts:
        lines = [
            (
                f"No CloudTrail activity recorded in the last {ACTIVITY_LOOKBACK_DAYS} days "
                f"(event data store: {EVENT_DATA_STORE_ID}):"
            ),
            "",
        ]
        for a in stale_accounts:
            lines.append(f"- {a['Id']}  {a.get('Name', '(no name)')}  <{a.get('Email', '(no email)')}>")

        if no_login_accounts:
            lines.append("")
            lines.append(
                f"Additionally, these ACTIVE accounts had some activity in the last "
                f"{ACTIVITY_LOOKBACK_DAYS} days but no interactive console sign-in - "
                "possibly automation-only, or just not manually reviewed recently:"
            )
            for entry in no_login_accounts:
                a = entry["account"]
                lines.append(
                    f"- {a['Id']}  {a.get('Name', '(no name)')}  "
                    f"(last activity: {entry['last_activity_time']})"
                )

        lines.append("")
        lines.append(
            "This reflects only what's in the event data store's lookback window - "
            "if the store is newer than the lookback period, treat this as 'no "
            "activity since monitoring started,' not 'no activity ever.'"
        )

        _notify(
            subject=f"Stale AWS account report: {len(stale_accounts)} account(s) with no activity",
            message="\n".join(lines),
        )
    else:
        logger.info("No stale accounts found - no notification sent")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "stale_account_count": len(stale_accounts),
                "stale_account_ids": [a["Id"] for a in stale_accounts],
                "no_login_account_count": len(no_login_accounts),
            }
        ),
    }
