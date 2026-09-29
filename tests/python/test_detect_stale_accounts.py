import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/stale-account-detector/lambda/detect_stale_accounts.py"
STORE_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/store-id"


def _account(account_id, status="ACTIVE"):
    return {"Id": account_id, "Name": f"acct-{account_id}", "Email": f"{account_id}@example.com", "Status": status}


def _row(account_id, last_activity="2026-09-01 00:00:00", last_login=None):
    return [
        {"recipientAccountId": account_id},
        {"last_activity_time": last_activity},
        {"last_console_login_time": last_login},
    ]


@pytest.fixture
def make_fn(load_lambda):
    def _make(accounts, rows, statuses=("FINISHED",), tags=None, **env):
        module = load_lambda(
            LAMBDA,
            EVENT_DATA_STORE_ARN=STORE_ARN,
            SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:report",
            QUERY_POLL_INTERVAL_SECONDS="0",
            **env,
        )
        organizations = MagicMock()
        organizations.get_paginator.return_value.paginate.return_value = [{"Accounts": accounts}]
        organizations.list_tags_for_resource.side_effect = lambda ResourceId: {"Tags": (tags or {}).get(ResourceId, [])}
        cloudtrail = MagicMock()
        cloudtrail.start_query.return_value = {"QueryId": "q-1"}
        cloudtrail.describe_query.side_effect = [{"QueryStatus": s} for s in statuses]
        cloudtrail.get_query_results.return_value = {"QueryResultRows": rows}
        module.organizations, module.cloudtrail, module.sns = organizations, cloudtrail, MagicMock()
        return module

    return _make


def _body(response):
    return json.loads(response["body"])


def test_account_with_no_activity_is_stale(make_fn):
    fn = make_fn([_account("111"), _account("222")], [_row("111", last_login="2026-09-01")])

    body = _body(fn.lambda_handler({}, None))

    assert body["stale_account_ids"] == ["222"]
    assert "222" in fn.sns.publish.call_args.kwargs["Message"]


def test_query_uses_the_bare_store_id_and_lookback(make_fn):
    fn = make_fn([], [], ACTIVITY_LOOKBACK_DAYS="30")

    fn.lambda_handler({}, None)

    query = fn.cloudtrail.start_query.call_args.kwargs["QueryStatement"]
    assert "FROM store-id" in query
    assert "-30" in query


def test_no_findings_sends_nothing(make_fn):
    fn = make_fn([_account("111")], [_row("111", last_login="2026-09-01")])

    fn.lambda_handler({}, None)

    fn.sns.publish.assert_not_called()


def test_suspended_accounts_are_ignored(make_fn):
    fn = make_fn([_account("111", status="SUSPENDED")], [])

    assert _body(fn.lambda_handler({}, None))["stale_account_count"] == 0


def test_excluded_and_tag_exempt_accounts_are_skipped(make_fn):
    fn = make_fn(
        [_account("111"), _account("222"), _account("333")],
        [],
        tags={"222": [{"Key": "idle-ok", "Value": "yes"}]},
        EXCLUDED_ACCOUNT_IDS="111",
        EXEMPT_TAG_KEY="idle-ok",
    )

    assert _body(fn.lambda_handler({}, None))["stale_account_ids"] == ["333"]


def test_empty_exempt_value_exempts_on_key_alone(make_fn):
    # Terraform sets EXEMPT_TAG_VALUE to "" when exempt_tag_value is unset.
    fn = make_fn(
        [_account("111")],
        [],
        tags={"111": [{"Key": "idle-ok", "Value": "anything"}]},
        EXEMPT_TAG_KEY="idle-ok",
        EXEMPT_TAG_VALUE="",
    )

    assert _body(fn.lambda_handler({}, None))["stale_account_count"] == 0


def test_automation_only_account_is_reported_but_not_stale(make_fn):
    fn = make_fn([_account("111"), _account("222")], [_row("111")])

    body = _body(fn.lambda_handler({}, None))

    assert body["no_login_account_count"] == 1
    assert "no interactive console sign-in" in fn.sns.publish.call_args.kwargs["Message"]


def test_waits_for_the_query_to_finish(make_fn):
    fn = make_fn([_account("111")], [], statuses=("QUEUED", "RUNNING", "FINISHED"))

    fn.lambda_handler({}, None)

    assert fn.cloudtrail.describe_query.call_count == 3


def test_failed_query_raises_instead_of_reporting_everything_stale(make_fn):
    fn = make_fn([_account("111")], [], statuses=("FAILED",))

    with pytest.raises(RuntimeError):
        fn.lambda_handler({}, None)
    fn.sns.publish.assert_not_called()


def test_results_are_paginated(make_fn):
    fn = make_fn([_account("111"), _account("222")], [])
    fn.cloudtrail.get_query_results.side_effect = [
        {"QueryResultRows": [_row("111")], "NextToken": "t"},
        {"QueryResultRows": [_row("222")]},
    ]

    assert _body(fn.lambda_handler({}, None))["stale_account_count"] == 0


def test_organizations_error_propagates(make_fn):
    fn = make_fn([], [])
    fn.organizations.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "ListAccounts"
    )

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)
