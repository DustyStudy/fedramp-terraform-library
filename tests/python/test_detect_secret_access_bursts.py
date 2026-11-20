import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/secret-access-burst-detector/lambda/detect_secret_access_bursts.py"
NOW = 1_800_000_000
THIEF = "arn:aws:sts::123456789012:assumed-role/app/i-0abc"
OTHER = "arn:aws:iam::123456789012:user/ci"


def _rows(rows):
    """Logs Insights result shape: each row is a list of field/value pairs."""
    return [[{"field": k, "value": str(v)} for k, v in row.items()] for row in rows]


def _denied(arn, count):
    return {
        "userIdentity.arn": arn,
        "denied": count,
        "first_denied": "2026-11-10 10:00:00.000",
        "last_denied": "2026-11-10 10:20:00.000",
    }


def _read(arn, event_name="GetSecretValue", **request):
    return {
        "userIdentity.arn": arn,
        "eventName": event_name,
        "reads": 1,
        "first_read": "2026-11-10 10:21:00.000",
        "last_read": "2026-11-10 10:21:00.000",
        **{f"requestParameters.{k}": v for k, v in request.items()},
    }


@pytest.fixture
def make_fn(load_lambda):
    def _make(denied=(), reads=(), **env):
        module = load_lambda(
            LAMBDA,
            SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:findings",
            CLOUDTRAIL_LOG_GROUP_NAME="aws-cloudtrail-logs",
            **env,
        )
        results = {module.DENIED_QUERY: _rows(denied), module.READS_QUERY: _rows(reads)}
        module.logs = MagicMock()
        # The query string doubles as the query ID, so results follow the query.
        module.logs.start_query.side_effect = lambda **kw: {"queryId": kw["queryString"]}
        module.logs.get_query_results.side_effect = lambda queryId: {"status": "Complete", "results": results[queryId]}
        module.sns = MagicMock()
        module.time = MagicMock()
        module.time.time.return_value = NOW
        return module

    return _make


def _body(response):
    return json.loads(response["body"])


def _message(fn):
    return fn.sns.publish.call_args.kwargs["Message"]


def test_denied_burst_then_secret_read_is_reported(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 240)], reads=[_read(THIEF, secretId="prod/db")])

    body = _body(fn.lambda_handler({}, None))

    assert body == {"suspect_count": 1, "finding_count": 1}
    fn.sns.publish.assert_called_once()
    message = _message(fn)
    assert THIEF in message
    assert "Denied calls: 240 (first 2026-11-10 10:00:00.000, last 2026-11-10 10:20:00.000)" in message
    assert "GetSecretValue prod/db x1 (first 2026-11-10 10:21:00.000" in message


def test_one_message_lists_every_finding_and_every_read(make_fn):
    fn = make_fn(
        denied=[_denied(THIEF, 30), _denied(OTHER, 25)],
        reads=[
            _read(THIEF, secretId="prod/db"),
            _read(THIEF, "GetParameter", name="/prod/api-key"),
            _read(OTHER, "GetParametersByPath", path="/prod"),
            _read(OTHER, "GetParameters"),
        ],
    )

    assert _body(fn.lambda_handler({}, None))["finding_count"] == 2
    fn.sns.publish.assert_called_once()
    message = _message(fn)
    assert "GetParameter /prod/api-key" in message
    assert "GetParametersByPath /prod" in message
    assert "GetParameters (name not in the event)" in message


@pytest.mark.parametrize(("count", "findings"), [(19, 0), (20, 1)])
def test_threshold_is_inclusive(make_fn, count, findings):
    fn = make_fn(denied=[_denied(THIEF, count)], reads=[_read(THIEF, secretId="prod/db")])

    assert _body(fn.lambda_handler({}, None))["finding_count"] == findings


def test_threshold_can_be_changed(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 5)], reads=[_read(THIEF, secretId="prod/db")], DENIED_CALL_THRESHOLD="5")

    assert _body(fn.lambda_handler({}, None))["finding_count"] == 1


def test_no_burst_sends_nothing_and_skips_the_read_query(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 3)], reads=[_read(THIEF, secretId="prod/db")])

    assert _body(fn.lambda_handler({}, None)) == {"suspect_count": 0, "finding_count": 0}
    fn.sns.publish.assert_not_called()
    assert fn.logs.start_query.call_count == 1


def test_burst_without_a_secret_read_sends_nothing(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 240)], reads=[_read(OTHER, secretId="prod/db")])

    assert _body(fn.lambda_handler({}, None)) == {"suspect_count": 1, "finding_count": 0}
    fn.sns.publish.assert_not_called()


@pytest.mark.parametrize("pattern", [THIEF, "arn:aws:sts::123456789012:assumed-role/app/*"])
def test_ignored_principals_are_skipped(make_fn, pattern):
    fn = make_fn(
        denied=[_denied(THIEF, 240)],
        reads=[_read(THIEF, secretId="prod/db")],
        IGNORED_PRINCIPAL_ARNS=json.dumps([pattern]),
    )

    assert _body(fn.lambda_handler({}, None)) == {"suspect_count": 0, "finding_count": 0}
    fn.sns.publish.assert_not_called()


def test_ignoring_one_principal_does_not_hide_another(make_fn):
    fn = make_fn(
        denied=[_denied(THIEF, 240), _denied(OTHER, 240)],
        reads=[_read(THIEF, secretId="prod/db"), _read(OTHER, secretId="prod/db")],
        IGNORED_PRINCIPAL_ARNS=json.dumps([OTHER]),
    )

    fn.lambda_handler({}, None)

    assert THIEF in _message(fn)
    assert OTHER not in _message(fn)


def test_denied_rows_without_a_principal_arn_are_skipped(make_fn):
    row = _denied(THIEF, 240)
    del row["userIdentity.arn"]
    fn = make_fn(denied=[row])

    assert _body(fn.lambda_handler({}, None))["suspect_count"] == 0


def test_queries_cover_the_window_on_the_cloudtrail_log_group(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 240)], QUERY_WINDOW_MINUTES="45")

    fn.lambda_handler({}, None)

    for call in fn.logs.start_query.call_args_list:
        assert call.kwargs["logGroupName"] == "aws-cloudtrail-logs"
        assert (call.kwargs["startTime"], call.kwargs["endTime"]) == (NOW - 45 * 60, NOW)
    assert [c.kwargs["queryString"] for c in fn.logs.start_query.call_args_list] == [fn.DENIED_QUERY, fn.READS_QUERY]


def test_queries_match_the_logging_monitoring_filters(make_fn):
    fn = make_fn()

    assert "/^AccessDenied/" in fn.DENIED_QUERY and "/UnauthorizedOperation$/" in fn.DENIED_QUERY
    assert "not ispresent(errorCode)" in fn.READS_QUERY
    assert '"secretsmanager.amazonaws.com" and eventName = "GetSecretValue"' in fn.READS_QUERY
    assert 'eventName in ["GetParameter", "GetParameters", "GetParametersByPath"]' in fn.READS_QUERY


def test_a_running_query_is_polled_until_complete(make_fn):
    fn = make_fn()
    fn.logs.get_query_results.side_effect = [
        {"status": "Scheduled", "results": []},
        {"status": "Running", "results": []},
        {"status": "Complete", "results": _rows([_denied(THIEF, 3)])},
    ]

    fn.lambda_handler({}, None)

    assert fn.logs.get_query_results.call_count == 3
    assert fn.time.sleep.call_count == 2


@pytest.mark.parametrize("status", ["Failed", "Cancelled", "Timeout", "Unknown"])
def test_a_query_that_does_not_complete_fails_the_run(make_fn, status):
    fn = make_fn()
    fn.logs.get_query_results.side_effect = lambda queryId: {"status": status, "results": []}

    with pytest.raises(RuntimeError, match=status):
        fn.lambda_handler({}, None)
    fn.sns.publish.assert_not_called()


def test_access_denied_on_the_log_group_fails_instead_of_reporting_clean(make_fn):
    fn = make_fn()
    fn.logs.start_query.side_effect = ClientError({"Error": {"Code": "AccessDeniedException"}}, "StartQuery")

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)


def test_a_failed_read_query_fails_the_run(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 240)])
    fn.logs.start_query.side_effect = [
        {"queryId": fn.DENIED_QUERY},
        ClientError({"Error": {"Code": "LimitExceededException"}}, "StartQuery"),
    ]

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)


def test_a_full_read_result_fails_instead_of_guessing(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 240)], reads=[_read(OTHER, secretId="prod/db")])
    fn.MAX_ROWS = 1

    with pytest.raises(RuntimeError, match="incomplete"):
        fn.lambda_handler({}, None)


def test_failed_publish_fails_the_run(make_fn):
    fn = make_fn(denied=[_denied(THIEF, 240)], reads=[_read(THIEF, secretId="prod/db")])
    fn.sns.publish.side_effect = ClientError({"Error": {"Code": "KMSAccessDenied"}}, "Publish")

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)


def test_oversized_report_is_cut_to_fit_sns(make_fn):
    fn = make_fn()

    fn._notify("subject", "x" * 400_000)

    assert len(_message(fn).encode("utf-8")) <= 256 * 1024
    assert "truncated" in _message(fn)
