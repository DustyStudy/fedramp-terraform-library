from datetime import datetime, timedelta, timezone

import pytest

LAMBDA = "modules/stale-account-detector/lambda/detect_stale_accounts.py"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def days_ago(days):
    return NOW - timedelta(days=days)


def iso(days):
    return days_ago(days).isoformat()


@pytest.fixture
def fn(load_lambda):
    def _load(**env):
        return load_lambda(LAMBDA, SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:report", REPORT_POLL_SECONDS="0", **env)

    return _load


def user_row(**overrides):
    row = {
        "user": "alice",
        "arn": "arn:aws:iam::111111111111:user/alice",
        "user_creation_time": iso(400),
        "password_enabled": "false",
        "password_last_used": "N/A",
        "password_last_changed": "N/A",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }
    return {**row, **overrides}


# --- staleness rule ---------------------------------------------------------


@pytest.mark.parametrize(
    ("created", "last_used", "expected"),
    [
        (400, 10, False),  # used recently
        (400, 91, True),  # used, but outside the window
        (400, None, True),  # old and never used
        (5, None, False),  # new and never used
        (None, None, True),  # no creation time counts as old
        (None, 10, False),
    ],
)
def test_is_stale(fn, created, last_used, expected):
    module = fn()
    created_at = days_ago(created) if created is not None else None
    used_at = days_ago(last_used) if last_used is not None else None
    assert module.is_stale(created_at, used_at, NOW) is expected


def test_inactivity_days_comes_from_the_environment(fn):
    module = fn(INACTIVITY_DAYS="35")
    assert module.is_stale(days_ago(400), days_ago(40), NOW) is True
    assert module.is_stale(days_ago(400), days_ago(30), NOW) is False


def test_parse_time_handles_report_placeholders(fn):
    module = fn()
    assert module.parse_time("N/A") is None
    assert module.parse_time("no_information") is None
    assert module.parse_time("not_supported") is None
    assert module.parse_time(None) is None
    assert module.parse_time("2026-09-01T00:00:00+00:00") == datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert module.parse_time(datetime(2026, 9, 1)).tzinfo is timezone.utc  # noqa: DTZ001 - a naive value is the case under test


# --- IAM users --------------------------------------------------------------


def test_unused_password_is_medium(fn):
    module = fn()
    row = user_row(password_enabled="true", password_last_used=iso(120), password_last_changed=iso(300))
    findings = module.check_iam_user(row, "111111111111", NOW)
    assert [(f["severity"], f["check"]) for f in findings] == [("MEDIUM", "iam-user-password")]
    assert "120 days ago" in findings[0]["detail"]


def test_unused_active_key_is_high_and_names_the_key_slot(fn):
    module = fn()
    row = user_row(access_key_2_active="true", access_key_2_last_rotated=iso(200), access_key_2_last_used_date="N/A")
    findings = module.check_iam_user(row, "111111111111", NOW)
    assert [(f["severity"], f["check"]) for f in findings] == [("HIGH", "iam-access-key")]
    assert findings[0]["resource"].endswith("user/alice access key 2")
    assert "never used" in findings[0]["detail"]


def test_recently_used_credentials_are_not_reported(fn):
    module = fn()
    row = user_row(
        password_enabled="true",
        password_last_used=iso(3),
        password_last_changed=iso(300),
        access_key_1_active="true",
        access_key_1_last_rotated=iso(300),
        access_key_1_last_used_date=iso(1),
    )
    assert module.check_iam_user(row, "111111111111", NOW) == []


def test_new_never_used_key_is_not_reported(fn):
    module = fn()
    row = user_row(user_creation_time=iso(2), access_key_1_active="true", access_key_1_last_rotated=iso(2))
    assert module.check_iam_user(row, "111111111111", NOW) == []


def test_inactive_key_and_root_row_are_ignored(fn):
    module = fn()
    assert module.check_iam_user(user_row(access_key_1_active="false", access_key_1_last_rotated=iso(300)), "1", NOW) == []
    root = user_row(user="<root_account>", password_enabled="not_supported", access_key_1_active="true", access_key_1_last_rotated=iso(300))
    assert module.check_iam_user(root, "1", NOW) == []
