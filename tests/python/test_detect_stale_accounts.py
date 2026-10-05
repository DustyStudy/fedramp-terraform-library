import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

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


# --- roles ------------------------------------------------------------------


def role(name="app", path="/", created=400, last_used=None, federated=None, tags=None):
    principal = {"Federated": federated} if federated else {"Service": "ec2.amazonaws.com"}
    return {
        "RoleName": name,
        "Path": path,
        "Arn": f"arn:aws:iam::111111111111:role{path}{name}",
        "CreateDate": days_ago(created),
        "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]},
        "RoleLastUsed": {} if last_used is None else {"LastUsedDate": days_ago(last_used)},
        "Tags": tags or [],
    }


GITHUB = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"


def test_classify_role(fn):
    module = fn()
    assert module.classify_role(role(path="/aws-service-role/x.amazonaws.com/")) == "service-linked"
    assert module.classify_role(role(name="AWSReservedSSO_Admin_abc", path="/aws-reserved/sso.amazonaws.com/")) == "sso"
    assert module.classify_role(role(federated=GITHUB)) == "pipeline"
    assert module.classify_role(role(federated="arn:aws:iam::111111111111:saml-provider/okta")) == "other"
    assert module.classify_role(role()) == "other"


def test_unused_pipeline_role_is_medium(fn):
    module = fn()
    findings = module.check_role(role(name="deploy", federated=GITHUB, last_used=120), "111111111111", NOW)
    assert [(f["severity"], f["check"]) for f in findings] == [("MEDIUM", "pipeline-role")]


def test_unused_other_role_is_low(fn):
    module = fn()
    findings = module.check_role(role(), "111111111111", NOW)
    assert [(f["severity"], f["check"]) for f in findings] == [("LOW", "iam-role")]
    assert "never used" in findings[0]["detail"]


def test_roles_that_are_never_reported(fn):
    module = fn(EXEMPT_TAG_KEY="stale-exempt")
    assert module.check_role(role(last_used=5), "1", NOW) == []
    assert module.check_role(role(created=3), "1", NOW) == []
    assert module.check_role(role(path="/aws-service-role/x.amazonaws.com/"), "1", NOW) == []
    assert module.check_role(role(name="AWSReservedSSO_Admin_abc"), "1", NOW) == []
    assert module.check_role(role(tags=[{"Key": "stale-exempt", "Value": "true"}]), "1", NOW) == []


def test_exempt_tag_value_must_match_when_set(fn):
    module = fn(EXEMPT_TAG_KEY="stale-exempt", EXEMPT_TAG_VALUE="yes")
    assert module.check_role(role(tags=[{"Key": "stale-exempt", "Value": "no"}]), "1", NOW) != []
    assert module.check_role(role(tags=[{"Key": "stale-exempt", "Value": "yes"}]), "1", NOW) == []


# --- accounts ---------------------------------------------------------------

ACCOUNT = {"Id": "111111111111", "Name": "dev", "JoinedTimestamp": days_ago(900)}


def test_account_with_no_recent_use_is_stale(fn):
    module = fn()
    findings = module.check_account(ACCOUNT, [user_row()], [role(last_used=200)], NOW)
    assert [(f["severity"], f["check"], f["account"]) for f in findings] == [("MEDIUM", "aws-account", "111111111111")]
    assert "dev" in findings[0]["resource"]


def test_any_recent_user_or_role_use_makes_the_account_active(fn):
    module = fn()
    assert module.check_account(ACCOUNT, [user_row()], [role(last_used=3)], NOW) == []
    recent_key = user_row(access_key_1_active="true", access_key_1_last_used_date=iso(2))
    assert module.check_account(ACCOUNT, [recent_key], [], NOW) == []


def test_scanner_and_service_linked_roles_are_not_account_activity(fn):
    module = fn(IGNORED_ROLE_NAMES="ProwlerScan", MEMBER_ROLE_NAME="StaleAccountRead")
    roles = [
        role(name="ProwlerScan", last_used=1),
        role(name="StaleAccountRead", last_used=0),
        role(name="AWSServiceRoleForSupport", path="/aws-service-role/support.amazonaws.com/", last_used=1),
    ]
    assert len(module.check_account(ACCOUNT, [], roles, NOW)) == 1


def test_root_use_is_not_account_activity_and_new_account_is_not_stale(fn):
    module = fn()
    root = user_row(user="<root_account>", password_last_used=iso(1))
    assert len(module.check_account(ACCOUNT, [root], [], NOW)) == 1
    assert module.check_account({**ACCOUNT, "JoinedTimestamp": days_ago(5)}, [], [], NOW) == []


# --- Identity Center --------------------------------------------------------

USERS = {
    "u-active": {"name": "active", "created": days_ago(500), "enabled": True},
    "u-idle": {"name": "idle", "created": days_ago(500), "enabled": True},
    "u-new": {"name": "new", "created": days_ago(3), "enabled": True},
    "u-off": {"name": "off", "created": days_ago(500), "enabled": False},
    "u-unassigned": {"name": "unassigned", "created": days_ago(500), "enabled": True},
}


def test_sso_user_with_no_sign_in_is_medium(fn):
    module = fn()
    assigned = {"u-active", "u-idle", "u-new", "u-off"}
    findings = module.check_sso_users(USERS, assigned, {"u-active": days_ago(2)}, "999999999999", NOW)
    assert [(f["severity"], f["check"], f["resource"]) for f in findings] == [("MEDIUM", "sso-user", "user idle")]
    assert findings[0]["account"] == "999999999999"


def test_sso_user_unknown_to_the_identity_store_is_skipped(fn):
    module = fn()
    assert module.check_sso_users(USERS, {"u-deleted"}, {}, "999999999999", NOW) == []


def test_unused_sso_access_is_low_per_user_account_and_permission_set(fn):
    module = fn()
    assignments = {
        ("u-active", "111111111111", "Admin"),
        ("u-active", "222222222222", "Admin"),
        ("u-off", "111111111111", "Admin"),
    }
    last_access = {("u-active", "111111111111", "Admin"): days_ago(4)}
    findings = module.check_sso_access(assignments, last_access, USERS, NOW)
    assert [(f["severity"], f["check"], f["account"], f["resource"]) for f in findings] == [
        ("LOW", "sso-access", "222222222222", "user active with permission set Admin")
    ]


# --- collectors -------------------------------------------------------------


def pages(method_pages):
    """A client whose get_paginator(name).paginate(**kw) returns method_pages[name]."""
    client = MagicMock()

    def get_paginator(name):
        paginator = MagicMock()
        source = method_pages[name]
        paginator.paginate.side_effect = (lambda **kw: source(**kw)) if callable(source) else (lambda **kw: source)
        return paginator

    client.get_paginator.side_effect = get_paginator
    return client


def test_credential_report_polls_until_complete_and_parses_rows(fn):
    module = fn()
    client = MagicMock()
    client.generate_credential_report.side_effect = [{"State": "STARTED"}, {"State": "INPROGRESS"}, {"State": "COMPLETE"}]
    client.get_credential_report.return_value = {"Content": b"user,arn,password_enabled\nalice,arn:aws:iam::1:user/alice,true\n"}
    rows = module.credential_report(client)
    assert rows == [{"user": "alice", "arn": "arn:aws:iam::1:user/alice", "password_enabled": "true"}]
    assert client.generate_credential_report.call_count == 3


def test_credential_report_gives_up_with_an_error(fn):
    module = fn()
    client = MagicMock()
    client.generate_credential_report.return_value = {"State": "INPROGRESS"}
    with pytest.raises(RuntimeError, match="credential report"):
        module.credential_report(client)


def test_list_roles_fetches_each_role_for_last_used(fn):
    module = fn()
    client = pages({"list_roles": [{"Roles": [{"RoleName": "a"}, {"RoleName": "b"}]}]})
    client.get_role.side_effect = lambda RoleName: {"Role": {"RoleName": RoleName, "RoleLastUsed": {}}}
    assert [r["RoleName"] for r in module.list_roles(client)] == ["a", "b"]


def test_exempt_user_names_reads_tags_only_when_a_key_is_set(fn):
    client = MagicMock()
    client.list_user_tags.side_effect = lambda UserName: {"Tags": [{"Key": "stale-exempt", "Value": "x"}] if UserName == "bot" else []}
    rows = [user_row(user="bot"), user_row(user="alice"), user_row(user="<root_account>")]
    assert fn(EXEMPT_TAG_KEY="stale-exempt").exempt_user_names(client, rows) == {"bot"}
    untouched = MagicMock()
    assert fn(EXEMPT_TAG_KEY="").exempt_user_names(untouched, rows) == set()
    untouched.list_user_tags.assert_not_called()


def trail_event(days, user_id, details):
    body = {"userIdentity": {"type": "IdentityCenterUser", "onBehalfOf": {"userId": user_id}}, "serviceEventDetails": details}
    return {"EventTime": days_ago(days), "CloudTrailEvent": json.dumps(body)}


def test_sso_activity_keeps_the_latest_successful_event(fn):
    module = fn()
    events = {
        "UserAuthentication": [
            trail_event(10, "u1", {"UserAuthentication": "Success"}),
            trail_event(2, "u1", {"UserAuthentication": "Success"}),
            trail_event(1, "u1", {"UserAuthentication": "Failure"}),
            trail_event(1, "u2", {"UserAuthentication": "Failure"}),
        ],
        "GetRoleCredentials": [
            trail_event(5, "u1", {"account_id": "111111111111", "role_name": "Admin"}),
            trail_event(3, "u1", {"account_id": "111111111111", "role_name": "Admin"}),
            trail_event(1, None, {"account_id": "111111111111", "role_name": "Admin"}),
        ],
    }
    module.cloudtrail = pages({"lookup_events": lambda **kw: [{"Events": events[kw["LookupAttributes"][0]["AttributeValue"]]}]})
    last_sign_in, last_access = module.sso_activity(days_ago(90), deadline=float("inf"))
    assert last_sign_in == {"u1": days_ago(2)}
    assert last_access == {("u1", "111111111111", "Admin"): days_ago(3)}


def test_sso_activity_stops_at_the_deadline(fn):
    module = fn()
    module.cloudtrail = pages({"lookup_events": [{"Events": []}]})
    with pytest.raises(module.LookupTimeout):
        module.sso_activity(days_ago(90), deadline=0.0)


def test_identity_center_assignments_expand_groups(fn):
    module = fn()
    module.identitystore = pages(
        {
            "list_users": [
                {
                    "Users": [
                        {"UserId": "u1", "UserName": "alice", "CreatedAt": days_ago(100), "UserStatus": "ENABLED"},
                        {"UserId": "u2", "UserName": "bob", "UserStatus": "DISABLED"},
                    ]
                }
            ],
            "list_group_memberships": [{"GroupMemberships": [{"MemberId": {"UserId": "u1"}}, {"MemberId": {"UserId": "u2"}}]}],
        }
    )
    module.sso_admin = pages(
        {
            "list_permission_sets": [{"PermissionSets": ["ps-arn"]}],
            "list_accounts_for_provisioned_permission_set": [{"AccountIds": ["111111111111"]}],
            "list_account_assignments": [
                {
                    "AccountAssignments": [
                        {"PrincipalType": "GROUP", "PrincipalId": "g1"},
                        {"PrincipalType": "USER", "PrincipalId": "u1"},
                    ]
                }
            ],
        }
    )
    module.sso_admin.describe_permission_set.return_value = {"PermissionSet": {"Name": "Admin"}}
    users, assignments = module.identity_center_assignments({"InstanceArn": "ins", "IdentityStoreId": "d-1"})
    assert users == {
        "u1": {"name": "alice", "created": days_ago(100), "enabled": True},
        "u2": {"name": "bob", "created": None, "enabled": False},
    }
    assert assignments == {("u1", "111111111111", "Admin"), ("u2", "111111111111", "Admin")}
