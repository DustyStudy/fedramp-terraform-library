import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

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
        "Federate": [trail_event(1, "u3", {"account_id": "222222222222", "role_name": "ReadOnly"})],
        "GetRoleCredentials": [
            trail_event(5, "u1", {"account_id": "111111111111", "role_name": "Admin"}),
            trail_event(3, "u1", {"account_id": "111111111111", "role_name": "Admin"}),
            trail_event(1, None, {"account_id": "111111111111", "role_name": "Admin"}),
        ],
    }
    module.cloudtrail = pages({"lookup_events": lambda **kw: [{"Events": events[kw["LookupAttributes"][0]["AttributeValue"]]}]})
    last_sign_in, last_access = module.sso_activity(days_ago(90), deadline=float("inf"))
    assert last_sign_in == {"u1": days_ago(2)}
    # Console access through the portal is a Federate event; CLI access is GetRoleCredentials.
    assert last_access == {("u1", "111111111111", "Admin"): days_ago(3), ("u3", "222222222222", "ReadOnly"): days_ago(1)}


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


# --- handler ----------------------------------------------------------------

OWN = "999999999999"
MEMBER = "111111111111"


def org_account(account_id, status="ACTIVE"):
    return {"Id": account_id, "Name": f"acct-{account_id}", "Status": status, "JoinedTimestamp": days_ago(900)}


@pytest.fixture
def handler(fn, monkeypatch):
    """The module with AWS replaced: accounts, per-account scans and SSO are injectable."""

    def _make(accounts, scans=None, sso=(), tags=None, **env):
        module = fn(**env)
        module.organizations = pages({"list_accounts": [{"Accounts": accounts}]})
        module.organizations.list_tags_for_resource.side_effect = lambda ResourceId: {"Tags": (tags or {}).get(ResourceId, [])}
        module.sts = MagicMock()
        module.sts.get_caller_identity.return_value = {"Account": OWN, "Arn": f"arn:aws-us-gov:sts::{OWN}:assumed-role/x/y"}
        module.sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t"}}
        module.sns = MagicMock()
        scanned = []

        def scan_account(account, iam_client, now):
            scanned.append(account["Id"])
            result = (scans or {}).get(account["Id"], [])
            if isinstance(result, Exception):
                raise result
            return result

        def scan_identity_center(own_account_id, now, deadline, account_ids):
            module.sso_account_ids = account_ids
            if isinstance(sso, Exception):
                raise sso
            return sso

        monkeypatch.setattr(module, "scan_account", scan_account)
        monkeypatch.setattr(module, "scan_identity_center", scan_identity_center)
        module.scanned = scanned
        return module

    return _make


def finding(severity="LOW", check="iam-role", account=MEMBER):
    return {"severity": severity, "check": check, "account": account, "resource": "r", "detail": "d"}


def test_handler_scans_every_active_account_and_counts_by_severity(handler):
    module = handler(
        [org_account(OWN), org_account(MEMBER), org_account("222222222222", status="SUSPENDED")],
        scans={OWN: [finding("HIGH", "iam-access-key", OWN)], MEMBER: [finding(), finding("MEDIUM", "aws-account")]},
        MEMBER_ROLE_NAME="StaleAccountRead",
    )
    result = module.lambda_handler({}, None)
    assert module.scanned == [OWN, MEMBER]
    assert result["accounts_scanned"] == 2
    assert result["counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert result["errors"] == [] and result["not_checked"] == []
    role_arn = module.sts.assume_role.call_args.kwargs["RoleArn"]
    assert role_arn == f"arn:aws-us-gov:iam::{MEMBER}:role/StaleAccountRead"
    message = module.sns.publish.call_args.kwargs["Message"]
    assert "HIGH (1)" in message and "[iam-access-key]" in message


def test_handler_skips_excluded_and_exempt_accounts(handler):
    module = handler(
        [org_account(OWN), org_account(MEMBER), org_account("333333333333")],
        tags={"333333333333": [{"Key": "stale-exempt", "Value": "true"}]},
        MEMBER_ROLE_NAME="StaleAccountRead",
        EXCLUDED_ACCOUNT_IDS=MEMBER,
        EXEMPT_TAG_KEY="stale-exempt",
    )
    module.lambda_handler({}, None)
    assert module.scanned == [OWN]


def test_unreadable_account_is_an_error_and_never_a_stale_account(handler):
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
    module = handler([org_account(OWN), org_account(MEMBER)], scans={MEMBER: denied}, MEMBER_ROLE_NAME="StaleAccountRead")
    result = module.lambda_handler({}, None)
    assert [e["account"] for e in result["errors"]] == [MEMBER]
    assert "AccessDenied" in result["errors"][0]["error"]
    assert result["findings"] == [] and result["accounts_scanned"] == 1
    assert MEMBER in module.sns.publish.call_args.kwargs["Message"]


def test_credential_report_timeout_is_an_error_not_a_crash(handler):
    module = handler([org_account(OWN)], scans={OWN: RuntimeError("credential report was not ready after 30 polls")})
    result = module.lambda_handler({}, None)
    assert result["errors"] == [{"account": OWN, "error": "credential report was not ready after 30 polls"}]


def test_without_a_member_role_only_this_account_is_read_and_the_report_says_so(handler):
    module = handler([org_account(OWN), org_account(MEMBER), org_account("222222222222")])
    result = module.lambda_handler({}, None)
    assert module.scanned == [OWN]
    assert result["not_checked"] == ["IAM in 2 member account(s): member_role_name is not set"]
    module.sts.assume_role.assert_not_called()
    assert "member_role_name is not set" in module.sns.publish.call_args.kwargs["Message"]


def test_sso_findings_are_included(handler):
    module = handler([org_account(OWN)], sso=[finding("MEDIUM", "sso-user", OWN)])
    assert module.lambda_handler({}, None)["counts"]["MEDIUM"] == 1


def test_failed_event_lookup_marks_sso_not_checked(handler):
    module = handler([org_account(OWN)], sso=ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow"}}, "LookupEvents"))
    result = module.lambda_handler({}, None)
    assert len(result["not_checked"]) == 1 and result["not_checked"][0].startswith("sso-user and sso-access:")
    assert "not checked" in module.sns.publish.call_args.kwargs["Message"].lower()


def test_no_identity_center_instance_marks_sso_not_checked(handler):
    module = handler([org_account(OWN)], sso=None)
    result = module.lambda_handler({}, None)
    assert result["not_checked"] == ["sso-user and sso-access: no IAM Identity Center instance in this region"]


def test_nothing_to_say_sends_no_notification(handler):
    module = handler([org_account(OWN)])
    result = module.lambda_handler({}, None)
    assert result == {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "accounts_scanned": 1, "errors": [], "not_checked": [], "findings": []}
    module.sns.publish.assert_not_called()


def test_scan_account_applies_user_exemptions_and_all_three_checks(fn):
    module = fn(EXEMPT_TAG_KEY="stale-exempt")
    client = MagicMock()
    stale_key = {"access_key_1_active": "true", "access_key_1_last_rotated": iso(300)}
    report = [user_row(user="alice", **stale_key), user_row(user="bot", arn="arn:aws:iam::1:user/bot", **stale_key)]
    module.credential_report = lambda c: report
    module.list_roles = lambda c: [role()]
    module.exempt_user_names = lambda c, rows: {"bot"}
    findings = module.scan_account(org_account(MEMBER), client, NOW)
    assert sorted(f["check"] for f in findings) == ["aws-account", "iam-access-key", "iam-role"]


def test_scan_identity_center_returns_none_without_an_instance(fn):
    module = fn()
    module.sso_admin = MagicMock()
    module.sso_admin.list_instances.return_value = {"Instances": []}
    assert module.scan_identity_center(OWN, NOW, float("inf"), {OWN}) is None


# --- review fixes -----------------------------------------------------------


def test_accounts_are_filtered_on_state_when_status_is_gone(handler):
    accounts = [
        {"Id": OWN, "Name": "mgmt", "State": "ACTIVE", "JoinedTimestamp": days_ago(900)},
        {"Id": MEMBER, "Name": "closed", "State": "SUSPENDED", "JoinedTimestamp": days_ago(900)},
        {"Id": "333333333333", "Name": "unknown", "JoinedTimestamp": days_ago(900)},
    ]
    module = handler(accounts, MEMBER_ROLE_NAME="StaleAccountRead")
    module.lambda_handler({}, None)
    # An account with neither field is read, never silently dropped.
    assert module.scanned == [OWN, "333333333333"]


def test_running_out_of_time_still_publishes_and_lists_unread_accounts(handler):
    module = handler([org_account(OWN), org_account(MEMBER)], MEMBER_ROLE_NAME="StaleAccountRead")
    context = MagicMock()
    context.get_remaining_time_in_millis.return_value = 0
    result = module.lambda_handler({}, context)
    assert module.scanned == []
    assert result["not_checked"] == ["IAM in 2 account(s): ran out of time"]
    assert "ran out of time" in module.sns.publish.call_args.kwargs["Message"]


def test_connection_failure_on_one_account_is_an_error_not_a_crash(handler):
    module = handler([org_account(OWN)], scans={OWN: EndpointConnectionError(endpoint_url="https://iam.amazonaws.com")})
    result = module.lambda_handler({}, None)
    assert [e["account"] for e in result["errors"]] == [OWN]


def test_handler_passes_the_target_accounts_to_the_sso_checks(handler):
    module = handler([org_account(OWN), org_account(MEMBER)], EXCLUDED_ACCOUNT_IDS=MEMBER)
    module.lambda_handler({}, None)
    assert module.sso_account_ids == {OWN}


def test_list_roles_does_not_fetch_service_linked_roles(fn):
    module = fn()
    linked = {"RoleName": "AWSServiceRoleForSupport", "Path": "/aws-service-role/support.amazonaws.com/"}
    client = pages({"list_roles": [{"Roles": [linked, {"RoleName": "app", "Path": "/"}]}]})
    client.get_role.side_effect = lambda RoleName: {"Role": {"RoleName": RoleName, "Path": "/", "RoleLastUsed": {}}}
    assert [r["RoleName"] for r in module.list_roles(client)] == ["AWSServiceRoleForSupport", "app"]
    client.get_role.assert_called_once_with(RoleName="app")


def test_oversized_report_is_cut_to_fit_sns(fn):
    module = fn()
    module.sns = MagicMock()
    findings = [finding("LOW", "iam-role", MEMBER) | {"resource": f"arn:aws:iam::{MEMBER}:role/{'r' * 60}{i}"} for i in range(5000)]
    module._publish(findings, [], [], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 5000})
    message = module.sns.publish.call_args.kwargs["Message"]
    assert len(message.encode("utf-8")) <= 250_000
    assert "more finding(s) not shown" in message
    assert "5000 finding(s)" in message


def sso_module(fn, monkeypatch, assignments, last_sign_in, last_access):
    module = fn()
    module.sso_admin = MagicMock()
    module.sso_admin.list_instances.return_value = {"Instances": [{"InstanceArn": "ins", "IdentityStoreId": "d-1"}]}
    monkeypatch.setattr(module, "identity_center_assignments", lambda instance: (USERS, assignments))
    monkeypatch.setattr(module, "sso_activity", lambda start, deadline: (last_sign_in, last_access))
    return module


def test_sso_access_is_reported_only_for_target_accounts(fn, monkeypatch):
    assignments = {("u-idle", MEMBER, "Admin"), ("u-idle", "222222222222", "Admin")}
    module = sso_module(fn, monkeypatch, assignments, {}, {})
    findings = module.scan_identity_center(OWN, NOW, float("inf"), {OWN, MEMBER})
    assert [f["account"] for f in findings if f["check"] == "sso-access"] == [MEMBER]
    # The user is still a stale sso-user: they hold assignments somewhere.
    assert [f["check"] for f in findings if f["check"] == "sso-user"] == ["sso-user"]


def test_recent_account_access_counts_as_sso_user_activity(fn, monkeypatch):
    key = ("u-idle", MEMBER, "Admin")
    module = sso_module(fn, monkeypatch, {key}, {}, {key: days_ago(1)})
    assert module.scan_identity_center(OWN, NOW, float("inf"), {MEMBER}) == []
