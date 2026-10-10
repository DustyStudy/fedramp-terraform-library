import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/identity-center-access-auditor/lambda/audit_identity_center_access.py"
INSTANCE = {"InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1"}


def _pages(client):
    """Serve get_paginator(op).paginate(**kw) from the client's op mock, as one page."""
    client.get_paginator.side_effect = lambda op: MagicMock(paginate=lambda **kw: [getattr(client, op)(**kw)])
    return client


def _permission_set(name, accounts=("111",), managed=(), inline=None, assignments=None, customer_managed=0):
    return {
        "name": name,
        "accounts": list(accounts),
        "managed": [{"Name": m, "Arn": f"arn:aws:iam::aws:policy/{m}"} for m in managed],
        "inline": json.dumps(inline) if inline is not None else "",
        "assignments": assignments or [{"PrincipalType": "GROUP", "PrincipalId": "g-1"}],
        "customer_managed": [{"Name": f"cm{i}"} for i in range(customer_managed)],
    }


@pytest.fixture
def make_fn(load_lambda):
    def _make(permission_sets, **env):
        module = load_lambda(LAMBDA, SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:audit", **env)
        by_arn = {f"ps-{p['name']}": p for p in permission_sets}
        sso = MagicMock()
        sso.list_instances.return_value = {"Instances": [INSTANCE]}
        sso.list_permission_sets.return_value = {"PermissionSets": list(by_arn)}
        sso.describe_permission_set.side_effect = lambda InstanceArn, PermissionSetArn: {
            "PermissionSet": {"Name": by_arn[PermissionSetArn]["name"]}
        }
        sso.list_accounts_for_provisioned_permission_set.side_effect = lambda InstanceArn, PermissionSetArn: {
            "AccountIds": by_arn[PermissionSetArn]["accounts"]
        }
        sso.list_managed_policies_in_permission_set.side_effect = lambda InstanceArn, PermissionSetArn: {
            "AttachedManagedPolicies": by_arn[PermissionSetArn]["managed"]
        }
        sso.get_inline_policy_for_permission_set.side_effect = lambda InstanceArn, PermissionSetArn: {
            "InlinePolicy": by_arn[PermissionSetArn]["inline"]
        }
        sso.list_customer_managed_policy_references_in_permission_set.side_effect = (
            lambda InstanceArn, PermissionSetArn: {
                "CustomerManagedPolicyReferences": by_arn[PermissionSetArn]["customer_managed"]
            }
        )
        sso.list_account_assignments.side_effect = lambda InstanceArn, AccountId, PermissionSetArn: {
            "AccountAssignments": by_arn[PermissionSetArn]["assignments"]
        }
        identitystore = MagicMock()
        identitystore.describe_user.return_value = {"UserName": "alice"}
        organizations = MagicMock()
        organizations.list_accounts.return_value = {"Accounts": [{"Id": "111", "Name": "prod"}]}
        module.sso_admin, module.identitystore, module.organizations = _pages(sso), identitystore, _pages(organizations)
        module.sns = MagicMock()
        return module

    return _make


def _body(response):
    return json.loads(response["body"])


def _message(fn):
    return fn.sns.publish.call_args.kwargs["Message"]


def test_administrator_access_is_flagged_with_account_names(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"])])

    body = _body(fn.lambda_handler({}, None))

    assert body["over_privileged_permission_set_count"] == 1
    assert "AdministratorAccess attached" in _message(fn)
    assert "prod" in _message(fn)


@pytest.mark.parametrize(
    ("statement", "reason"),
    [
        ({"Effect": "Allow", "Action": "*", "Resource": "*"}, "full wildcard action"),
        ({"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}, "service-wide wildcard action (iam:*)"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, "Allow with NotAction"),
    ],
)
def test_risky_inline_statements_are_flagged(make_fn, statement, reason):
    fn = make_fn([_permission_set("Wide", inline={"Statement": statement})])

    fn.lambda_handler({}, None)

    assert reason in _message(fn)


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Allow", "Action": "logs:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:*", "Resource": "arn:aws:iam::111:role/app"},
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
    ],
)
def test_scoped_or_non_sensitive_statements_pass(make_fn, statement):
    fn = make_fn([_permission_set("Scoped", inline={"Statement": [statement]})])

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 0


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ({"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"}, "iam:putrolepolicy"),
        (
            {"Effect": "Allow", "Action": "iam:DeleteRolePermissionsBoundary", "Resource": "arn:aws:iam::111:role/*"},
            "iam:deleterolepermissionsboundary",
        ),
        ({"Effect": "Allow", "Action": ["s3:GetObject", "iam:Attach*"], "Resource": "*"}, "iam:attachrolepolicy"),
        ({"Effect": "Allow", "Action": "IAM:PassRole", "Resource": "*"}, "iam:passrole"),
        ({"Effect": "Allow", "Action": "sso:CreateAccountAssignment", "Resource": "*"}, "sso:createaccountassignment"),
    ],
)
def test_escalation_actions_on_wildcard_resources_are_flagged(make_fn, statement, expected):
    fn = make_fn([_permission_set("Elevate", inline={"Statement": [statement]})])

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 1
    assert "privilege escalation action(s)" in _message(fn)
    assert expected in _message(fn)


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "arn:aws:iam::111:role/app"},
        {"Effect": "Allow", "Action": "iam:Get*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:PutRolePolicy", "Resource": "*"},
    ],
)
def test_named_or_read_only_iam_statements_pass(make_fn, statement):
    fn = make_fn([_permission_set("Scoped", inline={"Statement": [statement]})])

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 0


def test_escalation_action_list_can_be_overridden(make_fn):
    statement = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
    fn = make_fn(
        [_permission_set("Deploy", inline={"Statement": [statement]})],
        ESCALATION_ACTIONS="iam:PutRolePolicy",
    )

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 0


def test_direct_user_assignment_is_flagged(make_fn):
    fn = make_fn([_permission_set("ReadOnly", assignments=[{"PrincipalType": "USER", "PrincipalId": "u-1"}])])

    body = _body(fn.lambda_handler({}, None))

    assert body["direct_user_assignment_count"] == 1
    assert "alice -> ReadOnly on prod" in _message(fn)


def test_direct_user_check_can_be_disabled(make_fn):
    fn = make_fn(
        [_permission_set("ReadOnly", assignments=[{"PrincipalType": "USER", "PrincipalId": "u-1"}])],
        FLAG_DIRECT_USER_ASSIGNMENTS="false",
    )

    fn.lambda_handler({}, None)

    fn.sns.publish.assert_not_called()


def test_unused_permission_sets_alone_send_nothing(make_fn):
    fn = make_fn([_permission_set("Old", accounts=())])

    body = _body(fn.lambda_handler({}, None))

    assert body["unused_permission_set_count"] == 1
    fn.sns.publish.assert_not_called()


def test_unused_permission_sets_ride_along_with_real_findings(make_fn):
    fn = make_fn([_permission_set("Old", accounts=()), _permission_set("Admin", managed=["AdministratorAccess"])])

    fn.lambda_handler({}, None)

    assert "Unused permission sets (1)" in _message(fn)


def test_customer_managed_policies_are_counted_not_evaluated(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"], customer_managed=2)])

    fn.lambda_handler({}, None)

    assert "2 customer-managed policy reference(s)" in _message(fn)


def test_missing_organizations_access_falls_back_to_ids(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"])])
    fn.organizations.list_accounts.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListAccounts")

    fn.lambda_handler({}, None)

    assert "111" in _message(fn)


def test_sso_access_denied_fails_instead_of_reporting_clean(make_fn):
    fn = make_fn([])
    fn.sso_admin.list_permission_sets.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListPermissionSets")

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)


def test_unreadable_inline_policy_fails_instead_of_reporting_clean(make_fn):
    fn = make_fn([_permission_set("Dev")])
    fn.sso_admin.get_inline_policy_for_permission_set.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "GetInlinePolicyForPermissionSet"
    )

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)


def test_inline_policy_that_is_not_json_is_reported(make_fn):
    fn = make_fn([_permission_set("Dev")])
    fn.sso_admin.get_inline_policy_for_permission_set.side_effect = lambda InstanceArn, PermissionSetArn: {
        "InlinePolicy": "{not json"
    }

    response = fn.lambda_handler({}, None)

    assert _body(response)["over_privileged_permission_set_count"] == 1
    assert "could not be parsed" in _message(fn)


def test_oversized_report_is_cut_to_fit_sns(make_fn):
    fn = make_fn([])

    fn._notify("subject", "x" * 400_000)

    message = _message(fn)
    assert len(message.encode("utf-8")) <= 256 * 1024
    assert "truncated" in message


def test_failed_publish_fails_the_run(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"])])
    fn.sns.publish.side_effect = ClientError({"Error": {"Code": "KMSAccessDenied"}}, "Publish")

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)
