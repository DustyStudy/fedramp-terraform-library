import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/identity-center-access-auditor/lambda/audit_identity_center_access.py"
INSTANCE = {"InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1"}
# Default versions of AWS-managed policies, cut down to the statement that matters.
MANAGED_DOCUMENTS = {
    "IAMFullAccess": {"Statement": [{"Effect": "Allow", "Action": ["iam:*", "organizations:Describe*"], "Resource": "*"}]},
    "PowerUserAccess": {"Statement": [{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}]},
    "AWSOrganizationsFullAccess": {"Statement": {"Effect": "Allow", "Action": "organizations:*", "Resource": "*"}},
    "ReadOnlyAccess": {"Statement": [{"Effect": "Allow", "Action": ["iam:Get*", "iam:List*", "s3:Get*"], "Resource": "*"}]},
}


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
        module.iam = MagicMock()
        module.iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v7"}}
        module.iam.get_policy_version.side_effect = lambda PolicyArn, VersionId: {
            "PolicyVersion": {"Document": MANAGED_DOCUMENTS[PolicyArn.rsplit("/", 1)[1]]}
        }
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
        # NotResource reaches everything but the named resource, so it counts as "*".
        ({"Effect": "Allow", "Action": "iam:*", "NotResource": "arn:aws:iam::111:role/x"}, "service-wide wildcard action (iam:*)"),
        ({"Effect": "Allow", "NotAction": "s3:*", "NotResource": "arn:aws:s3:::logs"}, "Allow with NotAction"),
        ({"Effect": "Allow", "Action": "iam:PassRole", "NotResource": "arn:aws:iam::111:role/x"}, "iam:passrole"),
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
        {"Effect": "Deny", "Action": "iam:*", "NotResource": "arn:aws:iam::111:role/x"},
        {"Effect": "Allow", "Action": "logs:*", "NotResource": "arn:aws:logs:us-east-1:111:log-group:audit"},
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


@pytest.mark.parametrize(
    ("policy", "reason"),
    [
        ("IAMFullAccess", "AWS-managed policy IAMFullAccess: service-wide wildcard action (iam:*)"),
        ("PowerUserAccess", "AWS-managed policy PowerUserAccess: Allow with NotAction"),
        ("AWSOrganizationsFullAccess", "AWS-managed policy AWSOrganizationsFullAccess: service-wide wildcard action"),
    ],
)
def test_risky_aws_managed_policies_other_than_administrator_access_are_flagged(make_fn, policy, reason):
    fn = make_fn([_permission_set("Wide", managed=[policy])])

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 1
    assert reason in _message(fn)
    fn.iam.get_policy_version.assert_called_once_with(PolicyArn=f"arn:aws:iam::aws:policy/{policy}", VersionId="v7")


def test_read_only_aws_managed_policy_passes(make_fn):
    fn = make_fn([_permission_set("Viewer", managed=["ReadOnlyAccess"])])

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 0


def test_aws_managed_policy_is_fetched_once_however_many_permission_sets_use_it(make_fn):
    fn = make_fn([_permission_set("A", managed=["IAMFullAccess"]), _permission_set("B", managed=["IAMFullAccess"])])

    assert _body(fn.lambda_handler({}, None))["over_privileged_permission_set_count"] == 2
    assert fn.iam.get_policy.call_count == 1


def test_unreadable_aws_managed_policy_fails_instead_of_reporting_clean(make_fn):
    fn = make_fn([_permission_set("Wide", managed=["IAMFullAccess"])])
    fn.iam.get_policy.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetPolicy")

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)


def test_user_name_is_looked_up_once_across_accounts(make_fn):
    assignments = [{"PrincipalType": "USER", "PrincipalId": "u-1"}]
    fn = make_fn([_permission_set("ReadOnly", accounts=("111", "222", "333"), assignments=assignments)])

    assert _body(fn.lambda_handler({}, None))["direct_user_assignment_count"] == 3
    assert fn.identitystore.describe_user.call_count == 1


def test_running_out_of_time_publishes_an_incomplete_report(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"]), _permission_set("Dev")])
    context = MagicMock()
    context.get_remaining_time_in_millis.return_value = 0

    body = _body(fn.lambda_handler({}, context))

    assert body["permission_sets_not_finished"] == 2
    fn.sso_admin.list_account_assignments.assert_not_called()
    assert "INCOMPLETE: ran out of time with 2 permission set(s)" in _message(fn)
    assert fn.sns.publish.call_args.kwargs["Subject"].startswith("INCOMPLETE ")


def test_deadline_during_the_assignment_walk_keeps_the_findings_already_made(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"]), _permission_set("Dev")])
    # The clock: handler start, first permission set (in time), then past the deadline.
    fn.time = MagicMock()
    fn.time.monotonic.side_effect = [0.0, 0.0, *[10_000.0] * 5]

    body = _body(fn.lambda_handler({}, None))

    assert body["over_privileged_permission_set_count"] == 1
    assert body["permission_sets_not_finished"] == 2  # Admin half walked, Dev not reached
    assert "AdministratorAccess attached" in _message(fn)
    assert "INCOMPLETE" in _message(fn)


def test_a_complete_run_is_not_marked_incomplete(make_fn):
    fn = make_fn([_permission_set("Admin", managed=["AdministratorAccess"])])

    assert _body(fn.lambda_handler({}, None))["permission_sets_not_finished"] == 0
    assert "INCOMPLETE" not in _message(fn)
    assert "INCOMPLETE" not in fn.sns.publish.call_args.kwargs["Subject"]
