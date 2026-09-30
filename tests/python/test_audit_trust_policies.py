import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/trust-policy-auditor/lambda/audit_trust_policies.py"
ACCOUNT = "111111111111"
ORG_PEER = "222222222222"
OUTSIDER = "999999999999"
GITHUB = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"


@pytest.fixture
def fn(load_lambda):
    return load_lambda(LAMBDA)


@pytest.fixture
def ctx(fn):
    return fn.Context([ACCOUNT, ORG_PEER])


def _role(*statements, path="/"):
    return {
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/r",
        "Path": path,
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": list(statements)},
    }


def _github(condition):
    return {
        "Effect": "Allow",
        "Principal": {"Federated": GITHUB},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": condition,
    }


AUD = {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}


def _severities(findings):
    return [f["severity"] for f in findings]


# --- OIDC trust --------------------------------------------------------------


def test_github_trust_pinned_to_a_branch_is_clean(fn, ctx):
    role = _role(_github({
        "StringEquals": {**AUD, "token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main"},
    }))

    assert fn.check_role_trust(role, ACCOUNT, ctx) == []


def test_github_trust_without_sub_is_critical(fn, ctx):
    findings = fn.check_role_trust(_role(_github({"StringEquals": AUD})), ACCOUNT, ctx)

    assert _severities(findings) == ["CRITICAL"]
    assert "no subject (sub) condition" in findings[0]["detail"]


def test_github_trust_without_aud_is_high(fn, ctx):
    role = _role(_github({"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main"}}))

    assert _severities(fn.check_role_trust(role, ACCOUNT, ctx)) == ["HIGH"]


@pytest.mark.parametrize(
    ("sub", "severity"),
    [
        ("*", "CRITICAL"),
        ("repo:*", "CRITICAL"),
        ("repo:*/app:*", "CRITICAL"),
        ("repo:acme/*", "HIGH"),
        ("repo:acme/app-*:ref:refs/heads/main", "HIGH"),
        ("repo:acme*/app:ref:refs/heads/main", "CRITICAL"),
        ("repo:acme/app:*", "MEDIUM"),
        ("repository_owner_id:123:*", "MEDIUM"),
        # The subject format with immutable IDs: a wildcard ID keeps the name.
        ("repo:acme@*/app@*:*", "MEDIUM"),
        ("repo:acme@*/app@*:ref:refs/heads/main", "LOW"),
        ("repo:acme@*/*:ref:refs/heads/main", "HIGH"),
    ],
)
def test_github_sub_wildcards_are_graded(fn, ctx, sub, severity):
    role = _role(_github({"StringEquals": AUD, "StringLike": {"token.actions.githubusercontent.com:sub": sub}}))

    assert _severities(fn.check_role_trust(role, ACCOUNT, ctx)) == [severity]


def test_a_star_under_string_equals_is_a_literal_not_a_wildcard(fn, ctx):
    role = _role(_github({"StringEquals": {**AUD, "token.actions.githubusercontent.com:sub": "repo:acme/*"}}))

    assert fn.check_role_trust(role, ACCOUNT, ctx) == []


def test_condition_keys_match_case_insensitively(fn, ctx):
    role = _role(_github({
        "StringEquals": {
            "Token.Actions.GithubUserContent.com:AUD": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:Sub": "repo:acme/app:ref:refs/heads/main",
        }
    }))

    assert fn.check_role_trust(role, ACCOUNT, ctx) == []


def test_other_oidc_provider_without_sub_is_high(fn, ctx):
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {"oidc.eks.us-east-1.amazonaws.com/id/ABC:aud": "sts.amazonaws.com"}},
    }

    assert _severities(fn.check_role_trust(_role(statement), ACCOUNT, ctx)) == ["HIGH"]


def test_saml_trust_is_out_of_scope(fn, ctx):
    statement = {"Effect": "Allow", "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/idp"}}

    assert fn.check_role_trust(_role(statement), ACCOUNT, ctx) == []


# --- cross-account trust -------------------------------------------------------


def test_trust_in_any_principal_is_critical(fn, ctx):
    statement = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}

    assert _severities(fn.check_role_trust(_role(statement), ACCOUNT, ctx)) == ["CRITICAL"]


def test_trust_in_any_principal_limited_to_the_org_is_clean(fn, ctx):
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
    }

    assert fn.check_role_trust(_role(statement), ACCOUNT, ctx) == []


def test_outside_account_without_external_id_is_high(fn, ctx):
    statement = {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OUTSIDER}:root"}, "Action": "sts:AssumeRole"}

    findings = fn.check_role_trust(_role(statement), ACCOUNT, ctx)

    assert _severities(findings) == ["HIGH"]
    assert OUTSIDER in findings[0]["detail"]


def test_outside_account_with_external_id_is_clean(fn, ctx):
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": OUTSIDER},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "vendor-123"}},
    }

    assert fn.check_role_trust(_role(statement), ACCOUNT, ctx) == []


def test_org_and_trusted_accounts_are_inside(fn):
    ctx = fn.Context([ACCOUNT, ORG_PEER], trusted=[OUTSIDER])
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": [f"arn:aws:iam::{ORG_PEER}:role/x", OUTSIDER]},
        "Action": "sts:AssumeRole",
    }

    assert fn.check_role_trust(_role(statement), ACCOUNT, ctx) == []


def test_unknown_org_turns_the_outside_check_off(fn):
    statement = {"Effect": "Allow", "Principal": {"AWS": OUTSIDER}, "Action": "sts:AssumeRole"}

    assert fn.check_role_trust(_role(statement), ACCOUNT, fn.Context(None)) == []


def test_service_linked_roles_are_skipped(fn, ctx):
    statement = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}

    assert fn.check_role_trust(_role(statement, path="/aws-service-role/x/"), ACCOUNT, ctx) == []


def test_deny_statements_are_ignored(fn, ctx):
    statement = {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}

    assert fn.check_role_trust(_role(statement), ACCOUNT, ctx) == []


# --- Lambda function policies ---------------------------------------------------

FUNCTION = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f"


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def test_public_invoke_is_critical(fn, ctx):
    policy = _policy({"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"})

    assert _severities(fn.check_function_policy(FUNCTION, policy, ACCOUNT, ctx)) == ["CRITICAL"]


def test_public_function_url_is_high(fn, ctx):
    policy = _policy({
        "Effect": "Allow",
        "Principal": "*",
        "Action": "lambda:InvokeFunctionUrl",
        "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}},
    })

    findings = fn.check_function_policy(FUNCTION, policy, ACCOUNT, ctx)

    assert _severities(findings) == ["HIGH"]
    assert "function URL" in findings[0]["detail"]


def test_service_principal_without_source_is_medium(fn, ctx):
    policy = _policy({"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "lambda:InvokeFunction"})

    assert _severities(fn.check_function_policy(FUNCTION, policy, ACCOUNT, ctx)) == ["MEDIUM"]


def test_service_principal_with_source_arn_is_clean(fn, ctx):
    # lambda:AddPermission writes the key as AWS:SourceArn.
    policy = _policy({
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "lambda:InvokeFunction",
        "Condition": {"ArnLike": {"AWS:SourceArn": f"arn:aws:events:us-east-1:{ACCOUNT}:rule/r"}},
    })

    assert fn.check_function_policy(FUNCTION, policy, ACCOUNT, ctx) == []


def test_outside_account_can_invoke_is_high(fn, ctx):
    policy = _policy({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OUTSIDER}:root"}, "Action": "lambda:InvokeFunction"})

    assert _severities(fn.check_function_policy(FUNCTION, policy, ACCOUNT, ctx)) == ["HIGH"]


# --- RAM ----------------------------------------------------------------------

SHARE = {"name": "s", "resourceShareArn": "arn:aws:ram:us-east-1:111111111111:resource-share/s", "status": "ACTIVE"}


def test_share_open_to_outside_principals_is_medium(fn, ctx):
    share = {**SHARE, "allowExternalPrincipals": True}

    assert _severities(fn.check_resource_share(share, [ORG_PEER], ACCOUNT, ctx)) == ["MEDIUM"]


def test_share_with_an_outside_account_is_high(fn, ctx):
    share = {**SHARE, "allowExternalPrincipals": True}

    assert _severities(fn.check_resource_share(share, [OUTSIDER], ACCOUNT, ctx)) == ["MEDIUM", "HIGH"]


def test_share_inside_the_org_is_clean(fn, ctx):
    share = {**SHARE, "allowExternalPrincipals": False}
    principals = ["arn:aws:organizations::111111111111:ou/o-abc/ou-xyz", ORG_PEER]

    assert fn.check_resource_share(share, principals, ACCOUNT, ctx) == []


# --- collection and handler ------------------------------------------------------


def _paginated(pages_by_operation):
    client = MagicMock()
    client.get_paginator.side_effect = lambda op: MagicMock(
        paginate=MagicMock(side_effect=lambda **kwargs: pages_by_operation[op])
    )
    return client


def _account_clients(roles=(), functions=(), policies=None, shares=(), associations=()):
    iam = _paginated({"list_roles": [{"Roles": list(roles)}]})
    lam = _paginated({"list_functions": [{"Functions": list(functions)}]})
    policies = policies or {}

    def get_policy(FunctionName):
        if FunctionName not in policies:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "GetPolicy")
        return {"Policy": policies[FunctionName]}

    lam.get_policy.side_effect = get_policy
    ram = _paginated({
        "get_resource_shares": [{"resourceShares": list(shares)}],
        "get_resource_share_associations": [{"resourceShareAssociations": list(associations)}],
    })
    by_service = {"iam": iam, "lambda": lam, "ram": ram}
    return lambda service, region: by_service[service]


def test_audit_account_runs_every_check(fn, ctx):
    client = _account_clients(
        roles=[_role(_github({"StringEquals": AUD}))],
        functions=[{"FunctionArn": FUNCTION}, {"FunctionArn": FUNCTION + "2"}],
        policies={FUNCTION: _policy({"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"})},
        shares=[{**SHARE, "allowExternalPrincipals": True}, {**SHARE, "status": "DELETED"}],
        associations=[{"associatedEntity": OUTSIDER, "status": "ASSOCIATED"}, {"associatedEntity": "888888888888", "status": "DISASSOCIATED"}],
    )

    findings = fn.audit_account(ACCOUNT, client, ["us-east-1"], ctx)

    assert sorted((f["check"], f["severity"]) for f in findings) == [
        ("lambda-policy", "CRITICAL"),
        ("oidc-trust", "CRITICAL"),
        ("ram-share", "HIGH"),
        ("ram-share", "MEDIUM"),
    ]


def test_get_policy_errors_other_than_not_found_fail_the_run(fn, ctx):
    client = _account_clients(functions=[{"FunctionArn": FUNCTION}])
    client("lambda", "us-east-1").get_policy.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetPolicy")

    with pytest.raises(ClientError):
        fn.audit_account(ACCOUNT, client, ["us-east-1"], ctx)


@pytest.fixture
def handler(load_lambda, monkeypatch):
    def _make(member_role_name="", org_accounts=(ACCOUNT, ORG_PEER), assume_fails=()):
        module = load_lambda(
            LAMBDA,
            SNS_TOPIC_ARN="arn:aws:sns:us-east-1:111111111111:audit",
            MEMBER_ROLE_NAME=member_role_name,
            REGIONS="us-east-1",
        )
        module.sts = MagicMock()
        module.sts.get_caller_identity.return_value = {"Account": ACCOUNT, "Arn": f"arn:aws-us-gov:sts::{ACCOUNT}:x"}

        def assume_role(RoleArn, RoleSessionName):
            if any(a in RoleArn for a in assume_fails):
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole")
            return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t"}}

        module.sts.assume_role.side_effect = assume_role
        module.organizations = _paginated({"list_accounts": [{"Accounts": [{"Id": a, "Status": "ACTIVE"} for a in org_accounts]}]})
        module.sns = MagicMock()
        module.audited = []

        def audit_account(account_id, client, regions, ctx):
            module.audited.append(account_id)
            return [module._finding("HIGH", "oidc-trust", account_id, "r", "d")]

        monkeypatch.setattr(module, "audit_account", audit_account)
        return module

    return _make


def test_handler_scans_only_its_own_account_by_default(handler):
    module = handler()

    result = module.lambda_handler({}, None)

    assert module.audited == [ACCOUNT]
    module.sts.assume_role.assert_not_called()
    assert result["counts"]["HIGH"] == 1


def test_handler_assumes_the_member_role_in_other_accounts(handler):
    module = handler(member_role_name="audit-read")

    module.lambda_handler({}, None)

    assert module.audited == [ACCOUNT, ORG_PEER]
    role_arn = module.sts.assume_role.call_args.kwargs["RoleArn"]
    assert role_arn == f"arn:aws-us-gov:iam::{ORG_PEER}:role/audit-read"


def test_unreachable_account_is_reported_not_hidden(handler):
    module = handler(member_role_name="audit-read", assume_fails=[ORG_PEER])

    result = module.lambda_handler({}, None)

    assert result["errors"] == [(ORG_PEER, "AccessDenied")]
    message = module.sns.publish.call_args.kwargs["Message"]
    assert "Accounts not scanned (1)" in message
    assert ORG_PEER in message


def test_report_says_when_the_org_could_not_be_listed(handler):
    module = handler(member_role_name="audit-read")
    module.organizations.get_paginator.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListAccounts")

    module.lambda_handler({}, None)

    assert module.audited == [ACCOUNT]
    assert "could not be listed" in module.sns.publish.call_args.kwargs["Message"]


def test_clean_scan_sends_nothing(handler, monkeypatch):
    module = handler()
    monkeypatch.setattr(module, "audit_account", lambda *args: [])

    module.lambda_handler({}, None)

    module.sns.publish.assert_not_called()


def test_single_character_wildcard_in_the_ref_is_medium(fn, ctx):
    role = _role(_github({
        "StringEquals": AUD,
        "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme@1/app@2:ref:refs/heads/ma?n"},
    }))

    assert _severities(fn.check_role_trust(role, ACCOUNT, ctx)) == ["MEDIUM"]
