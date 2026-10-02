from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/rds-access-auditor/lambda/audit_rds_access.py"
ACCOUNT = "111111111111"
INSTANCE_ARN = f"arn:aws:rds:us-east-1:{ACCOUNT}:db:app"
CLUSTER_ARN = f"arn:aws:rds:us-east-1:{ACCOUNT}:cluster:app"
MASTERS = [("db-ABC", "postgres")]


@pytest.fixture
def fn(load_lambda):
    return load_lambda(LAMBDA)


def _severities(findings):
    return [f["severity"] for f in findings]


def _instance(**overrides):
    instance = {
        "DBInstanceArn": INSTANCE_ARN,
        "DbiResourceId": "db-ABC",
        "Engine": "postgres",
        "MasterUsername": "postgres",
        "MasterUserSecret": {"SecretArn": "arn:aws:secretsmanager:us-east-1:111111111111:secret:rds!db"},
        "IAMDatabaseAuthenticationEnabled": True,
        "PubliclyAccessible": False,
        "Endpoint": {"Port": 5432},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
        "DBParameterGroups": [{"DBParameterGroupName": "app-pg16"}],
    }
    instance.update(overrides)
    return instance


def _group(*rules, group_id="sg-1"):
    return {"GroupId": group_id, "IpPermissions": list(rules)}


def _rule(from_port, to_port, cidr="0.0.0.0/0", protocol="tcp"):
    key = ("Ipv6Ranges", "CidrIpv6") if ":" in cidr else ("IpRanges", "CidrIp")
    return {"IpProtocol": protocol, "FromPort": from_port, "ToPort": to_port, key[0]: [{key[1]: cidr}]}


# --- public access ---------------------------------------------------------------


def test_private_instance_is_clean(fn):
    assert fn.check_public_access(_instance(), [_group(_rule(5432, 5432))], ACCOUNT) == []


def test_public_instance_open_on_its_port_is_critical(fn):
    findings = fn.check_public_access(_instance(PubliclyAccessible=True), [_group(_rule(5432, 5432))], ACCOUNT)

    assert _severities(findings) == ["CRITICAL"]
    assert "sg-1" in findings[0]["detail"] and "5432" in findings[0]["detail"]


@pytest.mark.parametrize(
    "rule",
    [_rule(0, 65535), _rule(-1, -1, protocol="-1"), _rule(5432, 5432, cidr="::/0")],
    ids=["port-range", "all-traffic", "ipv6"],
)
def test_other_rules_that_admit_the_internet_are_critical(fn, rule):
    findings = fn.check_public_access(_instance(PubliclyAccessible=True), [_group(rule)], ACCOUNT)

    assert _severities(findings) == ["CRITICAL"]


@pytest.mark.parametrize(
    "rule",
    [_rule(5432, 5432, cidr="10.0.0.0/8"), _rule(22, 22)],
    ids=["private-cidr", "other-port"],
)
def test_public_instance_with_closed_groups_is_high(fn, rule):
    findings = fn.check_public_access(_instance(PubliclyAccessible=True), [_group(rule)], ACCOUNT)

    assert _severities(findings) == ["HIGH"]


# --- credentials --------------------------------------------------------------------


def test_managed_master_secret_and_iam_auth_are_clean(fn):
    assert fn.check_credentials(_instance(), INSTANCE_ARN, ACCOUNT) == []


def test_unmanaged_master_password_is_medium(fn):
    findings = fn.check_credentials(_instance(MasterUserSecret=None), INSTANCE_ARN, ACCOUNT)

    assert [(f["check"], f["severity"]) for f in findings] == [("master-credentials", "MEDIUM")]
    assert "'postgres'" in findings[0]["detail"]


def test_iam_auth_off_is_low(fn):
    findings = fn.check_credentials(_instance(IAMDatabaseAuthenticationEnabled=False), INSTANCE_ARN, ACCOUNT)

    assert [(f["check"], f["severity"]) for f in findings] == [("iam-auth", "LOW")]


def test_iam_auth_is_not_expected_where_the_engine_lacks_it(fn):
    instance = _instance(Engine="sqlserver-se", IAMDatabaseAuthenticationEnabled=False)

    assert fn.check_credentials(instance, INSTANCE_ARN, ACCOUNT) == []


# --- transport ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("engine", "parameters"),
    [
        ("postgres", {"rds.force_ssl": "1"}),
        ("aurora-postgresql", {"rds.force_ssl": "1"}),
        ("mysql", {"require_secure_transport": "ON"}),
        ("aurora-mysql", {"require_secure_transport": "1"}),
        ("oracle-ee", {}),
    ],
)
def test_enforced_tls_is_clean(fn, engine, parameters):
    assert fn.check_transport(engine, parameters, "pg", INSTANCE_ARN, ACCOUNT) == []


@pytest.mark.parametrize(
    ("engine", "parameters", "shown"),
    [
        ("postgres", {"rds.force_ssl": "0"}, "'0'"),
        ("mariadb", {"require_secure_transport": None}, "not set"),
        ("sqlserver-ex", {}, "not set"),
    ],
)
def test_unenforced_tls_is_medium(fn, engine, parameters, shown):
    findings = fn.check_transport(engine, parameters, "pg", INSTANCE_ARN, ACCOUNT)

    assert _severities(findings) == ["MEDIUM"]
    assert shown in findings[0]["detail"]


# --- rds-db:connect scope -------------------------------------------------------------


@pytest.mark.parametrize(
    "resource",
    [
        "*",
        "arn:aws:rds-db:*:*:*",
        "arn:aws:rds-db:us-east-1:111111111111:dbuser:*",
        "arn:aws:rds-db:us-east-1:111111111111:dbuser:db-ABC/*",
    ],
)
def test_connect_as_any_user_is_high(fn, resource):
    assert fn.connect_scope_problem(resource, MASTERS)[0] == "HIGH"


@pytest.mark.parametrize(
    "resource",
    ["arn:aws:rds-db:us-east-1:111111111111:dbuser:db-ABC/postgres", "arn:aws:rds-db:us-east-1:111111111111:dbuser:*/postgres"],
)
def test_connect_as_the_master_user_is_high(fn, resource):
    severity, detail = fn.connect_scope_problem(resource, MASTERS)

    assert severity == "HIGH"
    assert "master user 'postgres'" in detail


def test_connect_as_an_app_user_is_clean(fn):
    assert fn.connect_scope_problem("arn:aws:rds-db:us-east-1:111111111111:dbuser:db-ABC/app_readonly", MASTERS) is None


def test_partial_user_wildcard_is_medium(fn):
    assert fn.connect_scope_problem("arn:aws:rds-db:us-east-1:111111111111:dbuser:db-ABC/app_*", MASTERS)[0] == "MEDIUM"


def test_same_user_name_on_another_database_is_not_the_master(fn):
    resource = "arn:aws:rds-db:us-east-1:111111111111:dbuser:db-OTHER/postgres"

    assert fn.connect_scope_problem(resource, MASTERS) is None


def test_other_services_are_ignored(fn):
    assert fn.connect_scope_problem("arn:aws:s3:::bucket/*", MASTERS) is None


def _statement(action, resource, effect="Allow"):
    return {"Version": "2012-10-17", "Statement": [{"Effect": effect, "Action": action, "Resource": resource}]}


@pytest.mark.parametrize("action", ["rds-db:connect", "RDS-DB:Connect", "rds-db:*", ["s3:GetObject", "rds-db:conn*"]])
def test_actions_that_grant_connect_are_checked(fn, action):
    findings = fn.check_policy_document(_statement(action, "*"), "role", MASTERS, ACCOUNT)

    assert _severities(findings) == ["HIGH"]


@pytest.mark.parametrize(
    "document",
    [_statement("*", "*"), _statement("rds:*", "*"), _statement("rds-db:connect", "*", effect="Deny")],
    ids=["admin", "rds-control-plane", "deny"],
)
def test_statements_that_do_not_grant_connect_are_ignored(fn, document):
    # "*" admins are everywhere; flagging each would bury the real grants.
    assert fn.check_policy_document(document, "role", MASTERS, ACCOUNT) == []


def test_url_encoded_policy_documents_are_decoded(fn):
    encoded = "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22rds-db%3Aconnect%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"

    assert _severities(fn.check_policy_document(encoded, "role", MASTERS, ACCOUNT)) == ["HIGH"]


def test_check_iam_covers_inline_and_attached_managed_policies(fn):
    wide = _statement("rds-db:connect", "*")
    details = {
        "users": [{"Arn": "arn:aws:iam::111111111111:user/u", "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": wide}]}],
        "groups": [],
        "roles": [
            {"Arn": "arn:aws:iam::111111111111:role/app", "RolePolicyList": [{"PolicyName": "db", "PolicyDocument": wide}]},
            {
                "Arn": "arn:aws:iam::111111111111:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS",
                "Path": "/aws-service-role/rds.amazonaws.com/",
                "RolePolicyList": [{"PolicyName": "x", "PolicyDocument": wide}],
            },
        ],
        "policies": [
            {
                "Arn": "arn:aws:iam::111111111111:policy/attached",
                "AttachmentCount": 3,
                "PolicyVersionList": [
                    {"IsDefaultVersion": False, "Document": wide},
                    {"IsDefaultVersion": True, "Document": wide},
                ],
            },
            {"Arn": "arn:aws:iam::111111111111:policy/unused", "AttachmentCount": 0, "PolicyVersionList": [{"IsDefaultVersion": True, "Document": wide}]},
        ],
    }

    resources = [f["resource"] for f in fn.check_iam(details, MASTERS, ACCOUNT)]

    assert resources == [
        "arn:aws:iam::111111111111:user/u (inline policy p)",
        "arn:aws:iam::111111111111:role/app (inline policy db)",
        "arn:aws:iam::111111111111:policy/attached (attached to 3)",
    ]


# --- collection and handler -----------------------------------------------------------


def _paginated(pages_by_operation, calls=None):
    client = MagicMock()

    def paginator(op):
        def paginate(**kwargs):
            if calls is not None:
                calls.append((op, kwargs))
            return pages_by_operation[op]

        return MagicMock(paginate=MagicMock(side_effect=paginate))

    client.get_paginator.side_effect = paginator
    return client


def _account_clients(instances=(), clusters=(), parameters=(), cluster_parameters=(), groups=(), iam_pages=None, calls=None):
    rds = _paginated(
        {
            "describe_db_instances": [{"DBInstances": list(instances)}],
            "describe_db_clusters": [{"DBClusters": list(clusters)}],
            "describe_db_parameters": [{"Parameters": list(parameters)}],
            "describe_db_cluster_parameters": [{"Parameters": list(cluster_parameters)}],
        },
        calls,
    )
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": list(groups)}
    iam = _paginated({"get_account_authorization_details": iam_pages or [{}]})
    by_service = {"rds": rds, "ec2": ec2, "iam": iam}
    return lambda service, region: by_service[service]


def test_audit_account_runs_every_check(fn):
    cluster = {
        "DBClusterArn": CLUSTER_ARN,
        "DbClusterResourceId": "cluster-XYZ",
        "Engine": "aurora-postgresql",
        "MasterUsername": "admin",
        "IAMDatabaseAuthenticationEnabled": True,
        "DBClusterParameterGroup": "aurora-pg16",
    }
    member = _instance(
        DBInstanceArn=f"arn:aws:rds:us-east-1:{ACCOUNT}:db:app-1",
        DBClusterIdentifier="app",
        Engine="aurora-postgresql",
        MasterUserSecret=None,
        PubliclyAccessible=True,
    )
    standalone = _instance(IAMDatabaseAuthenticationEnabled=False)
    docdb = _instance(Engine="docdb", PubliclyAccessible=True, MasterUserSecret=None)
    iam_pages = [{"RoleDetailList": [{"Arn": "arn:aws:iam::111111111111:role/app", "RolePolicyList": [
        {"PolicyName": "db", "PolicyDocument": _statement("rds-db:connect", "arn:aws:rds-db:us-east-1:111111111111:dbuser:cluster-XYZ/admin")},
    ]}]}]
    client = _account_clients(
        instances=[member, standalone, docdb],
        clusters=[cluster],
        parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "1"}],
        cluster_parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "0"}],
        groups=[_group(_rule(5432, 5432))],
        iam_pages=iam_pages,
    )

    findings = fn.audit_account(ACCOUNT, client, ["us-east-1"])

    assert sorted((f["check"], f["severity"], f["resource"].split(":")[-1]) for f in findings) == [
        ("db-connect", "HIGH", "role/app (inline policy db)"),
        ("iam-auth", "LOW", "app"),
        ("master-credentials", "MEDIUM", "app"),
        ("public-access", "CRITICAL", "app-1"),
        ("transport", "MEDIUM", "app"),
    ]


def test_parameter_groups_are_read_once_per_region(fn):
    calls = []
    client = _account_clients(
        instances=[_instance(), _instance(DBInstanceArn=INSTANCE_ARN + "2", DbiResourceId="db-DEF")],
        parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "1"}],
        calls=calls,
    )

    fn.audit_account(ACCOUNT, client, ["us-east-1"])

    assert [op for op, _ in calls].count("describe_db_parameters") == 1


def test_security_groups_are_only_read_for_public_instances(fn):
    client = _account_clients(instances=[_instance()], parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "1"}])

    fn.audit_account(ACCOUNT, client, ["us-east-1"])

    client("ec2", "us-east-1").describe_security_groups.assert_not_called()


def _handler_env(fn, monkeypatch, member_role="", org_accounts=None):
    monkeypatch.setattr(fn, "MEMBER_ROLE_NAME", member_role)
    monkeypatch.setattr(fn, "REGIONS", ["us-east-1"])
    monkeypatch.setattr(fn, "SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111111111111:t")
    fn.sts = MagicMock()
    fn.sts.get_caller_identity.return_value = {"Account": ACCOUNT, "Arn": f"arn:aws-us-gov:sts::{ACCOUNT}:assumed-role/r/s"}
    fn.sns = MagicMock()
    fn.organizations = MagicMock()
    if org_accounts is None:
        fn.organizations.get_paginator.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListAccounts")
    else:
        fn.organizations.get_paginator.return_value.paginate.return_value = [
            {"Accounts": [{"Id": a, "Status": "ACTIVE"} for a in org_accounts]}
        ]


def test_single_account_by_default(fn, monkeypatch):
    _handler_env(fn, monkeypatch, org_accounts=[ACCOUNT, "222222222222"])
    monkeypatch.setattr(fn, "_client_factory", lambda credentials=None: _account_clients())

    result = fn.lambda_handler({}, None)

    assert result["accounts_scanned"] == 1
    fn.organizations.get_paginator.assert_not_called()
    fn.sns.publish.assert_not_called()


def test_member_accounts_are_scanned_and_failures_reported(fn, monkeypatch):
    _handler_env(fn, monkeypatch, member_role="audit-read", org_accounts=[ACCOUNT, "222222222222", "333333333333"])
    monkeypatch.setattr(fn, "_client_factory", lambda credentials=None: _account_clients(instances=[_instance(MasterUserSecret=None)], parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "1"}]))

    def assume_role(RoleArn, RoleSessionName):
        if "333333333333" in RoleArn:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole")
        assert RoleArn == "arn:aws-us-gov:iam::222222222222:role/audit-read"
        return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}

    fn.sts.assume_role.side_effect = assume_role

    result = fn.lambda_handler({}, None)

    assert result["accounts_scanned"] == 2
    assert result["errors"] == [("333333333333", "AccessDenied")]
    assert result["counts"]["MEDIUM"] == 2
    message = fn.sns.publish.call_args.kwargs["Message"]
    assert "Accounts not scanned (1)" in message and "333333333333: AccessDenied" in message


def test_unlisted_organization_is_called_out(fn, monkeypatch):
    _handler_env(fn, monkeypatch, member_role="audit-read")
    monkeypatch.setattr(fn, "_client_factory", lambda credentials=None: _account_clients(instances=[_instance(MasterUserSecret=None)], parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "1"}]))

    result = fn.lambda_handler({}, None)

    assert result["accounts_scanned"] == 1
    assert "only this account was scanned" in fn.sns.publish.call_args.kwargs["Message"]
