"""Provider supply-chain guard (SR-3, SR-11, CM-14).

Every provider a module or example can pull in must be one this library
has decided to trust. A consumer's `terraform init` runs these providers
as code on whatever machine or CI runner holds their deploy credentials,
so a typo in a `source` is a supply-chain incident, not a lint nit. The
2026-09 Graphalgo campaign published `kreuzwenker/docker`, a one-letter
typosquat of `kreuzwerker/docker`, to the Terraform Registry:
https://www.aikido.dev/blog/graphalgo-terraform-go-modules

Adding a provider means adding it here, in the same reviewed PR.
"""

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

ALLOWED_PROVIDERS = {
    "registry.terraform.io/hashicorp/aws",
    "registry.terraform.io/hashicorp/archive",
}

_SOURCE = re.compile(r'\bsource\s*=\s*"([^"]+)"')
_COMMENT = re.compile(r"(#|//).*$", re.MULTILINE)


def _normalize(source):
    parts = source.strip().lower().split("/")
    if len(parts) == 2:
        parts.insert(0, "registry.terraform.io")
    return "/".join(parts)


def _required_provider_sources(text):
    """Every `source` inside a `required_providers { ... }` block."""
    text = _COMMENT.sub("", text)
    for match in re.finditer(r"required_providers\s*\{", text):
        depth, i = 1, match.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield from _SOURCE.findall(text[match.end() : i])


def _declarations():
    for path in sorted(REPO_ROOT.rglob("*.tf")):
        if ".terraform" in path.parts:
            continue
        for source in _required_provider_sources(path.read_text(encoding="utf-8")):
            yield path.relative_to(REPO_ROOT).as_posix(), source


DECLARATIONS = list(_declarations())


def test_modules_declare_providers():
    # Guards the parser: if it silently found nothing, every other test
    # here would pass vacuously.
    assert len(DECLARATIONS) >= 20


@pytest.mark.parametrize(("path", "source"), DECLARATIONS, ids=[p for p, _ in DECLARATIONS])
def test_provider_source_is_allowlisted(path, source):
    assert _normalize(source) in ALLOWED_PROVIDERS, (
        f"{path} requires provider {source!r}, which is not in ALLOWED_PROVIDERS. "
        "Check the exact namespace on registry.terraform.io, then add it here in the same PR."
    )


@pytest.mark.parametrize(
    "tf",
    [
        'terraform {\n  required_providers {\n    docker = { source = "kreuzwenker/docker" }\n  }\n}\n',
        'terraform {\n  required_providers {\n    aws = {\n      source = "evil.example/hashicorp/aws"\n    }\n  }\n}\n',
    ],
    ids=["typosquat", "foreign-registry-host"],
)
def test_guard_rejects_untrusted_sources(tf):
    sources = list(_required_provider_sources(tf))
    assert sources and not any(_normalize(s) in ALLOWED_PROVIDERS for s in sources)


def test_guard_ignores_module_sources_and_comments():
    tf = (
        'terraform {\n  required_providers {\n'
        '    # x = { source = "evil/x" }\n'
        '    aws = { source = "hashicorp/aws" }\n  }\n}\n'
        'module "m" {\n  source = "../../modules/org-governance"\n}\n'
    )
    assert list(_required_provider_sources(tf)) == ["hashicorp/aws"]
