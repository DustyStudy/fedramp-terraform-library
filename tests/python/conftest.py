"""Load each module's Lambda by file path (module directories contain
hyphens, so they can't be imported as packages), as a fresh module per
test, so environment-driven settings read at import time can differ
between tests.

boto3 clients are created at import but make no calls until used; each
test swaps them for MagicMock objects, so nothing reaches AWS.
"""

import importlib.util
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture
def load_lambda(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")

    def _load(relative_path, **env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        path = REPO_ROOT / relative_path
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return _load
