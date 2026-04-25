import importlib
import os
import sys
import types
from unittest import mock

import pytest


def _fake_on_request():
    return lambda fn: fn


@pytest.fixture
def main_module(monkeypatch):
    fake_db = mock.Mock(name="firestore_db")

    fake_auth = mock.Mock(name="firebase_auth")
    fake_credentials = types.SimpleNamespace(Certificate=mock.Mock(name="Certificate"))
    fake_firestore = types.SimpleNamespace(
        client=mock.Mock(return_value=fake_db),
        Query=types.SimpleNamespace(DESCENDING="DESCENDING"),
    )

    firebase_admin_mod = types.SimpleNamespace(
        auth=fake_auth,
        credentials=fake_credentials,
        firestore=fake_firestore,
        initialize_app=mock.Mock(name="initialize_app"),
    )

    firebase_functions_mod = types.SimpleNamespace(
        https_fn=types.SimpleNamespace(on_request=_fake_on_request),
        options=types.SimpleNamespace(set_global_options=mock.Mock(name="set_global_options")),
    )

    fake_id_token_mod = types.SimpleNamespace(verify_oauth2_token=mock.Mock(name="verify_oauth2_token"))
    fake_google_auth_requests_mod = types.SimpleNamespace(Request=mock.Mock(name="GoogleAuthRequest"))

    monkeypatch.setitem(sys.modules, "firebase_admin", firebase_admin_mod)
    monkeypatch.setitem(sys.modules, "firebase_admin.auth", fake_auth)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", fake_credentials)
    monkeypatch.setitem(sys.modules, "firebase_admin.firestore", fake_firestore)
    monkeypatch.setitem(sys.modules, "firebase_functions", firebase_functions_mod)

    monkeypatch.setitem(sys.modules, "google.oauth2", types.SimpleNamespace(id_token=fake_id_token_mod))
    monkeypatch.setitem(sys.modules, "google.oauth2.id_token", fake_id_token_mod)
    monkeypatch.setitem(
        sys.modules,
        "google.auth.transport",
        types.SimpleNamespace(requests=fake_google_auth_requests_mod),
    )
    monkeypatch.setitem(sys.modules, "google.auth.transport.requests", fake_google_auth_requests_mod)
    monkeypatch.setitem(
        sys.modules,
        "google.cloud.firestore_v1.base_query",
        types.SimpleNamespace(FieldFilter=lambda *args, **kwargs: (args, kwargs)),
    )

    monkeypatch.setenv("SCHEDULER_SERVICE_ACCOUNT_EMAIL", "scheduler@example.iam.gserviceaccount.com")
    monkeypatch.setenv("SCHEDULER_AUDIENCE", "https://example.com/cleanup")

    if "main" in sys.modules:
        del sys.modules["main"]

    module = importlib.import_module("main")

    # Keep test environment deterministic.
    module.db = fake_db
    return module
