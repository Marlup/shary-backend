import base64
from datetime import datetime, timezone
from unittest import mock


class Req:
    def __init__(self, method="POST", headers=None, args=None, json_body=None):
        self.method = method
        self.headers = headers or {}
        self.args = args or {}
        self._json_body = json_body
        self.content_length = None
        self.base_url = "https://example.com"
        self.path = "/request_decision"

    def get_json(self, silent=True):
        return self._json_body


def _hash_b64(label: str) -> str:
    return base64.b64encode((label.encode("utf-8") + b"_" * 32)[:32]).decode("utf-8")


def _decision_body(recipient_hash: str, request_id: str):
    return {
        "recipient": recipient_hash,
        "request_id": request_id,
        "decision": "accept",
        "schema_version": 1,
    }


def test_request_decision_is_idempotent(main_module):
    recipient_hash = _hash_b64("recipient")
    request_id = _hash_b64("request")
    now_ts = int(datetime.now(timezone.utc).timestamp())

    main_module._require_hash_owner = lambda request, user_hash: "owner@example.com"
    main_module._identity_exists = lambda user_hash: True
    main_module._enforce_rate_limit = lambda request, endpoint_group, actor_key: None
    main_module._find_active_request = lambda request_id_value: (
        "request-doc-1",
        {"recipient": recipient_hash, "expires_at": now_ts + 600},
    )

    state = {}
    decision_ref = mock.Mock()

    def _fake_get():
        snap = mock.Mock()
        if state:
            snap.exists = True
            snap.to_dict.return_value = dict(state)
        else:
            snap.exists = False
        return snap

    decision_ref.get.side_effect = _fake_get
    decision_ref.set.side_effect = lambda payload: state.update(payload)

    collection_mock = mock.Mock()
    collection_mock.document.return_value = decision_ref

    main_module.db.collection.return_value = collection_mock

    first_body, first_status, _ = main_module.request_decision(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=_decision_body(recipient_hash, request_id))
    )
    second_body, second_status, _ = main_module.request_decision(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=_decision_body(recipient_hash, request_id))
    )

    assert first_status == 200
    assert first_body["status"] == "processed"
    assert second_status == 200
    assert second_body["status"] == "already_processed"
    assert second_body["decision_id"] == first_body["decision_id"]
    assert second_body["request_id"] == request_id


def test_request_decision_recipient_scope_enforced(main_module):
    recipient_hash = _hash_b64("recipient")
    other_hash = _hash_b64("other")
    request_id = _hash_b64("request")
    now_ts = int(datetime.now(timezone.utc).timestamp())

    main_module._require_hash_owner = lambda request, user_hash: "owner@example.com"
    main_module._identity_exists = lambda user_hash: True
    main_module._enforce_rate_limit = lambda request, endpoint_group, actor_key: None
    main_module._find_active_request = lambda request_id_value: (
        "request-doc-1",
        {"recipient": other_hash, "expires_at": now_ts + 600},
    )

    body, status, _ = main_module.request_decision(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=_decision_body(recipient_hash, request_id))
    )

    assert status == 403
    assert body["error_code"] == "recipient_scope_violation"


def test_payload_decision_compat_headers(main_module):
    recipient_hash = _hash_b64("recipient")
    request_id = _hash_b64("request")
    now_ts = int(datetime.now(timezone.utc).timestamp())

    main_module._require_hash_owner = lambda request, user_hash: "owner@example.com"
    main_module._identity_exists = lambda user_hash: True
    main_module._enforce_rate_limit = lambda request, endpoint_group, actor_key: None
    main_module._find_active_request = lambda request_id_value: (
        "request-doc-1",
        {"recipient": recipient_hash, "expires_at": now_ts + 600},
    )

    decision_ref = mock.Mock()
    state = {}

    def _fake_get():
        snap = mock.Mock()
        if state:
            snap.exists = True
            snap.to_dict.return_value = dict(state)
        else:
            snap.exists = False
        return snap

    decision_ref.get.side_effect = _fake_get
    decision_ref.set.side_effect = lambda payload: state.update(payload)

    collection_mock = mock.Mock()
    collection_mock.document.return_value = decision_ref
    main_module.db.collection.return_value = collection_mock

    req = Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=_decision_body(recipient_hash, request_id))
    req.path = "/payload_decision"
    first_body, first_status, first_headers = main_module.payload_decision(req)
    second_body, second_status, second_headers = main_module.payload_decision(req)

    assert first_status == 200
    assert first_body["status"] == "processed"
    assert first_headers["X-Compatibility-Endpoint"] == "payload_decision"
    assert first_headers["X-Deprecation-Date"] == "2026-07-31"

    assert second_status == 200
    assert second_body["status"] == "already_processed"
    assert second_headers["X-Compatibility-Endpoint"] == "payload_decision"
    assert second_headers["X-Deprecation-Date"] == "2026-07-31"
