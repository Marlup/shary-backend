import base64
from datetime import datetime, timezone


class Req:
    def __init__(self, method="GET", headers=None, args=None, json_body=None):
        self.method = method
        self.headers = headers or {}
        self.args = args or {}
        self._json_body = json_body
        self.content_length = None
        self.base_url = "https://example.com"
        self.path = "/"

    def get_json(self, silent=True):
        return self._json_body


def _hash_b64(label: str) -> str:
    # Produce a stable 32-byte payload for hash-shape validation.
    return base64.b64encode((label.encode("utf-8") + b"_" * 32)[:32]).decode("utf-8")


def _signature_b64() -> str:
    return base64.b64encode(b"s" * 64).decode("utf-8")


def _payload(now_ts: int, ttl: int):
    return {
        "user": _hash_b64("user"),
        "recipient": _hash_b64("recipient"),
        "creation_at": now_ts,
        "expires_at": now_ts + ttl,
        "data": "aGVsbG8=",
        "verification": _hash_b64("verification"),
        "signature": _signature_b64(),
        "schema_version": 1,
    }


def test_ping_requires_get(main_module):
    response, status, headers = main_module.ping(Req(method="POST"))
    assert status == 405
    assert response["error_code"] == "method_not_allowed"
    assert response["message"] == "Method not allowed. Use GET."
    assert response["request_id"] == headers["X-Request-Id"]


def test_request_id_passthrough(main_module):
    req = Req(method="GET", headers={"X-Request-Id": "req-abc-123"})
    response, status, headers = main_module.ping(req)
    assert status == 200
    assert response["request_id"] == "req-abc-123"
    assert headers["X-Request-Id"] == "req-abc-123"


def test_request_id_generated_when_missing(main_module):
    req = Req(method="GET", headers={})
    response, status, headers = main_module.ping(req)
    assert status == 200
    assert "X-Request-Id" in headers
    assert headers["X-Request-Id"] == response["request_id"]
    assert len(headers["X-Request-Id"]) >= 8


def test_upload_payload_rejects_ttl_above_limit(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    body = _payload(now_ts, ttl=main_module.MAX_DOCUMENT_TTL_SECONDS + 1)

    response, status, _ = main_module.upload_payload(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=body)
    )

    assert status == 400
    assert response["error_code"] == "ttl_too_large"
    assert response["message"] == "Document TTL exceeds allowed maximum."


def test_upload_payload_rejects_unsupported_schema(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    body = _payload(now_ts, ttl=60)
    body["schema_version"] = 2

    response, status, _ = main_module.upload_payload(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=body)
    )

    assert status == 400
    assert response["error_code"] == "unsupported_schema_version"


def test_upload_payload_rate_limit_contract(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    body = _payload(now_ts, ttl=60)

    main_module._validate_sender_binding = lambda request, payload: payload["user"]
    main_module._get_identity = lambda user_hash: {"pub_sign_b64": base64.b64encode(b"k" * 32).decode("utf-8")}
    main_module._verify_payload_integrity = lambda payload, sender_pub_sign_b64: None
    main_module._enforce_rate_limit = lambda request, endpoint_group, actor_key: (_ for _ in ()).throw(
        main_module.HttpError(
            429,
            "Rate limit exceeded. Retry after 19 seconds.",
            error_code="rate_limited",
            details={"retry_after_seconds": 19},
        )
    )

    response, status, _ = main_module.upload_payload(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=body)
    )

    assert status == 429
    assert response["error_code"] == "rate_limited"
    assert response["retry_after_seconds"] == 19


def test_upload_request_rejects_unsupported_schema(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    body = _payload(now_ts, ttl=60)
    body["schema_version"] = 2

    response, status, _ = main_module.upload_request(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=body)
    )

    assert status == 400
    assert response["error_code"] == "unsupported_schema_version"


def test_upload_request_rate_limit_contract(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    body = _payload(now_ts, ttl=60)

    main_module._validate_sender_binding = lambda request, payload: payload["user"]
    main_module._get_identity = lambda user_hash: {"pub_sign_b64": base64.b64encode(b"k" * 32).decode("utf-8")}
    main_module._verify_payload_integrity = lambda payload, sender_pub_sign_b64: None
    main_module._enforce_rate_limit = lambda request, endpoint_group, actor_key: (_ for _ in ()).throw(
        main_module.HttpError(
            429,
            "Rate limit exceeded. Retry after 23 seconds.",
            error_code="rate_limited",
            details={"retry_after_seconds": 23},
        )
    )

    response, status, _ = main_module.upload_request(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=body)
    )

    assert status == 429
    assert response["error_code"] == "rate_limited"
    assert response["retry_after_seconds"] == 23


def test_fetch_payload_caps_limit_and_queries_only_unexpired(main_module):
    user_hash = _hash_b64("recipient")

    main_module._require_hash_owner = lambda request, requested_hash: "owner@example.com"
    main_module._identity_exists = lambda user: True
    main_module._enforce_rate_limit = lambda request, endpoint_group, actor_key: None

    query = (
        main_module.db.collection.return_value
        .where.return_value
        .where.return_value
        .order_by.return_value
        .limit.return_value
    )
    query.stream.return_value = []

    response, status, _ = main_module.fetch_payload(
        Req(
            method="GET",
            headers={"Authorization": "Bearer t"},
            args={"user": user_hash, "limit": "9999"},
        )
    )

    assert status == 200
    assert response["payload"] == []

    # Ensure bounded read size is enforced.
    limited_query = (
        main_module.db.collection.return_value
        .where.return_value
        .where.return_value
        .order_by.return_value
    )
    limited_query.limit.assert_called_once_with(main_module.MAX_FETCH_LIMIT)


def test_fetch_request_rejects_unsupported_schema_query(main_module):
    user_hash = _hash_b64("recipient")
    response, status, _ = main_module.fetch_request(
        Req(
            method="GET",
            headers={"Authorization": "Bearer t"},
            args={"user": user_hash, "schema_version": "2"},
        )
    )
    assert status == 400
    assert response["error_code"] == "unsupported_schema_version"


def test_fetch_request_recipient_identity_missing(main_module):
    user_hash = _hash_b64("recipient")
    main_module._require_hash_owner = lambda request, requested_hash: "owner@example.com"
    main_module._identity_exists = lambda user: False
    response, status, _ = main_module.fetch_request(
        Req(
            method="GET",
            headers={"Authorization": "Bearer t"},
            args={"user": user_hash},
        )
    )
    assert status == 403
    assert response["error_code"] == "recipient_identity_missing"


def test_deprecated_endpoints_return_contract_envelope(main_module):
    req = Req(method="POST", headers={"Authorization": "Bearer t"})
    for endpoint in (main_module.upload_user, main_module.delete_user):
        response, status, headers = endpoint(req)
        assert status == 410
        assert response["error_code"] == "deprecated_endpoint"
        assert "message" in response
        assert "request_id" in response
        assert response["request_id"] == headers["X-Request-Id"]


def test_error_envelope_required_keys(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    bad_schema_body = _payload(now_ts, ttl=60)
    bad_schema_body["schema_version"] = 2

    scenarios = [
        lambda: main_module.ping(Req(method="POST")),
        lambda: main_module.upload_payload(
            Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=bad_schema_body)
        ),
        lambda: main_module.upload_user(Req(method="POST", headers={"Authorization": "Bearer t"})),
    ]

    for run_case in scenarios:
        response, status, headers = run_case()
        assert status >= 400
        assert "error_code" in response
        assert "message" in response
        assert "request_id" in response
        assert response["request_id"] == headers["X-Request-Id"]


def test_v2_register_does_not_echo_bearer_token(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    email = "user@example.com"
    user_hash = main_module._hash_b64(email)
    pub_kex_b64 = "ZmFrZS1wdWIta2V4"
    pub_sign_b64 = base64.b64encode(b"x" * 32).decode("utf-8")
    verification = main_module._hash_b64(".".join(["register", user_hash, pub_kex_b64, pub_sign_b64, str(now_ts)]))

    main_module._require_verified_email_match = lambda request, requested_email: (requested_email, "uid-1")
    main_module._verify_ed25519_detached = lambda verification_b64, signature_b64, key_b64: True

    doc_ref = main_module.db.collection.return_value.document.return_value
    doc_ref.get.return_value.exists = False

    response, status, _ = main_module._v2_register_identity(
        Req(
            method="POST",
            headers={"Authorization": "Bearer super-secret-token"},
            json_body={
                "email": email,
                "pub_kex_b64": pub_kex_b64,
                "pub_sign_b64": pub_sign_b64,
                "client_ts": now_ts,
                "schema_version": 1,
                "proof": {
                    "verification_b64": verification,
                    "signature_b64": _signature_b64(),
                },
            },
        )
    )

    assert status == 201
    assert response["status"] == "created"
    assert "super-secret-token" not in str(response)
