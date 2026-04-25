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

    def get_json(self, silent=True):
        return self._json_body


def _hash_b64(label: str) -> str:
    # Produce a stable 32-byte payload for hash-shape validation.
    return base64.b64encode((label.encode("utf-8") + b"_" * 32)[:32]).decode("utf-8")


def _payload(now_ts: int, ttl: int):
    return {
        "user": _hash_b64("user"),
        "recipient": _hash_b64("recipient"),
        "creation_at": now_ts,
        "expires_at": now_ts + ttl,
        "data": "aGVsbG8=",
        "verification": "verify-token",
        "signature": "sig-token",
    }


def test_ping_requires_get(main_module):
    response, status = main_module.ping(Req(method="POST"))
    assert status == 405
    assert "Method not allowed" in response["error"]


def test_upload_payload_rejects_ttl_above_limit(main_module):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    body = _payload(now_ts, ttl=main_module.MAX_DOCUMENT_TTL_SECONDS + 1)

    response, status = main_module.upload_payload(
        Req(method="POST", headers={"Authorization": "Bearer t"}, json_body=body)
    )

    assert status == 400
    assert response["error"] == "Document TTL exceeds allowed maximum."


def test_fetch_payload_caps_limit_and_queries_only_unexpired(main_module):
    user_hash = _hash_b64("recipient")

    main_module._require_hash_owner = lambda request, requested_hash: "owner@example.com"
    main_module._identity_exists = lambda user: True

    query = (
        main_module.db.collection.return_value
        .where.return_value
        .where.return_value
        .order_by.return_value
        .limit.return_value
    )
    query.stream.return_value = []

    response, status = main_module.fetch_payload(
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

    response, status = main_module._v2_register_identity(
        Req(
            method="POST",
            headers={"Authorization": "Bearer super-secret-token"},
            json_body={
                "email": email,
                "pub_kex_b64": pub_kex_b64,
                "pub_sign_b64": pub_sign_b64,
                "client_ts": now_ts,
                "proof": {
                    "verification_b64": verification,
                    "signature_b64": "dummy",
                },
            },
        )
    )

    assert status == 201
    assert response == {"status": "created"}
