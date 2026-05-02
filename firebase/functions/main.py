import base64
import hashlib
import logging
import os
import re
import secrets
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from firebase_admin import auth, credentials, firestore, initialize_app
from firebase_functions import https_fn, options
from flask import Request
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.cloud.firestore_v1.base_query import FieldFilter
from google.oauth2 import id_token

from constants import (
    COLLECTION_PAYLOADS,
    COLLECTION_RATE_LIMITS,
    COLLECTION_REQUESTS,
    COLLECTION_REQUEST_DECISIONS,
    DECISION_COMPAT_DEPRECATION_DATE,
    DEFAULT_DOCUMENT_TTL_SECONDS,
    DEFAULT_FETCH_LIMIT,
    DEFAULT_SCHEMA_VERSION,
    DEFAULT_SCHEDULER_SERVICE_ACCOUNT_EMAIL,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_DATA_B64_LENGTH,
    MAX_DOCUMENT_TTL_SECONDS,
    MAX_FETCH_LIMIT,
    MAX_REQUEST_ID_LENGTH,
    MAX_SIGNATURE_B64_LENGTH,
    MAX_VERIFICATION_B64_LENGTH,
    RATE_LIMIT_DECISION_PER_WINDOW,
    RATE_LIMIT_FETCH_PER_WINDOW,
    RATE_LIMIT_UPLOAD_PER_WINDOW,
    RATE_LIMIT_WINDOW_SECONDS,
    REQUIRED_PAYLOAD_FIELDS,
)


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

FUNCTIONS_REGION = os.getenv("FUNCTIONS_REGION", "europe-southwest1")
options.set_global_options(region=FUNCTIONS_REGION)

REQUEST_ID_HEADER = "X-Request-Id"
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SUPPORTED_SCHEMA_VERSIONS = {DEFAULT_SCHEMA_VERSION}
RATE_LIMITS_PER_WINDOW = {
    "upload": RATE_LIMIT_UPLOAD_PER_WINDOW,
    "fetch": RATE_LIMIT_FETCH_PER_WINDOW,
    "decision": RATE_LIMIT_DECISION_PER_WINDOW,
}
DECISION_VALUES = {
    "accept": "accepted",
    "reject": "rejected",
    "cancel": "cancelled",
}


def _initialize_firebase_admin() -> None:
    try:
        if os.getenv("K_SERVICE"):
            initialize_app()
            return

        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if cred_path:
            initialize_app(credentials.Certificate(cred_path))
        else:
            initialize_app()
    except ValueError:
        # Default app is already initialized (common during tests/reloads).
        pass


_initialize_firebase_admin()

db = None


def _db():
    global db
    if db is None:
        db = firestore.client()
    return db


COLLECTION_IDENTITIES_V2 = "identities_v2"
COLLECTION_IDENTITY_NONCES_V2 = "identity_rotate_nonces_v2"
NONCE_TTL_SECONDS = 5 * 60
MAX_BATCH_SIZE = 500


class HttpError(Exception):
    def __init__(
        self,
        status: int,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.status = status
        self.message = message
        self.error_code = error_code
        self.details = details or {}


def _snap_exists(snapshot: Any) -> bool:
    return getattr(snapshot, "exists", False) is True


def _doc_id(value: str) -> str:
    # Firestore document IDs cannot contain "/".
    # Percent-escape to keep a deterministic reversible mapping.
    return value.replace("%", "%25").replace("/", "%2F")


def _sanitize_request_id(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return ""
    if len(candidate) > MAX_REQUEST_ID_LENGTH:
        return ""
    if not REQUEST_ID_PATTERN.fullmatch(candidate):
        return ""
    return candidate


def _request_id_from_request(request: Request, payload: Optional[Dict[str, Any]] = None) -> str:
    cached = getattr(request, "_shary_request_id", "")
    if isinstance(cached, str) and cached:
        return cached

    from_header = _sanitize_request_id(request.headers.get(REQUEST_ID_HEADER, ""))
    if from_header:
        setattr(request, "_shary_request_id", from_header)
        return from_header

    if isinstance(payload, dict):
        from_body = _sanitize_request_id(str(payload.get("request_id", "")))
        if from_body:
            setattr(request, "_shary_request_id", from_body)
            return from_body

    generated = uuid.uuid4().hex
    setattr(request, "_shary_request_id", generated)
    return generated


def _json(request: Request) -> Dict[str, Any]:
    content_length = request.content_length or 0
    if content_length > (MAX_DATA_B64_LENGTH + 8192):
        raise HttpError(413, "Request body too large.", error_code="payload_too_large")

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise HttpError(400, "Invalid JSON body.", error_code="invalid_json")

    _request_id_from_request(request, payload)
    return payload


def _require_str(payload: Dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise HttpError(400, f"Missing or invalid field: {field}", error_code="invalid_argument")
    return value.strip()


def _require_int(payload: Dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool):
        raise HttpError(400, f"Missing or invalid field: {field}", error_code="invalid_argument")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise HttpError(400, f"Missing or invalid field: {field}", error_code="invalid_argument")


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _hash_b64(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("utf-8")


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("utf-8"), validate=True)


def _require_method(request: Request, method: str) -> None:
    if request.method.upper() != method:
        raise HttpError(405, f"Method not allowed. Use {method}.", error_code="method_not_allowed")


def _is_sha256_hash_b64(value: str) -> bool:
    try:
        raw = base64.b64decode(value.encode("utf-8"), validate=True)
        return len(raw) == 32
    except Exception:
        return False


def _require_hash_b64(value: str, field_name: str) -> str:
    if not _is_sha256_hash_b64(value):
        raise HttpError(400, f"Invalid hash format for field: {field_name}", error_code="invalid_hash")
    return value


def _require_signature_b64(value: str, field_name: str) -> str:
    if len(value) > MAX_SIGNATURE_B64_LENGTH:
        raise HttpError(400, f"{field_name} is too large.", error_code="invalid_signature")
    try:
        decoded = _decode_b64(value)
    except Exception as exc:
        raise HttpError(400, f"Invalid base64 for field: {field_name}", error_code="invalid_signature") from exc
    if len(decoded) != 64:
        raise HttpError(400, f"Invalid signature size for field: {field_name}", error_code="invalid_signature")
    return value


def _schema_version_from_payload(payload: Dict[str, Any]) -> int:
    raw = payload.get("schema_version", DEFAULT_SCHEMA_VERSION)
    if isinstance(raw, bool):
        raise HttpError(400, "Invalid schema_version.", error_code="invalid_schema_version")
    if isinstance(raw, int):
        version = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        version = int(raw.strip())
    else:
        raise HttpError(400, "Invalid schema_version.", error_code="invalid_schema_version")

    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise HttpError(400, f"Unsupported schema_version: {version}", error_code="unsupported_schema_version")
    return version


def _schema_version_from_query(request: Request) -> int:
    raw = (request.args.get("schema_version", "") or "").strip()
    if not raw:
        return DEFAULT_SCHEMA_VERSION
    if not raw.isdigit():
        raise HttpError(400, "Invalid schema_version.", error_code="invalid_schema_version")
    parsed = int(raw)
    if parsed not in SUPPORTED_SCHEMA_VERSIONS:
        raise HttpError(400, f"Unsupported schema_version: {parsed}", error_code="unsupported_schema_version")
    return parsed


def _safe_positive_limit(request: Request) -> int:
    raw = (request.args.get("limit", "") or "").strip()
    if not raw:
        return DEFAULT_FETCH_LIMIT
    if not raw.isdigit():
        raise HttpError(400, "Invalid limit.", error_code="invalid_argument")
    parsed = int(raw)
    if parsed <= 0:
        raise HttpError(400, "Invalid limit.", error_code="invalid_argument")
    return min(parsed, MAX_FETCH_LIMIT)


def _canonical_payload_digest(payload: Dict[str, Any]) -> str:
    canonical = ".".join(
        [
            payload["user"],
            payload["recipient"],
            payload["data"],
            str(payload["creation_at"]),
            str(payload["expires_at"]),
        ]
    )
    return _hash_b64(canonical)


def _normalize_payload_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    user_hash = _require_hash_b64(_require_str(payload, "user"), "user")
    recipient_hash = _require_hash_b64(_require_str(payload, "recipient"), "recipient")
    data = _require_str(payload, "data")
    verification = _require_hash_b64(_require_str(payload, "verification"), "verification")
    signature = _require_signature_b64(_require_str(payload, "signature"), "signature")
    creation_at = _require_int(payload, "creation_at")

    raw_expires_at = payload.get("expires_at")
    if raw_expires_at in (None, ""):
        expires_at = creation_at + DEFAULT_DOCUMENT_TTL_SECONDS
    else:
        expires_at = _require_int(payload, "expires_at")

    if len(data) > MAX_DATA_B64_LENGTH:
        raise HttpError(400, "Payload data is too large.", error_code="payload_too_large")
    if len(verification) > MAX_VERIFICATION_B64_LENGTH:
        raise HttpError(400, "Payload verification is too large.", error_code="invalid_argument")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if creation_at > (now_ts + MAX_CLOCK_SKEW_SECONDS):
        raise HttpError(400, "creation_at is too far in the future.", error_code="invalid_timestamp")
    if expires_at <= now_ts:
        raise HttpError(400, "expires_at must be in the future.", error_code="invalid_timestamp")
    if expires_at <= creation_at:
        raise HttpError(
            400,
            "expires_at must be greater than creation_at.",
            error_code="invalid_timestamp",
        )
    if (expires_at - creation_at) > MAX_DOCUMENT_TTL_SECONDS:
        raise HttpError(400, "Document TTL exceeds allowed maximum.", error_code="ttl_too_large")

    return {
        "user": user_hash,
        "recipient": recipient_hash,
        "creation_at": creation_at,
        "expires_at": expires_at,
        "data": data,
        "verification": verification,
        "signature": signature,
    }


def _get_identity(user_hash: str) -> Optional[Dict[str, Any]]:
    snap = _db().collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash)).get()
    if not _snap_exists(snap):
        return None
    row = snap.to_dict() or {}
    if str(row.get("user_hash", "")) != user_hash:
        return None
    return row


def _identity_exists(user_hash: str) -> bool:
    return _get_identity(user_hash) is not None


def _verify_ed25519_detached(message_hash_b64: str, signature_b64: str, public_sign_b64: str) -> bool:
    try:
        message = _decode_b64(message_hash_b64)
        signature = _decode_b64(signature_b64)
        public_key = _decode_b64(public_sign_b64)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        vk = Ed25519PublicKey.from_public_bytes(public_key)
        vk.verify(signature, message)
        return True
    except (ValueError, InvalidSignature):
        return False


def _principal_from_bearer(request: Request) -> Tuple[str, bool, str]:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HttpError(401, "Missing bearer token.", error_code="missing_bearer")

    token = header[len("Bearer ") :].strip()
    if not token:
        raise HttpError(401, "Missing bearer token.", error_code="missing_bearer")

    try:
        decoded = auth.verify_id_token(token, check_revoked=True)
    except Exception as exc:
        logger.warning("event=token_verify_failed err=%s", str(exc))
        raise HttpError(401, "Invalid bearer token.", error_code="invalid_bearer") from exc

    email = _normalize_email(str(decoded.get("email", "")))
    email_verified = bool(decoded.get("email_verified", False))
    uid = str(decoded.get("uid", ""))
    return email, email_verified, uid


def _require_verified_email_match(request: Request, requested_email: str) -> Tuple[str, str]:
    token_email, token_verified, token_uid = _principal_from_bearer(request)
    canonical = _normalize_email(requested_email)
    if not token_verified or not token_email:
        raise HttpError(403, "Verified email is required.", error_code="email_not_verified")
    if token_email != canonical:
        raise HttpError(403, "Token email does not match requested identity.", error_code="email_mismatch")
    return canonical, token_uid


def _require_hash_owner(request: Request, user_hash: str) -> str:
    _require_hash_b64(user_hash, "user")
    token_email, token_verified, _ = _principal_from_bearer(request)
    if not token_verified or not token_email:
        raise HttpError(403, "Verified email is required.", error_code="email_not_verified")
    expected = _hash_b64(token_email)
    if expected != user_hash:
        raise HttpError(
            403,
            "Sender/recipient hash does not match token identity.",
            error_code="hash_identity_mismatch",
        )
    return token_email


def _response(
    body: Dict[str, Any],
    status: int,
    request_id: str,
    extra_headers: Optional[Dict[str, str]] = None,
):
    headers = {REQUEST_ID_HEADER: request_id}
    if extra_headers:
        headers.update(extra_headers)
    return body, status, headers


def _ok(
    body: Dict[str, Any],
    status: int = 200,
    request_id: str = "",
    schema_version: int = DEFAULT_SCHEMA_VERSION,
    extra_headers: Optional[Dict[str, str]] = None,
):
    resolved_request_id = request_id or uuid.uuid4().hex
    response_body = dict(body)
    response_body.setdefault("request_id", resolved_request_id)
    response_body.setdefault("schema_version", schema_version)
    return _response(response_body, status, resolved_request_id, extra_headers=extra_headers)


def _default_error_code(status: int) -> str:
    mapping = {
        400: "invalid_argument",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        410: "deprecated_endpoint",
        413: "payload_too_large",
        429: "rate_limited",
    }
    return mapping.get(status, "internal_error")


def _error_response(error: Exception, request: Optional[Request], endpoint: str):
    request_id = uuid.uuid4().hex
    if request is not None:
        request_id = _request_id_from_request(request)

    if isinstance(error, HttpError):
        code = error.error_code or _default_error_code(error.status)
        body: Dict[str, Any] = {
            "error_code": code,
            "message": error.message,
            "request_id": request_id,
        }
        for key, value in error.details.items():
            if key not in body:
                body[key] = value
        logger.warning(
            "event=request_error endpoint=%s request_id=%s status=%s error_code=%s message=%s",
            endpoint,
            request_id,
            error.status,
            code,
            error.message,
        )
        return _response(body, error.status, request_id)

    logger.exception("event=unhandled_error endpoint=%s request_id=%s", endpoint, request_id)
    return _response(
        {
            "error_code": "internal_error",
            "message": "Internal server error.",
            "request_id": request_id,
        },
        500,
        request_id,
    )


def _rate_limit_actor_key(user_hash: str, request: Request) -> str:
    if user_hash:
        basis = f"user:{user_hash}"
    else:
        forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        remote_addr = getattr(request, "remote_addr", "") or ""
        basis = f"ip:{forwarded_for or remote_addr or 'unknown'}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


def _enforce_rate_limit(request: Request, endpoint_group: str, actor_key: str) -> None:
    limit = RATE_LIMITS_PER_WINDOW.get(endpoint_group)
    if not limit:
        return

    now_ts = int(datetime.now(timezone.utc).timestamp())
    window_start = now_ts - (now_ts % RATE_LIMIT_WINDOW_SECONDS)
    window_end = window_start + RATE_LIMIT_WINDOW_SECONDS

    key = f"{endpoint_group}:{actor_key}:{window_start}"
    ref = _db().collection(COLLECTION_RATE_LIMITS).document(_doc_id(key))
    snap = ref.get()

    current_count = 0
    if _snap_exists(snap):
        row = snap.to_dict() or {}
        try:
            current_count = int(row.get("count", 0))
        except (TypeError, ValueError):
            current_count = 0

    if current_count >= limit:
        retry_after = max(1, window_end - now_ts)
        raise HttpError(
            429,
            f"Rate limit exceeded. Retry after {retry_after} seconds.",
            error_code="rate_limited",
            details={"retry_after_seconds": retry_after},
        )

    write_payload = {
        "count": current_count + 1,
        "endpoint_group": endpoint_group,
        "actor_key": actor_key,
        "window_start": window_start,
        "updated_at": now_ts,
        "expires_at": window_end + (2 * RATE_LIMIT_WINDOW_SECONDS),
    }
    if _snap_exists(snap):
        ref.update(write_payload)
    else:
        ref.set(write_payload)


def _verify_scheduler_invoker(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HttpError(403, "Missing scheduler bearer token.", error_code="missing_scheduler_bearer")

    token = header[len("Bearer ") :].strip()
    if not token:
        raise HttpError(403, "Missing scheduler bearer token.", error_code="missing_scheduler_bearer")

    expected_audience = os.getenv("SCHEDULER_AUDIENCE", request.base_url or "").strip() or None
    try:
        claims = id_token.verify_oauth2_token(token, GoogleAuthRequest(), expected_audience)
    except Exception as exc:
        raise HttpError(403, "Invalid scheduler token.", error_code="invalid_scheduler_token") from exc

    email = _normalize_email(str(claims.get("email", "")))
    verified = bool(claims.get("email_verified", False))
    expected_email = _normalize_email(
        os.getenv("SCHEDULER_SERVICE_ACCOUNT_EMAIL", DEFAULT_SCHEDULER_SERVICE_ACCOUNT_EMAIL)
    )

    if not verified or email != expected_email:
        raise HttpError(403, "Unauthorized scheduler principal.", error_code="unauthorized_scheduler")
    return email


def _v2_register_identity(request: Request):
    request_id = _request_id_from_request(request)
    payload = _json(request)
    schema_version = _schema_version_from_payload(payload)

    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)

    pub_kex_b64 = _require_str(payload, "pub_kex_b64")
    pub_sign_b64 = _require_str(payload, "pub_sign_b64")
    client_ts = _require_int(payload, "client_ts")

    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise HttpError(400, "Missing or invalid field: proof", error_code="invalid_argument")
    verification_b64 = _require_hash_b64(_require_str(proof, "verification_b64"), "verification_b64")
    signature_b64 = _require_signature_b64(_require_str(proof, "signature_b64"), "signature_b64")

    user_hash = _hash_b64(canonical_email)
    canonical = ".".join(["register", user_hash, pub_kex_b64, pub_sign_b64, str(client_ts)])
    expected_verification = _hash_b64(canonical)

    if verification_b64 != expected_verification:
        raise HttpError(400, "Invalid verification digest.", error_code="digest_mismatch")

    if not _verify_ed25519_detached(verification_b64, signature_b64, pub_sign_b64):
        raise HttpError(401, "Invalid registration signature.", error_code="invalid_signature")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    ref = _db().collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash))
    snap = ref.get()
    if not _snap_exists(snap):
        ref.set(
            {
                "email": canonical_email,
                "user_hash": user_hash,
                "pub_kex_b64": pub_kex_b64,
                "pub_sign_b64": pub_sign_b64,
                "key_version": 1,
                "created_at": now_ts,
                "updated_at": now_ts,
                "schema_version": schema_version,
            }
        )
        return _ok({"status": "created"}, 201, request_id=request_id, schema_version=schema_version)

    row = snap.to_dict() or {}
    if row.get("pub_kex_b64") == pub_kex_b64 and row.get("pub_sign_b64") == pub_sign_b64:
        return _ok({"status": "already_registered"}, 200, request_id=request_id, schema_version=schema_version)

    raise HttpError(409, "Identity already bound to different keys. Use rotate.", error_code="identity_conflict")


def _v2_identity_challenge(request: Request):
    request_id = _request_id_from_request(request)
    payload = _json(request)
    schema_version = _schema_version_from_payload(payload)

    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)
    user_hash = _hash_b64(canonical_email)

    nonce = base64.b64encode(secrets.token_bytes(32)).decode("utf-8")
    now_ts = int(datetime.now(timezone.utc).timestamp())
    expires_at = now_ts + NONCE_TTL_SECONDS

    _db().collection(COLLECTION_IDENTITY_NONCES_V2).document(_doc_id(nonce)).set(
        {
            "nonce": nonce,
            "user_hash": user_hash,
            "created_at": now_ts,
            "expires_at": expires_at,
            "used": False,
            "schema_version": schema_version,
        }
    )
    return _ok({"nonce": nonce, "expires_at": expires_at}, 200, request_id=request_id, schema_version=schema_version)


def _v2_rotate_identity(request: Request):
    request_id = _request_id_from_request(request)
    payload = _json(request)
    schema_version = _schema_version_from_payload(payload)

    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)

    new_pub_kex_b64 = _require_str(payload, "new_pub_kex_b64")
    new_pub_sign_b64 = _require_str(payload, "new_pub_sign_b64")
    nonce = _require_str(payload, "nonce")
    old_key_signature_b64 = _require_signature_b64(_require_str(payload, "old_key_signature_b64"), "old_key_signature_b64")
    new_key_signature_b64 = _require_signature_b64(_require_str(payload, "new_key_signature_b64"), "new_key_signature_b64")
    client_ts = _require_int(payload, "client_ts")

    user_hash = _hash_b64(canonical_email)
    canonical = ".".join(["rotate", user_hash, new_pub_kex_b64, new_pub_sign_b64, nonce, str(client_ts)])
    verification_b64 = _hash_b64(canonical)

    identity_ref = _db().collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash))
    nonce_ref = _db().collection(COLLECTION_IDENTITY_NONCES_V2).document(_doc_id(nonce))
    identity_snap = identity_ref.get()
    nonce_snap = nonce_ref.get()

    if not _snap_exists(identity_snap):
        raise HttpError(404, "Identity not found.", error_code="identity_not_found")
    if not _snap_exists(nonce_snap):
        raise HttpError(409, "Nonce not found.", error_code="nonce_not_found")

    identity = identity_snap.to_dict() or {}
    nonce_row = nonce_snap.to_dict() or {}

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if nonce_row.get("user_hash") != user_hash:
        raise HttpError(403, "Nonce owner mismatch.", error_code="nonce_owner_mismatch")
    if bool(nonce_row.get("used", False)):
        raise HttpError(409, "Nonce already used.", error_code="nonce_already_used")
    if int(nonce_row.get("expires_at", 0)) < now_ts:
        raise HttpError(409, "Nonce expired.", error_code="nonce_expired")

    old_pub_sign_b64 = str(identity.get("pub_sign_b64", ""))
    if not _verify_ed25519_detached(verification_b64, old_key_signature_b64, old_pub_sign_b64):
        raise HttpError(401, "Old-key signature invalid.", error_code="invalid_signature")
    if not _verify_ed25519_detached(verification_b64, new_key_signature_b64, new_pub_sign_b64):
        raise HttpError(401, "New-key signature invalid.", error_code="invalid_signature")

    identity_ref.update(
        {
            "pub_kex_b64": new_pub_kex_b64,
            "pub_sign_b64": new_pub_sign_b64,
            "key_version": int(identity.get("key_version", 1)) + 1,
            "updated_at": now_ts,
            "schema_version": schema_version,
        }
    )
    nonce_ref.update({"used": True, "used_at": now_ts})

    return _ok({"ok": True}, 200, request_id=request_id, schema_version=schema_version)


def _v2_delete_identity(request: Request):
    request_id = _request_id_from_request(request)
    payload = _json(request)
    schema_version = _schema_version_from_payload(payload)

    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)
    client_ts = _require_int(payload, "client_ts")
    signature_b64 = _require_signature_b64(_require_str(payload, "signature_b64"), "signature_b64")

    user_hash = _hash_b64(canonical_email)
    ref = _db().collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash))
    snap = ref.get()
    if not _snap_exists(snap):
        raise HttpError(404, "Identity not found.", error_code="identity_not_found")

    row = snap.to_dict() or {}
    pub_sign_b64 = str(row.get("pub_sign_b64", ""))
    verification_b64 = _hash_b64(".".join(["delete", user_hash, str(client_ts)]))
    if not _verify_ed25519_detached(verification_b64, signature_b64, pub_sign_b64):
        raise HttpError(401, "Delete signature invalid.", error_code="invalid_signature")

    ref.delete()
    return _ok({"ok": True}, 200, request_id=request_id, schema_version=schema_version)


def _v2_get_pubkey(request: Request):
    request_id = _request_id_from_request(request)
    schema_version = _schema_version_from_query(request)

    # Read endpoint still requires a valid bearer to reduce scraping.
    _principal_from_bearer(request)
    user_hash = request.args.get("user_hash", "").strip()
    if not user_hash:
        raise HttpError(400, "Missing user_hash.", error_code="invalid_argument")
    user_hash = _require_hash_b64(user_hash, "user_hash")

    snap = _db().collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash)).get()
    if not _snap_exists(snap):
        raise HttpError(404, "Identity not found.", error_code="identity_not_found")

    row = snap.to_dict() or {}
    return _ok(
        {
            "user_hash": user_hash,
            "pub_kex_b64": row.get("pub_kex_b64", ""),
            "key_version": row.get("key_version", 1),
            "updated_at": row.get("updated_at", 0),
        },
        200,
        request_id=request_id,
        schema_version=schema_version,
    )


@https_fn.on_request()
def v2(request: Request):
    _request_id_from_request(request)
    try:
        path = request.path or "/"
        method = request.method.upper()

        if path == "/identity/register" and method == "POST":
            return _v2_register_identity(request)
        if path == "/identity/challenge" and method == "POST":
            return _v2_identity_challenge(request)
        if path == "/identity/rotate" and method == "POST":
            return _v2_rotate_identity(request)
        if path == "/identity/delete" and method == "POST":
            return _v2_delete_identity(request)
        if path == "/identity/pubkey" and method == "GET":
            return _v2_get_pubkey(request)

        raise HttpError(404, "Route not found.", error_code="route_not_found")
    except Exception as error:
        return _error_response(error, request, endpoint=f"v2:{request.path or '/'}")


@https_fn.on_request()
def ping(request: Request):
    _request_id_from_request(request)
    try:
        _require_method(request, "GET")
        return _ok({"status": True}, 200, request_id=_request_id_from_request(request))
    except Exception as error:
        return _error_response(error, request, endpoint="ping")


@https_fn.on_request()
def login_refresh_token(request: Request):
    _request_id_from_request(request)
    try:
        _require_method(request, "POST")
        payload = _json(request)
        schema_version = _schema_version_from_payload(payload)
        user_hash = _require_hash_b64(_require_str(payload, "user"), "user")
        _require_signature_b64(_require_str(payload, "signature"), "signature")

        email, verified, uid = _principal_from_bearer(request)
        if not verified:
            raise HttpError(403, "Verified email is required.", error_code="email_not_verified")
        if _hash_b64(email) != user_hash:
            raise HttpError(403, "User hash does not match token identity.", error_code="hash_identity_mismatch")

        custom_token = auth.create_custom_token(uid).decode("utf-8")
        return _ok(
            {"status": "login successful", "custom_token": custom_token, "user": user_hash},
            200,
            request_id=_request_id_from_request(request),
            schema_version=schema_version,
        )
    except Exception as error:
        return _error_response(error, request, endpoint="login_refresh_token")


@https_fn.on_request()
def get_pubkey(request: Request):
    # Legacy endpoint kept as alias of v2 read response shape.
    _request_id_from_request(request)
    try:
        _require_method(request, "GET")
        schema_version = _schema_version_from_query(request)
        _principal_from_bearer(request)
        user_hash = request.args.get("user", "").strip()
        if not user_hash:
            raise HttpError(400, "Missing user", error_code="invalid_argument")
        user_hash = _require_hash_b64(user_hash, "user")

        snap = _db().collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash)).get()
        if not _snap_exists(snap):
            raise HttpError(404, "Public key not found!", error_code="identity_not_found")

        row = snap.to_dict() or {}
        return _ok(
            {"pubkey": row.get("pub_kex_b64", "")},
            200,
            request_id=_request_id_from_request(request),
            schema_version=schema_version,
        )
    except Exception as error:
        return _error_response(error, request, endpoint="get_pubkey")


@https_fn.on_request()
def upload_user(request: Request):
    # Legacy endpoint intentionally retired to avoid unverified identity binding.
    _request_id_from_request(request)
    try:
        _require_method(request, "POST")
        raise HttpError(
            410,
            "Deprecated endpoint. Use /v2/identity/register.",
            error_code="deprecated_endpoint",
        )
    except Exception as error:
        return _error_response(error, request, endpoint="upload_user")


@https_fn.on_request()
def delete_user(request: Request):
    # Legacy endpoint intentionally retired to avoid weak signature flow.
    _request_id_from_request(request)
    try:
        _require_method(request, "POST")
        raise HttpError(
            410,
            "Deprecated endpoint. Use /v2/identity/delete.",
            error_code="deprecated_endpoint",
        )
    except Exception as error:
        return _error_response(error, request, endpoint="delete_user")


def _validate_sender_binding(request: Request, payload: Dict[str, Any]) -> str:
    user_hash = str(payload.get("user", "")).strip()
    if not user_hash:
        raise HttpError(400, "Missing user", error_code="invalid_argument")
    _require_hash_owner(request, user_hash)
    return user_hash


def _verify_payload_integrity(payload: Dict[str, Any], sender_pub_sign_b64: str) -> None:
    expected_digest = _canonical_payload_digest(payload)
    if payload["verification"] != expected_digest:
        raise HttpError(400, "Invalid payload digest.", error_code="payload_digest_mismatch")
    if not _verify_ed25519_detached(payload["verification"], payload["signature"], sender_pub_sign_b64):
        raise HttpError(401, "Invalid payload signature.", error_code="payload_signature_invalid")


def _store_payload_like(collection_name: str, request: Request, duplicate_message: str):
    _require_method(request, "POST")
    raw_payload = _json(request)
    schema_version = _schema_version_from_payload(raw_payload)
    payload = _normalize_payload_document(raw_payload)
    if not all(field in payload for field in REQUIRED_PAYLOAD_FIELDS):
        raise HttpError(400, "Missing required fields", error_code="invalid_argument")

    user_hash = _validate_sender_binding(request, payload)
    sender_identity = _get_identity(user_hash)
    if sender_identity is None:
        raise HttpError(403, "Unauthorized: sender identity not found", error_code="sender_identity_missing")

    _enforce_rate_limit(request, "upload", _rate_limit_actor_key(user_hash, request))
    _verify_payload_integrity(payload, str(sender_identity.get("pub_sign_b64", "")))

    collection = _db().collection(collection_name)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    docs = (
        collection.where(filter=FieldFilter("verification", "==", payload["verification"]))
        .where(filter=FieldFilter("expires_at", ">=", now_ts))
        .order_by("expires_at", direction=firestore.Query.DESCENDING)
        .limit(1)
        .get()
    )
    if docs:
        return _ok(
            {"status": duplicate_message},
            409,
            request_id=_request_id_from_request(request),
            schema_version=schema_version,
        )

    payload["server_received_at"] = now_ts
    payload["schema_version"] = schema_version
    doc = collection.document()
    doc.set(payload)
    logger.info(
        "event=store_payload endpoint=%s request_id=%s actor_hash=%s outcome_code=success",
        collection_name,
        _request_id_from_request(request),
        _rate_limit_actor_key(user_hash, request),
    )
    return _ok(
        {"status": "success", "doc_id": doc.id},
        200,
        request_id=_request_id_from_request(request),
        schema_version=schema_version,
    )


@https_fn.on_request()
def upload_payload(request: Request):
    _request_id_from_request(request)
    try:
        return _store_payload_like(
            COLLECTION_PAYLOADS,
            request,
            duplicate_message="A valid payload already exists",
        )
    except Exception as error:
        return _error_response(error, request, endpoint="upload_payload")


@https_fn.on_request()
def upload_request(request: Request):
    _request_id_from_request(request)
    try:
        return _store_payload_like(
            COLLECTION_REQUESTS,
            request,
            duplicate_message="A valid request-payload already exists",
        )
    except Exception as error:
        return _error_response(error, request, endpoint="upload_request")


def _fetch_by_recipient(collection_name: str, request: Request):
    _require_method(request, "GET")
    schema_version = _schema_version_from_query(request)

    user_hash = request.args.get("user", "").strip()
    if not user_hash:
        raise HttpError(400, "Missing user", error_code="invalid_argument")
    user_hash = _require_hash_b64(user_hash, "user")

    _require_hash_owner(request, user_hash)
    if not _identity_exists(user_hash):
        raise HttpError(403, "Unauthorized: recipient identity not found", error_code="recipient_identity_missing")

    _enforce_rate_limit(request, "fetch", _rate_limit_actor_key(user_hash, request))

    current_ts = int(datetime.now(timezone.utc).timestamp())
    fetch_limit = _safe_positive_limit(request)
    docs = (
        _db().collection(collection_name)
        .where(filter=FieldFilter("recipient", "==", user_hash))
        .where(filter=FieldFilter("expires_at", ">=", current_ts))
        .order_by("expires_at", direction=firestore.Query.DESCENDING)
        .limit(fetch_limit)
        .stream()
    )

    data_list: List[Dict[str, Any]] = []
    for doc in docs:
        doc_data = doc.to_dict() or {}
        doc_data["doc_id"] = doc.id
        if collection_name == COLLECTION_REQUESTS:
            doc_data["request_id"] = str(doc_data.get("verification", doc.id))
        data_list.append(doc_data)

    logger.info(
        "event=fetch endpoint=%s request_id=%s actor_hash=%s outcome_code=success count=%s",
        collection_name,
        _request_id_from_request(request),
        _rate_limit_actor_key(user_hash, request),
        len(data_list),
    )
    return _ok(
        {"payload": data_list},
        200,
        request_id=_request_id_from_request(request),
        schema_version=schema_version,
    )


@https_fn.on_request()
def fetch_payload(request: Request):
    _request_id_from_request(request)
    try:
        return _fetch_by_recipient(COLLECTION_PAYLOADS, request)
    except Exception as error:
        return _error_response(error, request, endpoint="fetch_payload")


@https_fn.on_request()
def fetch_request(request: Request):
    _request_id_from_request(request)
    try:
        return _fetch_by_recipient(COLLECTION_REQUESTS, request)
    except Exception as error:
        return _error_response(error, request, endpoint="fetch_request")


def _find_active_request(request_id_value: str) -> Tuple[str, Dict[str, Any]]:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    docs = (
        _db().collection(COLLECTION_REQUESTS)
        .where(filter=FieldFilter("verification", "==", request_id_value))
        .where(filter=FieldFilter("expires_at", ">=", now_ts))
        .order_by("expires_at", direction=firestore.Query.DESCENDING)
        .limit(1)
        .get()
    )
    if not docs:
        raise HttpError(404, "Request not found.", error_code="request_not_found")

    doc = docs[0]
    row = doc.to_dict() or {}
    return doc.id, row


def _normalize_decision(payload: Dict[str, Any]) -> str:
    decision = _require_str(payload, "decision").lower()
    if decision not in DECISION_VALUES:
        raise HttpError(400, "Invalid decision value.", error_code="invalid_decision")
    return decision


def _normalize_reason_code(payload: Dict[str, Any], decision: str) -> str:
    raw = str(payload.get("reason_code", "")).strip().lower()
    if not raw:
        return f"decision_{DECISION_VALUES[decision]}"

    sanitized = re.sub(r"[^a-z0-9_\\-]", "_", raw)
    if len(sanitized) > 64:
        raise HttpError(400, "reason_code is too long.", error_code="invalid_argument")
    return sanitized


def _handle_request_decision(request: Request, compatibility_route: bool):
    _require_method(request, "POST")
    payload = _json(request)
    schema_version = _schema_version_from_payload(payload)

    recipient_hash = _require_hash_b64(_require_str(payload, "recipient"), "recipient")
    request_id_value = _require_hash_b64(_require_str(payload, "request_id"), "request_id")
    decision = _normalize_decision(payload)
    reason_code = _normalize_reason_code(payload, decision)

    _require_hash_owner(request, recipient_hash)
    if not _identity_exists(recipient_hash):
        raise HttpError(403, "Unauthorized: recipient identity not found", error_code="recipient_identity_missing")

    _enforce_rate_limit(request, "decision", _rate_limit_actor_key(recipient_hash, request))

    source_doc_id, source_request = _find_active_request(request_id_value)
    if str(source_request.get("recipient", "")) != recipient_hash:
        raise HttpError(403, "Recipient does not own this request.", error_code="recipient_scope_violation")

    decision_doc_id = _hash_b64(f"{request_id_value}:{recipient_hash}")
    decision_ref = _db().collection(COLLECTION_REQUEST_DECISIONS).document(_doc_id(decision_doc_id))
    decision_snap = decision_ref.get()

    if _snap_exists(decision_snap):
        existing = decision_snap.to_dict() or {}
        existing_decision = str(existing.get("decision", ""))
        if existing_decision == decision:
            headers = None
            if compatibility_route:
                headers = {
                    "X-Compatibility-Endpoint": "payload_decision",
                    "X-Deprecation-Date": DECISION_COMPAT_DEPRECATION_DATE,
                }
            return _ok(
                {
                    "status": "already_processed",
                    "reason_code": str(existing.get("reason_code", reason_code)),
                    "decision_id": str(existing.get("decision_id", "")),
                    "request_id": request_id_value,
                },
                200,
                request_id=_request_id_from_request(request),
                schema_version=schema_version,
                extra_headers=headers,
            )

        raise HttpError(
            409,
            "Decision already finalized for this request.",
            error_code="decision_conflict",
            details={
                "decision_id": str(existing.get("decision_id", "")),
                "request_id": request_id_value,
            },
        )

    now_ts = int(datetime.now(timezone.utc).timestamp())
    decision_id = _hash_b64(f"{request_id_value}:{recipient_hash}:{decision}")
    expires_at = int(source_request.get("expires_at", now_ts + MAX_DOCUMENT_TTL_SECONDS))
    decision_ref.set(
        {
            "request_id": request_id_value,
            "request_doc_id": source_doc_id,
            "recipient": recipient_hash,
            "decision": decision,
            "reason_code": reason_code,
            "decision_id": decision_id,
            "created_at": now_ts,
            "expires_at": expires_at,
            "schema_version": schema_version,
        }
    )

    headers = None
    if compatibility_route:
        headers = {
            "X-Compatibility-Endpoint": "payload_decision",
            "X-Deprecation-Date": DECISION_COMPAT_DEPRECATION_DATE,
        }

    logger.info(
        "event=request_decision endpoint=%s request_id=%s actor_hash=%s outcome_code=processed",
        "payload_decision" if compatibility_route else "request_decision",
        _request_id_from_request(request),
        _rate_limit_actor_key(recipient_hash, request),
    )
    return _ok(
        {
            "status": "processed",
            "reason_code": reason_code,
            "decision_id": decision_id,
            "request_id": request_id_value,
        },
        200,
        request_id=_request_id_from_request(request),
        schema_version=schema_version,
        extra_headers=headers,
    )


@https_fn.on_request()
def request_decision(request: Request):
    _request_id_from_request(request)
    try:
        return _handle_request_decision(request, compatibility_route=False)
    except Exception as error:
        return _error_response(error, request, endpoint="request_decision")


@https_fn.on_request()
def payload_decision(request: Request):
    _request_id_from_request(request)
    try:
        return _handle_request_decision(request, compatibility_route=True)
    except Exception as error:
        return _error_response(error, request, endpoint="payload_decision")


@https_fn.on_request()
def clean_expired_docs(request: Request):
    _request_id_from_request(request)
    try:
        _require_method(request, "GET")
        scheduler_email = _verify_scheduler_invoker(request)
        logger.info(
            "event=cleanup_start endpoint=clean_expired_docs request_id=%s actor_hash=%s",
            _request_id_from_request(request),
            _rate_limit_actor_key(scheduler_email, request),
        )
        now_ts = int(datetime.now(timezone.utc).timestamp())

        total_deleted = 0
        for collection_name in [
            COLLECTION_PAYLOADS,
            COLLECTION_REQUESTS,
            COLLECTION_IDENTITY_NONCES_V2,
            COLLECTION_REQUEST_DECISIONS,
            COLLECTION_RATE_LIMITS,
        ]:
            expired_query = _db().collection(collection_name).where(filter=FieldFilter("expires_at", "<=", now_ts))
            batch = _db().batch()
            count = 0
            for doc in expired_query.stream():
                batch.delete(doc.reference)
                count += 1
                total_deleted += 1
                if count % MAX_BATCH_SIZE == 0:
                    batch.commit()
                    batch = _db().batch()
            if count % MAX_BATCH_SIZE != 0:
                batch.commit()

        logger.info(
            "event=cleanup_done endpoint=clean_expired_docs request_id=%s deleted=%s",
            _request_id_from_request(request),
            total_deleted,
        )
        return _ok({"deleted": total_deleted}, 200, request_id=_request_id_from_request(request))
    except Exception as error:
        return _error_response(error, request, endpoint="clean_expired_docs")
