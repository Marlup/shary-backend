import base64
import hashlib
import logging
import os
import secrets
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from firebase_admin import auth, credentials, firestore, initialize_app
from firebase_functions import https_fn, options
from flask import Request
from google.cloud.firestore_v1.base_query import FieldFilter
from google.oauth2 import id_token
from google.auth.transport.requests import Request as GoogleAuthRequest

from constants import (
    COLLECTION_PAYLOADS,
    COLLECTION_REQUESTS,
    REQUIRED_PAYLOAD_FIELDS,
    MAX_DOCUMENT_TTL_SECONDS,
    MAX_CLOCK_SKEW_SECONDS,
    DEFAULT_FETCH_LIMIT,
    MAX_FETCH_LIMIT,
    MAX_DATA_B64_LENGTH,
    MAX_SIGNATURE_B64_LENGTH,
    MAX_VERIFICATION_B64_LENGTH,
    DEFAULT_SCHEDULER_SERVICE_ACCOUNT_EMAIL,
)


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

FUNCTIONS_REGION = os.getenv("FUNCTIONS_REGION", "europe-southwest1")
options.set_global_options(region=FUNCTIONS_REGION)


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

db = firestore.client()


COLLECTION_IDENTITIES_V2 = "identities_v2"
COLLECTION_IDENTITY_NONCES_V2 = "identity_rotate_nonces_v2"
NONCE_TTL_SECONDS = 5 * 60
MAX_BATCH_SIZE = 500


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _doc_id(value: str) -> str:
    # Firestore document IDs cannot contain "/".
    # Percent-escape to keep a deterministic reversible mapping.
    return value.replace("%", "%25").replace("/", "%2F")


def _json(request: Request) -> Dict[str, Any]:
    content_length = request.content_length or 0
    if content_length > (MAX_DATA_B64_LENGTH + 8192):
        raise HttpError(413, "Request body too large.")

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise HttpError(400, "Invalid JSON body.")
    return payload


def _require_str(payload: Dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise HttpError(400, f"Missing or invalid field: {field}")
    return value.strip()


def _require_int(payload: Dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool):
        raise HttpError(400, f"Missing or invalid field: {field}")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise HttpError(400, f"Missing or invalid field: {field}")


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _hash_b64(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("utf-8")


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("utf-8"))


def _require_method(request: Request, method: str) -> None:
    if request.method.upper() != method:
        raise HttpError(405, f"Method not allowed. Use {method}.")


def _is_sha256_hash_b64(value: str) -> bool:
    try:
        raw = base64.b64decode(value.encode("utf-8"), validate=True)
        return len(raw) == 32
    except Exception:
        return False


def _require_hash_b64(value: str, field_name: str) -> str:
    if not _is_sha256_hash_b64(value):
        raise HttpError(400, f"Invalid hash format for field: {field_name}")
    return value


def _safe_positive_limit(request: Request) -> int:
    raw = (request.args.get("limit", "") or "").strip()
    if not raw:
        return DEFAULT_FETCH_LIMIT
    if not raw.isdigit():
        raise HttpError(400, "Invalid limit.")
    parsed = int(raw)
    if parsed <= 0:
        raise HttpError(400, "Invalid limit.")
    return min(parsed, MAX_FETCH_LIMIT)


def _normalize_payload_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    user_hash = _require_hash_b64(_require_str(payload, "user"), "user")
    recipient_hash = _require_hash_b64(_require_str(payload, "recipient"), "recipient")
    data = _require_str(payload, "data")
    verification = _require_str(payload, "verification")
    signature = _require_str(payload, "signature")
    creation_at = _require_int(payload, "creation_at")
    expires_at = _require_int(payload, "expires_at")

    if len(data) > MAX_DATA_B64_LENGTH:
        raise HttpError(400, "Payload data is too large.")
    if len(signature) > MAX_SIGNATURE_B64_LENGTH:
        raise HttpError(400, "Payload signature is too large.")
    if len(verification) > MAX_VERIFICATION_B64_LENGTH:
        raise HttpError(400, "Payload verification is too large.")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if creation_at > (now_ts + MAX_CLOCK_SKEW_SECONDS):
        raise HttpError(400, "creation_at is too far in the future.")
    if expires_at <= now_ts:
        raise HttpError(400, "expires_at must be in the future.")
    if expires_at <= creation_at:
        raise HttpError(400, "expires_at must be greater than creation_at.")
    if (expires_at - creation_at) > MAX_DOCUMENT_TTL_SECONDS:
        raise HttpError(400, "Document TTL exceeds allowed maximum.")

    return {
        "user": user_hash,
        "recipient": recipient_hash,
        "creation_at": creation_at,
        "expires_at": expires_at,
        "data": data,
        "verification": verification,
        "signature": signature,
    }


def _identity_exists(user_hash: str) -> bool:
    snap = db.collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash)).get()
    if not snap.exists:
        return False
    row = snap.to_dict() or {}
    return str(row.get("user_hash", "")) == user_hash


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
        raise HttpError(401, "Missing bearer token.")

    token = header[len("Bearer "):].strip()
    if not token:
        raise HttpError(401, "Missing bearer token.")

    try:
        decoded = auth.verify_id_token(token, check_revoked=True)
    except Exception as e:
        logger.warning("token_verify_failed err=%s", str(e))
        raise HttpError(401, "Invalid bearer token.")

    email = _normalize_email(str(decoded.get("email", "")))
    email_verified = bool(decoded.get("email_verified", False))
    uid = str(decoded.get("uid", ""))
    return email, email_verified, uid


def _require_verified_email_match(request: Request, requested_email: str) -> Tuple[str, str]:
    token_email, token_verified, token_uid = _principal_from_bearer(request)
    canonical = _normalize_email(requested_email)
    if not token_verified or not token_email:
        raise HttpError(403, "Verified email is required.")
    if token_email != canonical:
        raise HttpError(403, "Token email does not match requested identity.")
    return canonical, token_uid


def _require_hash_owner(request: Request, user_hash: str) -> str:
    _require_hash_b64(user_hash, "user")
    token_email, token_verified, _ = _principal_from_bearer(request)
    if not token_verified or not token_email:
        raise HttpError(403, "Verified email is required.")
    expected = _hash_b64(token_email)
    if expected != user_hash:
        raise HttpError(403, "Sender/recipient hash does not match token identity.")
    return token_email


def _ok(body: Dict[str, Any], status: int = 200):
    return body, status


def _error_response(error: Exception):
    if isinstance(error, HttpError):
        logger.warning("request_error status=%s msg=%s", error.status, error.message)
        return {"error": error.message}, error.status
    logger.exception("unhandled_error")
    return {"error": "Internal server error."}, 500


def _verify_scheduler_invoker(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HttpError(403, "Missing scheduler bearer token.")

    token = header[len("Bearer "):].strip()
    if not token:
        raise HttpError(403, "Missing scheduler bearer token.")

    expected_audience = os.getenv("SCHEDULER_AUDIENCE", request.base_url or "").strip() or None
    try:
        claims = id_token.verify_oauth2_token(token, GoogleAuthRequest(), expected_audience)
    except Exception:
        raise HttpError(403, "Invalid scheduler token.")

    email = _normalize_email(str(claims.get("email", "")))
    verified = bool(claims.get("email_verified", False))
    expected_email = _normalize_email(
        os.getenv("SCHEDULER_SERVICE_ACCOUNT_EMAIL", DEFAULT_SCHEDULER_SERVICE_ACCOUNT_EMAIL)
    )

    if not verified or email != expected_email:
        raise HttpError(403, "Unauthorized scheduler principal.")
    return email


def _v2_register_identity(request: Request):
    payload = _json(request)
    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)

    pub_kex_b64 = _require_str(payload, "pub_kex_b64")
    pub_sign_b64 = _require_str(payload, "pub_sign_b64")
    client_ts = _require_int(payload, "client_ts")

    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise HttpError(400, "Missing or invalid field: proof")
    verification_b64 = _require_str(proof, "verification_b64")
    signature_b64 = _require_str(proof, "signature_b64")

    user_hash = _hash_b64(canonical_email)
    canonical = ".".join(["register", user_hash, pub_kex_b64, pub_sign_b64, str(client_ts)])
    expected_verification = _hash_b64(canonical)

    if verification_b64 != expected_verification:
        raise HttpError(400, "Invalid verification digest.")

    if not _verify_ed25519_detached(verification_b64, signature_b64, pub_sign_b64):
        raise HttpError(401, "Invalid registration signature.")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    ref = db.collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash))
    snap = ref.get()
    if not snap.exists:
        ref.set({
            "email": canonical_email,
            "user_hash": user_hash,
            "pub_kex_b64": pub_kex_b64,
            "pub_sign_b64": pub_sign_b64,
            "key_version": 1,
            "created_at": now_ts,
            "updated_at": now_ts,
        })
        return _ok({"status": "created"}, 201)

    row = snap.to_dict() or {}
    if row.get("pub_kex_b64") == pub_kex_b64 and row.get("pub_sign_b64") == pub_sign_b64:
        return _ok({"status": "already_registered"}, 200)

    raise HttpError(409, "Identity already bound to different keys. Use rotate.")


def _v2_identity_challenge(request: Request):
    payload = _json(request)
    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)
    user_hash = _hash_b64(canonical_email)

    nonce = base64.b64encode(secrets.token_bytes(32)).decode("utf-8")
    now_ts = int(datetime.now(timezone.utc).timestamp())
    expires_at = now_ts + NONCE_TTL_SECONDS

    db.collection(COLLECTION_IDENTITY_NONCES_V2).document(_doc_id(nonce)).set({
        "nonce": nonce,
        "user_hash": user_hash,
        "created_at": now_ts,
        "expires_at": expires_at,
        "used": False,
    })
    return _ok({"nonce": nonce, "expires_at": expires_at}, 200)


def _v2_rotate_identity(request: Request):
    payload = _json(request)
    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)

    new_pub_kex_b64 = _require_str(payload, "new_pub_kex_b64")
    new_pub_sign_b64 = _require_str(payload, "new_pub_sign_b64")
    nonce = _require_str(payload, "nonce")
    old_key_signature_b64 = _require_str(payload, "old_key_signature_b64")
    new_key_signature_b64 = _require_str(payload, "new_key_signature_b64")
    client_ts = _require_int(payload, "client_ts")

    user_hash = _hash_b64(canonical_email)
    canonical = ".".join(
        ["rotate", user_hash, new_pub_kex_b64, new_pub_sign_b64, nonce, str(client_ts)]
    )
    verification_b64 = _hash_b64(canonical)

    identity_ref = db.collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash))
    nonce_ref = db.collection(COLLECTION_IDENTITY_NONCES_V2).document(_doc_id(nonce))
    identity_snap = identity_ref.get()
    nonce_snap = nonce_ref.get()

    if not identity_snap.exists:
        raise HttpError(404, "Identity not found.")
    if not nonce_snap.exists:
        raise HttpError(409, "Nonce not found.")

    identity = identity_snap.to_dict() or {}
    nonce_row = nonce_snap.to_dict() or {}

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if nonce_row.get("user_hash") != user_hash:
        raise HttpError(403, "Nonce owner mismatch.")
    if bool(nonce_row.get("used", False)):
        raise HttpError(409, "Nonce already used.")
    if int(nonce_row.get("expires_at", 0)) < now_ts:
        raise HttpError(409, "Nonce expired.")

    old_pub_sign_b64 = str(identity.get("pub_sign_b64", ""))
    if not _verify_ed25519_detached(verification_b64, old_key_signature_b64, old_pub_sign_b64):
        raise HttpError(401, "Old-key signature invalid.")
    if not _verify_ed25519_detached(verification_b64, new_key_signature_b64, new_pub_sign_b64):
        raise HttpError(401, "New-key signature invalid.")

    identity_ref.update({
        "pub_kex_b64": new_pub_kex_b64,
        "pub_sign_b64": new_pub_sign_b64,
        "key_version": int(identity.get("key_version", 1)) + 1,
        "updated_at": now_ts,
    })
    nonce_ref.update({"used": True, "used_at": now_ts})

    return _ok({"ok": True}, 200)


def _v2_delete_identity(request: Request):
    payload = _json(request)
    email = _require_str(payload, "email")
    canonical_email, _ = _require_verified_email_match(request, email)
    client_ts = _require_int(payload, "client_ts")
    signature_b64 = _require_str(payload, "signature_b64")

    user_hash = _hash_b64(canonical_email)
    ref = db.collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash))
    snap = ref.get()
    if not snap.exists:
        raise HttpError(404, "Identity not found.")

    row = snap.to_dict() or {}
    pub_sign_b64 = str(row.get("pub_sign_b64", ""))
    verification_b64 = _hash_b64(".".join(["delete", user_hash, str(client_ts)]))
    if not _verify_ed25519_detached(verification_b64, signature_b64, pub_sign_b64):
        raise HttpError(401, "Delete signature invalid.")

    ref.delete()
    return _ok({"ok": True}, 200)


def _v2_get_pubkey(request: Request):
    # Read endpoint still requires a valid bearer to reduce scraping.
    _principal_from_bearer(request)
    user_hash = request.args.get("user_hash", "").strip()
    if not user_hash:
        raise HttpError(400, "Missing user_hash.")
    user_hash = _require_hash_b64(user_hash, "user_hash")

    snap = db.collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash)).get()
    if not snap.exists:
        raise HttpError(404, "Identity not found.")

    row = snap.to_dict() or {}
    return _ok(
        {
            "user_hash": user_hash,
            "pub_kex_b64": row.get("pub_kex_b64", ""),
            "key_version": row.get("key_version", 1),
            "updated_at": row.get("updated_at", 0),
        },
        200,
    )


@https_fn.on_request()
def v2(request: Request):
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

        raise HttpError(404, "Route not found.")
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def ping(request: Request):
    try:
        _require_method(request, "GET")
        return _ok({"status": True}, 200)
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def login_refresh_token(request: Request):
    try:
        _require_method(request, "POST")
        payload = _json(request)
        user_hash = _require_hash_b64(_require_str(payload, "user"), "user")
        signature = str(payload.get("signature", "")).strip()
        if len(signature) > MAX_SIGNATURE_B64_LENGTH:
            raise HttpError(400, "Signature is too large.")

        email, verified, uid = _principal_from_bearer(request)
        if not verified:
            raise HttpError(403, "Verified email is required.")
        if _hash_b64(email) != user_hash:
            raise HttpError(403, "User hash does not match token identity.")

        custom_token = auth.create_custom_token(uid).decode("utf-8")
        return _ok({"status": "login successful", "custom_token": custom_token, "user": user_hash}, 200)
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def get_pubkey(request: Request):
    # Legacy endpoint kept as alias of v2 read response shape.
    try:
        _require_method(request, "GET")
        _principal_from_bearer(request)
        user_hash = request.args.get("user", "").strip()
        if not user_hash:
            raise HttpError(400, "Missing user")
        user_hash = _require_hash_b64(user_hash, "user")

        snap = db.collection(COLLECTION_IDENTITIES_V2).document(_doc_id(user_hash)).get()
        if not snap.exists:
            raise HttpError(404, "Public key not found!")

        row = snap.to_dict() or {}
        return _ok({"pubkey": row.get("pub_kex_b64", "")}, 200)
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def upload_user(request: Request):
    # Legacy endpoint intentionally retired to avoid unverified identity binding.
    try:
        _require_method(request, "POST")
        return _ok({"error": "Deprecated endpoint. Use /v2/identity/register."}, 410)
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def delete_user(request: Request):
    # Legacy endpoint intentionally retired to avoid weak signature flow.
    try:
        _require_method(request, "POST")
        return _ok({"error": "Deprecated endpoint. Use /v2/identity/delete."}, 410)
    except Exception as error:
        return _error_response(error)


def _validate_sender_binding(request: Request, payload: Dict[str, Any]) -> str:
    user_hash = str(payload.get("user", "")).strip()
    if not user_hash:
        raise HttpError(400, "Missing user")
    _require_hash_owner(request, user_hash)
    return user_hash


def _store_payload_like(collection_name: str, request: Request, duplicate_message: str):
    _require_method(request, "POST")
    payload = _normalize_payload_document(_json(request))
    if not all(field in payload for field in REQUIRED_PAYLOAD_FIELDS):
        raise HttpError(400, "Missing required fields")

    user_hash = _validate_sender_binding(request, payload)
    if not _identity_exists(user_hash):
        raise HttpError(403, "Unauthorized: sender identity not found")

    collection = db.collection(collection_name)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    docs = (
        collection
        .where(filter=FieldFilter("verification", "==", payload["verification"]))
        .where(filter=FieldFilter("expires_at", ">=", now_ts))
        .order_by("expires_at", direction=firestore.Query.DESCENDING)
        .limit(1)
        .get()
    )
    if docs:
        return _ok({"status": duplicate_message}, 409)

    payload["server_received_at"] = now_ts
    doc = collection.document()
    doc.set(payload)
    return _ok({"status": "success", "doc_id": doc.id}, 200)


@https_fn.on_request()
def upload_payload(request: Request):
    try:
        return _store_payload_like(
            COLLECTION_PAYLOADS,
            request,
            duplicate_message="A valid payload already exists",
        )
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def upload_request(request: Request):
    try:
        return _store_payload_like(
            COLLECTION_REQUESTS,
            request,
            duplicate_message="A valid request-payload already exists",
        )
    except Exception as error:
        return _error_response(error)


def _fetch_by_recipient(collection_name: str, request: Request):
    _require_method(request, "GET")
    user_hash = request.args.get("user", "").strip()
    if not user_hash:
        raise HttpError(400, "Missing user")
    user_hash = _require_hash_b64(user_hash, "user")

    _require_hash_owner(request, user_hash)
    if not _identity_exists(user_hash):
        raise HttpError(403, "Unauthorized: recipient identity not found")

    current_ts = int(datetime.now(timezone.utc).timestamp())
    fetch_limit = _safe_positive_limit(request)
    docs = (
        db.collection(collection_name)
        .where(filter=FieldFilter("recipient", "==", user_hash))
        .where(filter=FieldFilter("expires_at", ">=", current_ts))
        .order_by("expires_at", direction=firestore.Query.DESCENDING)
        .limit(fetch_limit)
        .stream()
    )

    data_list: List[Dict[str, Any]] = []
    for doc in docs:
        doc_data = doc.to_dict() or {}
        data_list.append(doc_data)
    return _ok({"payload": data_list}, 200)


@https_fn.on_request()
def fetch_payload(request: Request):
    try:
        return _fetch_by_recipient(COLLECTION_PAYLOADS, request)
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def fetch_request(request: Request):
    try:
        return _fetch_by_recipient(COLLECTION_REQUESTS, request)
    except Exception as error:
        return _error_response(error)


@https_fn.on_request()
def clean_expired_docs(request: Request):
    try:
        _require_method(request, "GET")
        scheduler_email = _verify_scheduler_invoker(request)
        logger.info("clean_expired_docs: Starting cleanup invoker=%s", scheduler_email)
        now_ts = int(datetime.now(timezone.utc).timestamp())

        total_deleted = 0
        for collection_name in [COLLECTION_PAYLOADS, COLLECTION_REQUESTS, COLLECTION_IDENTITY_NONCES_V2]:
            expired_query = db.collection(collection_name).where(
                filter=FieldFilter("expires_at", "<=", now_ts)
            )
            batch = db.batch()
            count = 0
            for doc in expired_query.stream():
                batch.delete(doc.reference)
                count += 1
                total_deleted += 1
                if count % MAX_BATCH_SIZE == 0:
                    batch.commit()
                    batch = db.batch()
            if count % MAX_BATCH_SIZE != 0:
                batch.commit()

        logger.info("clean_expired_docs: Deleted %d expired document(s)", total_deleted)
        return _ok({"deleted": total_deleted}, 200)
    except Exception as error:
        return _error_response(error)

