import os
import hashlib
from functools import wraps

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from flask import request, Request, abort
import firebase_admin
from firebase_functions import firestore_fn, https_fn
from firebase_admin import credentials, firestore

# functions/create_user.py
from jwt_manager import JWTManager
from crypto import verify
from constants import PATH_CRED_FIREBASE_PROJECT, REQUIRED_FIELDS, RESPONSE_SECRET_KEY

#cred = credentials.ApplicationDefault()
cred = credentials.Certificate(PATH_CRED_FIREBASE_PROJECT)
firebase_admin.initialize_app(cred)
db = firestore.client()

os.environ["FIRESTORE_EMULATOR_HOST"] = "localhost:9090"  # Adjust if using a different port

# Check if running in Firebase Emulator mode
if os.getenv("FIRESTORE_EMULATOR_HOST"):
    print("🔥 Running with Firestore Emulator")

COLLECTION_SHARING_NAME = "sharing"
COLLECTION_PUBKEYS_NAME = "pubkeys"

# ENV: This should match your Cloud Scheduler --oidc-service-account-email
ALLOWED_SERVICE_ACCOUNT = os.environ.get("ALLOWED_SERVICE_ACCOUNT")

def hash_username(username: str) -> str:
    # Convert to bytes
    username_bytes = username.encode('utf-8')

    # Choose a hash function: SHA-256 is a good default
    hash_object = hashlib.sha256(username_bytes)

    # Get the hex digest
    return hash_object.hexdigest()

@https_fn.on_request()
def protected_action(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return {"error": "Missing or invalid Authorization header"}, 401

    token = auth.replace("Bearer ", "")
    try:
        claims = JWTManager.decode_token(token, RESPONSE_SECRET_KEY)
        owner = claims["sub"]
        # Now you can use `owner` to fetch data securely
        return {"status": "Access granted", "user": owner}, 200
    except ValueError as err:
        return {"error": str(err)}, 401

def require_jwt(func):
    @wraps(func)
    def wrapper(request: Request, *args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return {"error": "Missing or invalid Authorization header"}, 401

        token = auth.replace("Bearer ", "").strip()
        print(f"require_jwt - token: {token}")
        try:
            print(f"require_jwt - before")
            claims = JWTManager.decode_token(token, RESPONSE_SECRET_KEY)
            print(f"require_jwt - {claims}")
            owner = claims.get("sub")
            if not owner:
                return {"error": "Invalid token: no owner found"}, 401
            # Inject owner into the endpoint
            return func(request, *args, **kwargs)
        except Exception as e:
            return {"error": str(e)}, 401

    return wrapper

@https_fn.on_request()
def login_refresh_token(request: Request):
    try:
        payload = request.get_json()
        owner = payload.get("owner")
        signature = payload.get("signature")

        if not owner:
            return {"error": "Missing owner"}, 400
        if not signature:
            return {"error": "Missing signature"}, 400

        # Get the stored pubkey
        docs = db.collection(COLLECTION_PUBKEYS_NAME) \
                 .where("owner", "==", owner) \
                 .limit(1) \
                 .get()

        if not docs:
            return {"error": "User not found"}, 404

        doc = docs[0]
        pubkey = doc.to_dict()["pubkey"]

        # Verify user identity
        if not verify(signature, owner.encode("utf-8"), pubkey):
            return {"error": "Verification failed"}, 403

        token = JWTManager.create_token(
            owner=owner,
            secret_key=RESPONSE_SECRET_KEY,
            additional_claims={"pubkey": pubkey}
            )

        return {"status": "login successful", "token": token, "user": owner}, 200

    except Exception as e:
        return {"error": str(e)}, 500

#@functions_framework.http
@https_fn.on_request()
def get_pubkey(request):
    owner = request.args.get("owner", None)
    if not owner:
        return {"error": "Missing owner"}, 400
    try:
        doc = _get_doc_pubkey(owner)
        if not doc:
            return {"error": "Public key not found"}, 404
        
        pubkey = doc.to_dict()["pubkey"]
        return {"pubkey": pubkey}, 200
    
    except Exception as e:
        return {"error": str(e)}, 500

def _get_doc_pubkey(owner, return_first=True):
    docs = db.collection(COLLECTION_PUBKEYS_NAME) \
            .where("owner", "==", owner) \
            .get()
    if not docs:
        return None
    return docs[0] if return_first else docs

@https_fn.on_request()
def ping(_):
    return {"status": True}, 200

#@functions_framework.http
@https_fn.on_request()
def store_user(request):
    try:
        payload = request.get_json()
        owner = payload.get("owner")
        print(f"store_user - {owner}")
        pubkey = payload.get("pubkey")
        
        # Validate request payload
        if not owner:
            return {"error": "Missing owner"}, 400
        if not pubkey:
            return {"error": "Missing pubkey"}, 400

        collection = db.collection(COLLECTION_PUBKEYS_NAME)
        docs = collection.where("owner", "==", owner) \
                         .limit(1) \
                         .get()
        if docs:
            # User already exists
            return {"warning": "User credentials now allowed"}, 409
        
        new_doc = collection.document()
        new_doc.set(payload)

        # Create the JWT token
        token = JWTManager.create_token(
            owner=owner, 
            secret_key=RESPONSE_SECRET_KEY,
            additional_claims={"pubkey": pubkey}
            )

        return {"status": "public key stored",
                "doc_id": new_doc.id, 
                "token": token
               }, 200

    except Exception as e:
        return {"error": str(e)}, 500

#@functions_framework.http
@https_fn.on_request()
@require_jwt
def delete_user(request):
    try:
        payload = request.get_json()
        owner = payload.get("owner")
        signature = payload.get("signature")

        # Validate request payload
        if not owner:
            return {"error": "Missing owner"}, 400
        if not signature:
            return {"error": "Missing signature"}, 400

        doc = _get_doc_pubkey(owner)
        if not doc:
            return {"error": "Public key not found"}, 404
        
        pubkey = doc.to_dict()["pubkey"]

        owner_verified = verify(signature, owner.encode("utf-8"), pubkey)
        if owner_verified:
            # Clean up the document
            doc_id = doc.id
            doc.delete()
            return {"status": "Document deleted", "doc_id": doc_id}, 200
        else:
            return {"error": "Owner verification failed"}, 403
    
    except Exception as e:
        return {"error": str(e)}, 500

#@functions_framework.http
@https_fn.on_request()
@require_jwt
def store_payload(request):
    """
    HTTP endpoint to receive encrypted data and store it in Firestore.
    Expects a JSON payload, encrypted data, etc.
    """
    try:
        data = request.get_json()
        
        if not all(field in data for field in REQUIRED_FIELDS):
            return {"error": "Missing required fields"}, 400

        collection = db.collection(COLLECTION_SHARING_NAME)
        docs = collection.where("verification", "==", data["verification"]).get()

        if not docs:
            payload = {
                "owner": data["owner"],
                "consumer": data["consumer"],
                "creation_at": data["creation_at"],
                "expires_at": data["expires_at"],
                "data": data["data"],
                "verification": data["verification"],
                "signature": data["signature"]
            }
            doc = collection.document()
            doc.set(payload)
            return {"status": "success", "doc_id": doc.id}, 200
        
        existing_doc = docs[0]
        stored_payload = existing_doc.to_dict()
        if stored_payload.get("verification") == data["verification"]:
            return {"status": "The data already exists"}, 409

    except Exception as e:
        return {"error": str(e)}, 500

# Helper to verify OIDC token
def verify_oidc_token(request: str, expected_audience: str = None):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        abort(401, "Missing or invalid Authorization header")
    
    token = auth_header.split(" ")[1]
    request_adapter = google_requests.Request()

    try:
        # Validate OIDC token and extract payload
        idinfo = id_token.verify_oauth2_token(
            token,
            request_adapter,
            audience=expected_audience
            )
        email = idinfo.get("email")

        if ALLOWED_SERVICE_ACCOUNT and email != ALLOWED_SERVICE_ACCOUNT:
            abort(403, f"Unauthorized service account: {email}")

        return email
    except Exception as e:
        print(f"Token validation error: {e}")
        abort(403, "Invalid OIDC token")

@https_fn.on_request()
def clean_expired_docs(request: Request):
    # Optional: secure the function
    verify_oidc_token(request)
    
    expired_query = db.collection("sharing") \
                      .where("expires_at", "<=", firestore.SERVER_TIMESTAMP)

    expired_docs = expired_query.stream()
    batch = db.batch()
    deleted_count = 0

    for doc in expired_docs:
        batch.delete(doc.reference)
        deleted_count += 1

    if deleted_count > 0:
        batch.commit()

    return f"Deleted {deleted_count} expired document(s)", 200