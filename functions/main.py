import os
import json
import base64
import hashlib
import datetime

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from flask import request, Request, abort
import firebase_admin
from firebase_functions import firestore_fn, https_fn
from firebase_admin import credentials, firestore
import functions_framework

from constants import PATH_CRED_FIREBASE_PROJECT

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

#@functions_framework.http
@https_fn.on_request()
def get_pubkey(request):
    try:
        doc_id = request.args.get("doc_id", None)
        if not doc_id:
            return {"error": "Missing doc_id"}, 400

        doc = db.collection(COLLECTION_PUBKEYS_NAME) \
                    .document()
        if not doc.exists:
            return {"error": "Public key not found"}, 404

        pub_key = doc.get().to_dict()["pub_key"]
        doc.delete()
        return {"pub_key": pub_key}, 200

    except Exception as e:
        return {"error": str(e)}, 500

#@functions_framework.http
@https_fn.on_request()
def upload_pubkey(request):
    try:
        payload = request.get_json()
        doc_id = payload.get("doc_id")
        pub_key = payload.get("pub_key")

        if not doc_id:
            return {"error": "Missing doc_id"}, 400

        if not pub_key:
            return {"error": "Missing pub_key"}, 400

        collection = db.collection(COLLECTION_SHARING_NAME)
        docs = collection.where("doc_id", "==", doc_id) \
                         .get()
        if docs:
            return {"conflict": "Public key already exists"}, 409
        
        new_doc = collection.document()
        new_doc.set(payload)
        return {"status": "public key stored", "doc_id": new_doc.id}, 200

    except Exception as e:
        return {"error": str(e)}, 500

#@functions_framework.http
@https_fn.on_request()
def store_payload(request):
    """
    HTTP endpoint to receive encrypted data and store it in Firestore.
    Expects a JSON payload with mode, encrypted data, etc.
    """
    try:
        data = request.get_json()

        required_fields = ["mode", "owner", "consumers", "creation_at", 
                           "expires_at", "data", "verification_hash", "signature",
                          ]
        if not all(field in data for field in required_fields):
            return {"error": "Missing required fields"}, 400

        payload = {
            "mode": data["mode"],
            "owner": data["owner"],
            "consumers": data["consumers"],
            "creation_at": data["creation_at"],
            "expires_at": data["expires_at"],
            "data": data["data"],
            "verification_hash": data["verification_hash"],
            "signature": data["signature"],
        }

        # Optional: validate sender token using Firebase Auth here
        collection = db.collection(COLLECTION_SHARING_NAME)
        docs = collection.where("verification_hash", "==", data["verification_hash"]).get()

        if not docs:
            doc = collection.document()
            doc.set(payload)
            return {"status": "success", "doc_id": doc.id}, 200
        
        existing_doc = docs[0]
        stored_payload = existing_doc.to_dict()
        if stored_payload.get("verification_hash") == data["verification_hash"]:
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