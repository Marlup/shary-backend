import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import firebase_admin
from firebase_functions import firestore_fn, https_fn
from firebase_admin import credentials, firestore

# Initialize Firebase
#cred = credentials.Certificate("shary-21b61-firebase-adminsdk-fbsvc-3f26b2aa68.json")
#firebase_admin.initialize_app(cred)
#db = firestore.client()

os.environ["FIRESTORE_EMULATOR_HOST"] = "localhost:9090"  # Adjust if using a different port

# Check if running in Firebase Emulator mode
if os.getenv("FIRESTORE_EMULATOR_HOST"):
    print("🔥 Running with Firestore Emulator")

firebase_admin.initialize_app()
db = firestore.client()

COLLECTION_NAME = "sharing"

def hash_username(username: str) -> str:
    # Convert to bytes
    username_bytes = username.encode('utf-8')

    # Choose a hash function: SHA-256 is a good default
    hash_object = hashlib.sha256(username_bytes)

    # Get the hex digest
    return hash_object.hexdigest()

@https_fn.on_request()
def write_data_from_user(request: https_fn.Request):
    """Stores encrypted data from User A for User B."""
    data = request.json
    mode = data.get("mode")

    if not mode:
        return https_fn.Response("Missing 'mode' parameter", status=400)
    
    from_user = data.get("from_user") # hashed from client
    if not from_user:
        return https_fn.Response("Missing 'from_user' parameter", status=400)
    
    to_user = data.get("to_user") # hashed from client
    if not to_user:
        return https_fn.Response("Missing 'to_user' parameter", status=400)
    
    fields = data.get("fields")
    if not fields:
        return https_fn.Response("Missing 'fields' parameter", status=400)
    
    _, doc_ref = db.collection(COLLECTION_NAME) \
                   .document(from_user) \
                   .set(
                       {
                           "mode": mode,
                           "from_user": from_user, #
                           "to_user": to_user,
                           "fields": fields
                       }, 
                       merge=True)

    return https_fn.Response(f"Message with ID {doc_ref.id} added.")

@https_fn.on_request()
def send_data_to_user(request: https_fn.Request) -> https_fn.Response:
    """Retrieves stored data."""
    from_user = request.args.get("from_user") # hashed from client
    if not from_user:
        return https_fn.Response("Missing 'from_user' parameter", status=400)
    
    to_user = request.args.get("to_user") # hashed from client
    if not to_user:
        return https_fn.Response("Missing 'to_user' parameter", status=400)

    #db: google.cloud.firestore.Client = firestore.client()

    from_user_doc = db.collection(COLLECTION_NAME) \
                      .document(from_user) \
                      .get()
    if not from_user_doc.exists:
        return https_fn.Response("No data found", status=404)

    data = from_user_doc.to_dict()
    if data["mode"] != "fb-to-user" or "fields" not in data:
        return https_fn.Response("Incomplete data", status=400)

    fields = data["fields"]

    return https_fn.Response(
        json.dumps(
            {"from_user": from_user, "fields": fields}
            ), 
        mimetype="application/json"
        )
