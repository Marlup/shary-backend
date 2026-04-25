REQUIRED_PAYLOAD_FIELDS = [
    "user",
    "recipient",
    "creation_at",
    "expires_at",
    "data",
    "verification",
    "signature",
]
COLLECTION_PAYLOADS = "payloads"
COLLECTION_REQUESTS = "requests"

MAX_DOCUMENT_TTL_SECONDS = 60 * 60 * 24 * 30
MAX_CLOCK_SKEW_SECONDS = 5 * 60
MAX_FETCH_LIMIT = 200
DEFAULT_FETCH_LIMIT = 100
MAX_DATA_B64_LENGTH = 128 * 1024
MAX_SIGNATURE_B64_LENGTH = 1024
MAX_VERIFICATION_B64_LENGTH = 512

DEFAULT_SCHEDULER_SERVICE_ACCOUNT_EMAIL = "expiration-cleanup-scheduler@shary-21b61.iam.gserviceaccount.com"
