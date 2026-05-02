from unittest import mock


class Req:
    def __init__(self, method="GET", headers=None, args=None, json_body=None, base_url="https://example.com/cleanup"):
        self.method = method
        self.headers = headers or {}
        self.args = args or {}
        self._json_body = json_body
        self.base_url = base_url
        self.content_length = None
        self.path = "/clean_expired_docs"

    def get_json(self, silent=True):
        return self._json_body


def test_clean_expired_docs_rejects_missing_scheduler_bearer(main_module):
    response, status, _ = main_module.clean_expired_docs(Req(method="GET", headers={}))
    assert status == 403
    assert response["error_code"] == "missing_scheduler_bearer"
    assert response["message"] == "Missing scheduler bearer token."


def test_clean_expired_docs_accepts_valid_scheduler_oidc(main_module):
    main_module.id_token.verify_oauth2_token.return_value = {
        "email": "scheduler@example.iam.gserviceaccount.com",
        "email_verified": True,
    }

    fake_doc = mock.Mock()
    fake_doc.reference = "payloads/abc"

    where_mock = main_module.db.collection.return_value.where.return_value
    where_mock.stream.return_value = [fake_doc]

    batch_mock = mock.Mock()
    main_module.db.batch.return_value = batch_mock

    response, status, _ = main_module.clean_expired_docs(
        Req(
            method="GET",
            headers={"Authorization": "Bearer fake.scheduler.jwt"},
            base_url="https://example.com/cleanup",
        )
    )

    assert status == 200
    assert response["deleted"] == 5
    assert batch_mock.delete.call_count == 5
    assert batch_mock.commit.call_count == 5
