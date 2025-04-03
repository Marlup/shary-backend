import pytest
from unittest import mock
from flask import Request
from main import clean_expired_docs

class FakeRequest:
    headers = {"Authorization": "Bearer fake.token"}

@mock.patch("main.verify_oidc_token")
@mock.patch("main.db")
def test_clean_expired_docs(mock_db, mock_verify_token):
    mock_verify_token.return_value = "test-scheduler@shary-21b61.iam.gserviceaccount.com"

    # Mock Firestore behavior
    fake_doc = mock.Mock()
    fake_doc.reference = "fake/doc/ref"
    mock_db.collection.return_value.where.return_value.stream.return_value = [fake_doc]
    mock_batch = mock.Mock()
    mock_db.batch.return_value = mock_batch

    # Execute function
    response = clean_expired_docs(FakeRequest())

    # Assertions
    assert response[1] == 200
    mock_batch.delete.assert_called_with("fake/doc/ref")
    mock_batch.commit.assert_called_once()
