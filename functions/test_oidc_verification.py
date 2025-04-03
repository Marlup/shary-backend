import os
import pytest
from unittest import mock
from flask import Request
from main import verify_oidc_token

class FakeRequest:
    headers = {"Authorization": "Bearer fake.token"}

@mock.patch("google.oauth2.id_token.verify_oauth2_token")
def test_get_email_from_oidc_mocked(mock_verify_token):
    mock_verify_token.return_value = {
        "email": "test-scheduler@shary-21b61.iam.gserviceaccount.com"
    }

    email = verify_oidc_token(FakeRequest(), expected_audience="https://test-url")
    assert email == "test-scheduler@shary-21b61.iam.gserviceaccount.com"
