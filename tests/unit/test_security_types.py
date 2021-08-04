import json
import time

from unittest import TestCase, mock

import requests

from soteria.agents import base, oauth, open_auth, rsa
from soteria.configuration import Configuration, ConfigurationException
from soteria.security import SecurityException
from tests.unit import fixtures


class TestBase(TestCase):
    def setUp(self):
        self.test_credentials = fixtures.TEST_CREDENTIALS
        self.base_security = base.BaseSecurity(credentials=self.test_credentials)

    def test_base_security_init(self):
        self.assertEqual(self.base_security.credentials, self.test_credentials)
        with self.assertRaises(NotImplementedError):
            self.base_security.encode()
        with self.assertRaises(NotImplementedError):
            self.base_security.decode()

    def test_base_add_timestamp(self):
        timestamp_str, current_time = self.base_security._add_timestamp("")
        timestamp = int(timestamp_str)

        self.assertTrue(timestamp > 0)
        self.assertEqual(int(timestamp), int(current_time))

    def test_base_validate_timestamp(self):
        current_timestamp = time.time()

        self.assertIsNone(self.base_security._validate_timestamp(current_timestamp))

    def test_base_validate_timestamp_failed(self):
        timestamp_one_hour_ago = int(time.time()) - 3600

        with self.assertRaises(SecurityException) as e:
            self.base_security._validate_timestamp(timestamp_one_hour_ago)
        self.assertTrue(str(e.exception), base.BaseSecurity.VALIDATION_ERROR_MESSAGE)

    def test_base_get_key(self):
        credentials = [
            {"storage_key": "abc", "value": fixtures.TEST_PRIVATE_KEY, "credential_type": "bink_private_key"},
            {"storage_key": "def", "value": fixtures.TEST_PUBLIC_KEY, "credential_type": "merchant_public_key"},
        ]
        key_type = "bink_private_key"
        key = self.base_security._get_key(key_type, credentials)

        self.assertTrue(key, fixtures.TEST_PRIVATE_KEY)

    def test_base_get_key_failed(self):
        credentials = [
            {"storage_key": "def", "value": fixtures.TEST_PUBLIC_KEY, "credential_type": "merchant_public_key"}
        ]
        key_type = "bink_private_key"

        with self.assertRaises(ConfigurationException):
            self.base_security._get_key(key_type, credentials)


class TestOAuth(TestCase):
    def setUp(self):
        self.oauth = oauth.OAuth(credentials=fixtures.TEST_CREDENTIALS)

    def test_oauth_encode(self):
        with mock.patch.object(self.oauth, "session") as mock_session:
            test_oauth_access_token = "test-oauth-access-token"
            mock_session.post.return_value.json.return_value = {"access_token": test_oauth_access_token}

            encoded_request = self.oauth.encode(json.dumps(fixtures.TEST_REQUEST_DATA))
            auth_header = encoded_request["headers"]["Authorization"]
            self.assertTrue(auth_header.endswith(test_oauth_access_token))
            self.assertEqual(encoded_request["json"], fixtures.TEST_REQUEST_DATA)

    def test_oauth_encode_failed_connection(self):
        with mock.patch.object(self.oauth, "session") as mock_session:
            mock_session.post.side_effect = requests.RequestException("test requests exception")

            with self.assertRaises(SecurityException) as e:
                self.oauth.encode(json.dumps(fixtures.TEST_REQUEST_DATA))
            self.assertTrue(
                str(e.exception).startswith(
                    "Failed request to get oauth token from test_oauth_url. Exception: test requests exception"
                )
            )

    def test_oauth_encode_bad_credentials(self):
        bad_credentials = {"outbound": {"service": 0, "credentials": []}, "inbound": {"service": 0, "credentials": []}}
        bad_oauth = oauth.OAuth(credentials=bad_credentials)
        test_oauth_access_token = "test-oauth-access-token"
        with mock.patch.object(self.oauth, "session") as mock_session:
            mock_session.post.return_value.json.return_value = {"access_token": test_oauth_access_token}

            with self.assertRaises(SecurityException) as e:
                bad_oauth.encode(json.dumps(fixtures.TEST_REQUEST_DATA))
            self.assertEqual(str(e.exception), Configuration.SECURITY_ERROR_MESSAGE)


class TestOpenAuth(TestCase):
    def setUp(self):
        self.open_auth = open_auth.OpenAuth(credentials=fixtures.TEST_CREDENTIALS)

    def test_open_auth_encode(self):
        encoded_request = self.open_auth.encode(json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(encoded_request["json"], fixtures.TEST_REQUEST_DATA)

    def test_open_auth_decode(self):
        decoded_request = self.open_auth.decode({}, fixtures.TEST_REQUEST_DATA)
        self.assertEqual(decoded_request, fixtures.TEST_REQUEST_DATA)

    def test_open_auth_decode_no_data(self):
        decoded_request = self.open_auth.decode({}, None)
        self.assertEqual(decoded_request, "{}")


class TestRSA(TestCase):
    def setUp(self):
        self.rsa = rsa.RSA(credentials=fixtures.TEST_CREDENTIALS)
        self.encoded_request = self.rsa.encode(json.dumps(fixtures.TEST_REQUEST_DATA))

    def test_rsa_encode(self):
        self.assertTrue(self.encoded_request["headers"].get("Authorization"))
        self.assertTrue(self.encoded_request["headers"].get("X-REQ-TIMESTAMP"))
        self.assertEqual(self.encoded_request["json"], fixtures.TEST_REQUEST_DATA)

    def test_rsa_decode(self):
        headers = self.encoded_request["headers"]
        decoded_request = self.rsa.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))

        self.assertEqual(decoded_request, json.dumps(fixtures.TEST_REQUEST_DATA))

    def test_rsa_decode_wrong_headers(self):
        headers = {"X-REQ-TIMESTAMP": int(time.time())}

        with self.assertRaises(SecurityException) as e:
            self.rsa.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(str(e.exception), base.BaseSecurity.VALIDATION_ERROR_MESSAGE)

    def test_rsa_decode_no_signature_in_header(self):
        headers = {"X-REQ-TIMESTAMP": int(time.time()), "Authorization": "token abc"}

        with self.assertRaises(SecurityException) as e:
            self.rsa.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(str(e.exception), base.BaseSecurity.VALIDATION_ERROR_MESSAGE)

    def test_rsa_decode_no_public_key(self):
        headers = self.encoded_request["headers"]
        rsa_agent = rsa.RSA(credentials=fixtures.EMPTY_CREDENTIALS)

        with self.assertRaises(ConfigurationException) as e:
            rsa_agent.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(str(e.exception), Configuration.SECURITY_ERROR_MESSAGE)

    def test_rsa_decode_verify_fail(self):
        headers = {"X-REQ-TIMESTAMP": int(time.time()), "Authorization": fixtures.TEST_BAD_SIGNATURE}

        with self.assertRaises(SecurityException) as e:
            self.rsa.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(str(e.exception), base.BaseSecurity.VALIDATION_ERROR_MESSAGE)

    def test_rsa_decode_invalid_timestamp(self):
        headers = {"X-REQ-TIMESTAMP": "abc", "Authorization": fixtures.TEST_AUTHORIZATION_SIGNATURE}

        with self.assertRaises(SecurityException) as e:
            self.rsa.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(str(e.exception), base.BaseSecurity.VALIDATION_ERROR_MESSAGE)

    def test_rsa_decode_invalid_authorization(self):
        headers = {"X-REQ-TIMESTAMP": int(time.time()), "Authorization": "abc"}

        with self.assertRaises(SecurityException) as e:
            self.rsa.decode(headers, json.dumps(fixtures.TEST_REQUEST_DATA))
        self.assertEqual(str(e.exception), base.BaseSecurity.VALIDATION_ERROR_MESSAGE)
