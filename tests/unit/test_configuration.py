from unittest import TestCase, mock

import requests

from soteria.configuration import Configuration, ConfigurationException, hash_ids, generate_record_uid, \
    decode_record_uid
from tests.unit import fixtures


class TestConfiguration(TestCase):
    def test_generate_record_uid(self):
        record_uid = generate_record_uid(135)
        decoded_uid = hash_ids.decode(record_uid)[0]
        self.assertEqual(decoded_uid, 135)

    def test_decode_record_uid(self):
        record_uid = 'Kp82DR7Yd5gewMA8OdN9xzyXGqEJ3bPV'
        decoded_uid = decode_record_uid(record_uid)
        self.assertEqual(decoded_uid, 531)

    @mock.patch.object(Configuration, "get_security_credentials")
    @mock.patch('soteria.configuration.requests_retry_session')
    def test_configuration_init(self, mock_requests_retry_session, mock_get_security_credentials):
        mock_requests_retry_session.return_value.get.return_value.status_code = 200
        mock_requests_retry_session.return_value.get.return_value.json.return_value = fixtures.MOCK_CONFIG_JSON
        mock_get_security_credentials.return_value = fixtures.MOCK_VAULT_RESPONSE

        config = Configuration(*fixtures.CONFIG_CLASS_ARGS)
        self.assertEqual(config.scheme_slug, fixtures.MOCK_CONFIG_JSON['merchant_id'])
        self.assertEqual(config.handler_type[0], fixtures.MOCK_CONFIG_JSON['handler_type'])
        self.assertEqual(config.security_credentials, fixtures.MOCK_CONFIG_JSON['security_credentials'])

    @mock.patch.object(Configuration, "get_security_credentials")
    @mock.patch('soteria.configuration.requests_retry_session')
    def test_configuration_init_requests_exception_from_config_service(self, mock_requests_retry_session, mock_get_security_credentials):
        mock_requests_retry_session.return_value.get.return_value.status_code = 404
        mock_requests_retry_session.return_value.get.return_value.json.return_value = {'error': 'Not found'}
        mock_requests_retry_session.return_value.get.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError('Not found')
        )
        mock_get_security_credentials.return_value = fixtures.MOCK_VAULT_RESPONSE

        with self.assertRaises(ConfigurationException) as e:
            Configuration(*fixtures.CONFIG_CLASS_ARGS)
        self.assertEqual(str(e.exception), Configuration.HTTP_ERROR_MESSAGE)

    @mock.patch.object(Configuration, "get_security_credentials")
    @mock.patch('soteria.configuration.requests_retry_session')
    def test_configuration_init_bad_config_from_service(self, mock_requests_retry_session, mock_get_security_credentials):
        mock_requests_retry_session.return_value.get.return_value.status_code = 200
        mock_requests_retry_session.return_value.get.return_value.json.return_value = {'error': 'Not found'}
        mock_get_security_credentials.return_value = fixtures.MOCK_VAULT_RESPONSE

        with self.assertRaises(ConfigurationException) as e:
            Configuration(*fixtures.CONFIG_CLASS_ARGS)
        self.assertEqual(str(e.exception), Configuration.PARSE_ERROR_MESSAGE)

    @mock.patch("azure.keyvault.secrets.SecretClient")
    @mock.patch('soteria.configuration.requests_retry_session')
    def test_configuration_init_vault_fail(self, mock_requests_retry_session, mock_secret_client):
        mock_requests_retry_session.return_value.get.return_value.status_code = 200
        mock_requests_retry_session.return_value.get.return_value.json.return_value = fixtures.MOCK_CONFIG_JSON
        mock_secret_client.return_value.get_secret.return_value = {}

        with self.assertRaises(ConfigurationException) as e:
            Configuration(*fixtures.CONFIG_CLASS_ARGS)
        self.assertEqual(str(e.exception), Configuration.SECURITY_ERROR_MESSAGE)
