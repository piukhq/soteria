from unittest import TestCase, mock

from soteria.agents import open_auth
from soteria.configuration import Configuration
from soteria.security import get_security_agent, authorise, SecurityException
from tests.unit import fixtures


class TestSecurity(TestCase):
    def test_get_security_agent(self):
        security_agent = get_security_agent(Configuration.OPEN_AUTH_SECURITY)

        self.assertIsInstance(security_agent, open_auth.OpenAuth)

    @mock.patch('soteria.security.getattr')
    def test_get_security_agent_not_found(self, mock_getattr):
        mock_getattr.side_effect = AttributeError('Attribute not found')

        with self.assertRaises(SecurityException) as e:
            get_security_agent(Configuration.OPEN_AUTH_SECURITY)
        self.assertEqual(str(e.exception), 'Could not find security class: OpenAuth.')

    @mock.patch('soteria.configuration.hvac.Client')
    @mock.patch('soteria.configuration.requests_retry_session')
    def test_authorise(self, mock_requests_retry_session, mock_vault):
        mock_config = fixtures.MOCK_CONFIG_JSON
        mock_config['security_credentials'] = {
            "inbound": {
                "service": Configuration.OPEN_AUTH_SECURITY,
                "credentials": []
            },
            "outbound": {
                "service": Configuration.OPEN_AUTH_SECURITY,
                "credentials": []
            }
        }
        mock_requests_retry_session.return_value.get.return_value.status_code = 200
        mock_requests_retry_session.return_value.get.return_value.json.return_value = mock_config
        mock_vault.read.return_value = fixtures.MOCK_VAULT_RESPONSE

        @authorise(Configuration.JOIN_HANDLER, fixtures.MockRequest, 'vault_url', 'vault_token', 'config_url')
        def accept_request(scheme_slug, data, config):
            return data, scheme_slug, config

        data, scheme_slug, config = accept_request(scheme_slug='test-scheme-slug')

        self.assertEqual(data, {"message": "success"})
        self.assertEqual(scheme_slug, 'test-scheme-slug')
        self.assertIsInstance(config, Configuration)
        self.assertEqual(config.handler_type[0], Configuration.JOIN_HANDLER)
