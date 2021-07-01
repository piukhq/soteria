import requests
import json
from hashids import Hashids

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import HttpResponseError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
)

from soteria.reporting import get_logger
from soteria.requests_retry import requests_retry_session

hash_ids = Hashids(min_length=32, salt='GJgCh--VgsonCWacO5-MxAuMS9hcPeGGxj5tGsT40FM')
logger = get_logger("soteria")


class ConfigurationException(Exception):
    pass


def generate_record_uid(scheme_account_id):
    return hash_ids.encode(scheme_account_id)


def decode_record_uid(record_uid):
    return hash_ids.decode(record_uid)[0]


class Configuration:
    """
    Configuration for merchant API integration. Requires merchant id and handler type to retrieve
    configurations.
    Config parameters:
    - scheme_slug: merchant slug.
    - handler_type: join, update.
    - merchant_url: url of merchant endpoint.
    - callback_url: Endpoint url for merchant to call for response (Async processes only)
    - integration_service: sync or async process.
    - security_credentials: credentials required for dealing with security e.g public/private keys.
    - retry_limit: number of times to retry on failed request.
    - log_level: level of logging to record e.g DEBUG for all, WARNING for warning logs and above.
    """
    UPDATE_HANDLER = 0
    JOIN_HANDLER = 1
    VALIDATE_HANDLER = 2
    TRANSACTION_MATCHING = 3
    CHECK_MEMBERSHIP_HANDLER = 4
    TRANSACTION_HISTORY_HANDLER = 5

    HANDLER_TYPE_CHOICES = (
        (UPDATE_HANDLER, "Update"),
        (JOIN_HANDLER, "Join"),
        (VALIDATE_HANDLER, "Validate"),
        (TRANSACTION_MATCHING, "Transaction Matching"),
        (CHECK_MEMBERSHIP_HANDLER, "Check Membership"),
        (TRANSACTION_HISTORY_HANDLER, "Transaction History"),
    )

    SYNC_INTEGRATION = 0
    ASYNC_INTEGRATION = 1

    INTEGRATION_CHOICES = (
        (SYNC_INTEGRATION, "Sync"),
        (ASYNC_INTEGRATION, "Async"),
    )

    RSA_SECURITY = 0
    OPEN_AUTH_SECURITY = 1
    OAUTH_SECURITY = 2

    SECURITY_TYPE_CHOICES = (
        (RSA_SECURITY, "RSA"),
        (OPEN_AUTH_SECURITY, "Open Auth (No Authentication)"),
        (OAUTH_SECURITY, "OAuth"),
    )

    DEBUG_LOG_LEVEL = 0
    INFO_LOG_LEVEL = 1
    WARNING_LOG_LEVEL = 2
    ERROR_LOG_LEVEL = 3
    CRITICAL_LOG_LEVEL = 4

    LOG_LEVEL_CHOICES = (
        (DEBUG_LOG_LEVEL, "Debug"),
        (INFO_LOG_LEVEL, "Info"),
        (WARNING_LOG_LEVEL, "Warning"),
        (ERROR_LOG_LEVEL, "Error"),
        (CRITICAL_LOG_LEVEL, "Critical")
    )

    HTTP_ERROR_MESSAGE = "Failed to connect to configuration service."
    PARSE_ERROR_MESSAGE = "Failed to parse configuration service response."
    SECURITY_ERROR_MESSAGE = "Error retrieving security credentials for this request."
    UNKNOWN_ERROR = "An unexpected problem has occurred obtaining secrets, please investigate"

    def __init__(self, scheme_slug, handler_type, vault_url, vault_token, config_service_url):
        """
        :param scheme_slug: merchant identifier.
        :param handler_type: Int. A choice from Configuration.HANDLER_TYPE_CHOICES.
        """
        self.scheme_slug = scheme_slug
        self.handler_type = (handler_type, self.handler_type_as_str(handler_type))
        self.vault_url = vault_url
        self.vault_token = vault_token
        self.session = requests_retry_session()

        self.data = self._get_config_data(config_service_url)
        self._process_config_data()
        logger.debug('retrieved configuration for {}. scheme slug: {}'.format(self.handler_type, scheme_slug))

    @classmethod
    def handler_type_as_str(cls, handler_type: int) -> str:
        return cls.HANDLER_TYPE_CHOICES[handler_type][1].upper()

    def _get_config_data(self, config_service_url):
        params = {
            'merchant_id': self.scheme_slug,
            'handler_type': self.handler_type[0]
        }

        try:
            get_config_service_url = config_service_url + '/configuration'
            resp = self.session.get(get_config_service_url, params=params)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise ConfigurationException(self.HTTP_ERROR_MESSAGE) from e

        return resp.json()

    def _process_config_data(self):
        try:
            self.merchant_url = self.data['merchant_url']
            self.integration_service = self.INTEGRATION_CHOICES[self.data['integration_service']][1].upper()
            self.retry_limit = self.data['retry_limit']
            self.log_level = self.LOG_LEVEL_CHOICES[self.data['log_level']][1].upper()
            self.callback_url = self.data['callback_url']
            self.country = self.data['country']

            self.security_credentials = self.data['security_credentials']
            inbound_data = self.security_credentials['inbound']['credentials']
            outbound_data = self.security_credentials['outbound']['credentials']

            self.security_credentials['inbound']['credentials'] = self.get_security_credentials(inbound_data)
            self.security_credentials['outbound']['credentials'] = self.get_security_credentials(outbound_data)
        except KeyError as ex:
            raise ConfigurationException(self.PARSE_ERROR_MESSAGE) from ex

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=3, max=12),
        reraise=True,
    )
    def get_security_credentials(self, key_items):
        """
        Retrieves security credential values from key storage vault.
        :param key_items: list of dicts {'type': e.g 'bink_public_key', 'storage_key': auto-generated hash from helios}
        :return: key_items: returns same list of dict with added 'value' keys containing actual credential values.
        """
        kv_credential = DefaultAzureCredential(
            exclude_environment_credential=True,
            exclude_shared_token_cache_credential=True,
            exclude_visual_studio_code_credential=True,
            exclude_interactive_browser_credential=True,
        )
        client = SecretClient(vault_url=self.vault_url, credential=kv_credential)
        try:
            for key_item in key_items:
                stored_value = json.loads(client.get_secret(key_item["storage_key"]).value)
                stored_dict = stored_value['data']

                # Stores the value mapped to the 'value' key of the stored data.
                # If this doesn't exist, i.e for compound keys, the full mapping is stored as the value.
                value = stored_dict.get('value')
                key_item.update(value=value or stored_dict)
        except (TypeError, KeyError, ValueError) as e:
            raise ConfigurationException(self.SECURITY_ERROR_MESSAGE) from e
        except HttpResponseError as e:
            raise ConfigurationException(self.HTTP_ERROR_MESSAGE) from e
        except Exception as e:
            raise ConfigurationException(self.UNKNOWN_ERROR) from e

        return key_items
