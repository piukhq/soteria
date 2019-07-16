import hvac
import requests
from hashids import Hashids

hash_ids = Hashids(min_length=32, salt='GJgCh--VgsonCWacO5-MxAuMS9hcPeGGxj5tGsT40FM')


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
    TRANSACTION_MATCHING_HANDLER = 3
    CHECK_MEMBERSHIP_HANDLER = 4
    TRANSACTION_HISTORY_HANDLER = 5

    HANDLER_TYPE_CHOICES = (
        (UPDATE_HANDLER, "Update"),
        (JOIN_HANDLER, "Join"),
        (VALIDATE_HANDLER, "Validate"),
        (TRANSACTION_MATCHING_HANDLER, "Transaction Matching"),
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

    ERROR_MESSAGE = "There is an error with the configuration or it was not possible to retrieve."
    SECURITY_ERROR_MESSAGE = "Error retrieving security credentials for this request."

    def __init__(self, scheme_slug, handler_type, vault_url, vault_token, config_service_url):
        """
        :param scheme_slug: merchant identifier.
        :param handler_type: Int. A choice from Configuration.HANDLER_TYPE_CHOICES.
        """
        self.scheme_slug = scheme_slug
        self.handler_type = (handler_type, self.HANDLER_TYPE_CHOICES[handler_type][1].upper())
        self.vault_url = vault_url
        self.vault_token = vault_token

        self.data = self._get_config_data(config_service_url)
        self._process_config_data()

    def _get_config_data(self, config_service_url):
        params = {
            'merchant_id': self.scheme_slug,
            'handler_type': self.handler_type[0]
        }

        try:
            get_config_service_url = config_service_url + '/configuration'
            resp = requests.get(get_config_service_url, params=params)
            resp.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
            raise ConfigurationException(self.ERROR_MESSAGE) from e

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
        except KeyError as e:
            raise ConfigurationException(self.ERROR_MESSAGE) from e

        try:
            self.security_credentials['inbound']['credentials'] = self.get_security_credentials(inbound_data)
            self.security_credentials['outbound']['credentials'] = self.get_security_credentials(outbound_data)
        except (TypeError, KeyError) as e:
            raise ConfigurationException(self.SECURITY_ERROR_MESSAGE) from e

    def get_security_credentials(self, key_items):
        """
        Retrieves security credential values from key storage vault.
        :param key_items: list of dicts {'type': e.g 'bink_public_key', 'storage_key': auto-generated hash from helios}
        :return: key_items: returns same list of dict with added 'value' keys containing actual credential values.
        """
        client = hvac.Client(token=self.vault_token, url=self.vault_url)
        try:
            for key_item in key_items:
                stored_dict = client.read(
                    'secret/data/{}'.format(key_item["storage_key"])
                )['data']['data']

                # Stores the value mapped to the 'value' key of the stored data.
                # If this doesn't exist, i.e for compound keys, the full mapping is stored as the value.
                value = stored_dict.get('value')
                key_item.update(value=value or stored_dict)
        except TypeError as e:
            raise ConfigurationException(self.SECURITY_ERROR_MESSAGE) from e

        return key_items
