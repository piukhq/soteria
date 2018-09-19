import time

from soteria.configuration import ConfigurationException, Configuration
from soteria.security import SecurityException


class BaseSecurity:
    time_limit = 120
    VALIDATION_ERROR_MESSAGE = 'Validation of the request has failed.'
    SERVICE_CONNECTION_ERROR = 'There was in issue connecting to an external service.'

    def __init__(self, credentials=None):
        """
        :param credentials: list if dicts e.g
        [{'type': 'bink_private_key', 'storage_key': 'vaultkey', 'value': 'keyvalue'}]
        """
        self.credentials = credentials

    def encode(self, *args, **kwargs):
        """
        :return: dict of parameters to be unpacked for requests.post()
        """
        raise NotImplementedError()

    def decode(self, *args, **kwargs):
        """
        :return: json string of payload
        """
        raise NotImplementedError()

    def _validate_timestamp(self, timestamp):
        current_time = time.time()
        if (current_time - int(timestamp)) > self.time_limit:
            raise SecurityException(self.VALIDATION_ERROR_MESSAGE)

    @staticmethod
    def _add_timestamp(json_data):
        """Appends a timestamp to a json string."""
        current_time = int(time.time())
        json_with_timestamp = '{}{}'.format(json_data, current_time)
        return json_with_timestamp, current_time

    @staticmethod
    def _get_key(key_type, credentials_list):
        for item in credentials_list:
            if item['credential_type'] == key_type:
                return item['value']
        raise ConfigurationException(Configuration.SECURITY_ERROR_MESSAGE)
