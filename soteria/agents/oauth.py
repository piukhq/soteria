import json

import requests

from soteria.agents.base import BaseSecurity
from soteria.configuration import Configuration
from soteria.security import SecurityException


class OAuth(BaseSecurity):

    def encode(self, json_data):
        try:
            credentials = self.credentials['outbound']['credentials'][0]['value']
            url = credentials['url']
            resp = requests.post(url=url, data=credentials['payload'])
            response_json = resp.json()

            request_data = {
                "json": json.loads(json_data),
                "headers": {
                    "Authorization": "{} {}".format(credentials['prefix'], response_json['access_token'])
                }
            }
        except requests.RequestException as e:
            raise SecurityException(self.SERVICE_CONNECTION_ERROR) from e
        except (KeyError, IndexError) as e:
            raise SecurityException(Configuration.SECURITY_ERROR_MESSAGE) from e

        return request_data
