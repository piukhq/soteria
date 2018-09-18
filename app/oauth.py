import json

import requests

from app.configuration import Configuration
from app.base import BaseSecurity


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
            raise requests.RequestException(self.SERVICE_CONNECTION_ERROR) from e
        except (KeyError, IndexError) as e:
            raise RuntimeError(Configuration.SECURITY_ERROR_MESSAGE) from e

        return request_data
