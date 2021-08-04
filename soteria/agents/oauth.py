import json
import typing as t

import requests

from soteria.agents.base import BaseSecurity
from soteria.configuration import Configuration
from soteria.requests_retry import requests_retry_session
from soteria.security import SecurityException


class OAuth(BaseSecurity):
    def __init__(self, credentials: t.Optional[t.Dict[str, t.Any]] = None) -> None:
        super().__init__(credentials=credentials)
        self.session = requests_retry_session()

    def encode(self, json_data: str) -> t.Dict[str, t.Any]:  # type: ignore
        try:
            credentials = t.cast(t.Dict[str, t.Any], self.credentials)["outbound"]["credentials"][0]["value"]
            url = credentials["url"]
            resp = self.session.post(url=url, data=credentials["payload"])
            resp.raise_for_status()
            response_json = resp.json()

            request_data = {
                "json": json.loads(json_data),
                "headers": {"Authorization": "{} {}".format(credentials["prefix"], response_json["access_token"])},
            }
        except requests.RequestException as e:
            error = "Failed request to get oauth token from {}. Exception: {}".format(url, e)
            raise SecurityException(error) from e
        except (KeyError, IndexError) as e:
            raise SecurityException(Configuration.SECURITY_ERROR_MESSAGE) from e

        return request_data
