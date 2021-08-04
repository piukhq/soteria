import json

from soteria.agents.base import BaseSecurity


class OpenAuth(BaseSecurity):
    def encode(self, json_data):
        return {"json": json.loads(json_data)}

    def decode(self, headers, json_data):
        return json_data or "{}"
