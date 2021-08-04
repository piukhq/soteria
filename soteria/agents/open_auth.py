import json
import typing as t

from soteria.agents.base import BaseSecurity


class OpenAuth(BaseSecurity):
    def encode(self, json_data: str) -> t.Dict[str, t.Any]:  # type: ignore
        return {"json": json.loads(json_data)}

    def decode(self, headers: t.Dict[str, str], json_data: str) -> str:  # type: ignore
        return json_data or "{}"
