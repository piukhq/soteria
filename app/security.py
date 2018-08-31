import base64
import json
import sys
import time

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA as CRYPTO_RSA
from Crypto.Signature import pkcs1_15

from app.configuration import Configuration


class Security:

    TYPES = {
        Configuration.RSA_SECURITY: 'RSA',
        Configuration.OPEN_AUTH_SECURITY: 'OpenAuth',
        Configuration.OAUTH_SECURITY: 'OAuth'
    }

    @staticmethod
    def generate_timestamp():
        return int(time.time())

    @staticmethod
    def get_security(security_type):
        # returns corresponding security class from this module.
        try:
            return getattr(sys.modules[__name__], Security.TYPES[security_type])
        except KeyError:
            raise ValueError(f'No security found for {security_type}')


class RSA(Security):

    def get_headers(self, **kwargs):
        json_data = kwargs['json_data']
        key = kwargs['key']
        timestamp = self.generate_timestamp()
        json_data_with_timestamp = f'{json.dumps(json_data)}{timestamp}'

        key = CRYPTO_RSA.importKey(key)
        digest = SHA256.new(json_data_with_timestamp.encode('utf8'))
        signer = pkcs1_15.new(key)
        signature = base64.b64encode(signer.sign(digest)).decode('utf8')

        return {
            'Authorization': f'Signature {signature}',
            'X-REQ-TIMESTAMP': timestamp
        }


class OpenAuth(Security):

    def get_headers(self, **kwargs):
        return {'X-REQ-TIMESTAMP': self.generate_timestamp()}


class OAuth(Security):

    def get_headers(self, **kwargs):
        compound_key = kwargs['key']
        url = compound_key['url']
        resp = requests.post(url=url, data=compound_key['payload'])
        response_json = resp.json()

        return {"Authorization": f"{compound_key['prefix']} {response_json['access_token']}"}
