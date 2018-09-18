import json
import time

from soteria.configuration import Configuration

TEST_REQUEST_DATA = {'points': '10'}


TEST_PUBLIC_KEY = (
    '-----BEGIN RSA PUBLIC KEY-----\n'
    'MIIBCgKCAQEAsw2VXAHRqPaCDVYI6Lug3Uq9Quik7m3sI8BkzqdCkBmakPZ5cssb\n'
    'c4EsxETTA9V0V1KDMUy6vGUSaN8pbg4MPDZOzUlJyOcBAhaKWpUH4Bw0OlBtKPVe\n'
    'wN51n8NZHvwqh39f5rwVNVB5T2haTOsuG0Q7roH5TPYs75F87bELwRLCnWyXo69f\n'
    '6o6fH7N+M2CN11S1UKT7ZkqaL2fm3LWuf8GWAkOrvrZp6js3kKCCuztI+JxP93Aa\n'
    '3411aVH1jt0Wgyex+ekdAO2ykGq2tbs9vGi//6ZweZey+B1+2LrCum1+Wulaf1lG\n'
    'LNF5Bo6fHuXXw63fhx54PQe8pMWc5LW93wIDAQAB\n'
    '-----END RSA PUBLIC KEY-----\n'
)


# matching private key for the public key we use in the tests
TEST_PRIVATE_KEY = (
    '-----BEGIN RSA PRIVATE KEY-----\n'
    'MIIEpAIBAAKCAQEAsw2VXAHRqPaCDVYI6Lug3Uq9Quik7m3sI8BkzqdCkBmakPZ5\n'
    'cssbc4EsxETTA9V0V1KDMUy6vGUSaN8pbg4MPDZOzUlJyOcBAhaKWpUH4Bw0OlBt\n'
    'KPVewN51n8NZHvwqh39f5rwVNVB5T2haTOsuG0Q7roH5TPYs75F87bELwRLCnWyX\n'
    'o69f6o6fH7N+M2CN11S1UKT7ZkqaL2fm3LWuf8GWAkOrvrZp6js3kKCCuztI+JxP\n'
    '93Aa3411aVH1jt0Wgyex+ekdAO2ykGq2tbs9vGi//6ZweZey+B1+2LrCum1+Wula\n'
    'f1lGLNF5Bo6fHuXXw63fhx54PQe8pMWc5LW93wIDAQABAoIBAQCEdnQc0SuueE/W\n'
    'VePZaZWkoPpLWZlK2v9ro5XwXEUeHhL/U5idmC0C0nmv6crCd1POljiAbGdpoMxx\n'
    '0UbxKGtc0ECUFrgDbQKN7OcGBGMDJVpuGbnoJz6mKO2T+A0ioyNDgrQMGvEFtDdK\n'
    'y8SiSwqdGWmdvIIWsbiks1lc7zHm7yAUWSp/XYgsw73+xsU+3wRlrEGsUoiTlb5J\n'
    'ZAGXBd95Gix7FQeX04WDP47xtdaydz2G/dhqsN8w78peMDPMNd/LPKMpAHYCT/5b\n'
    'wri0nfzVjNMHULCZU4KoopO8De0M1aik5GwWOdnFx6z/VkW/drXltfc9MKOJKXP7\n'
    'WI5wSCHhAoGBAOmt8z7y5RYuhIum8+e1hsQPb0ah55xcGSK8Vb066xx1XFxlgWB+\n'
    'Xiv+Ga7nQvJm3johLPuIFp0eQKrJ3a+KH+L6biM20S7K5hfxi3qdrHOBd8qKoRWS\n'
    'cbR1V40TYxXTvWYYUa2jnKPsB0msm+3l0jwNLZhygbhwDtw1cNhed2ebAoGBAMQn\n'
    '4UPHU1HE7nUI09eY11eUURuB69TRIoZNO3VVII83RHro7qHyKWk0W2RevjrE8ir2\n'
    'S4ivFYQU5lca6QmcsPj7iGtFbeVImuTWwDTaahCFcfV/pV0L6xxU/7TowKivABHe\n'
    'SUVwZJU+sPPcSSHZRa1uP7/6XD5oZEnysm1Vx6ENAoGBAKQiw/XWRKVE/WLeXPnH\n'
    'Hqb+NGoHdRj1883bPdoR1W0C3mIkBjER8fGypLWeyP5c1QE9pkvzNfccdc3Axw7y\n'
    '1RzoTI49hcb5S49L4W257JShPtQsdaMiXu2jcmCsWm/Nb36T3GM7xd25/xB3xnre\n'
    'b8Iwe3NWEtnLFBUHEIFaMUK7AoGAHoqHDGKQmn6rEhXZxgvKG5zANCQ6b9xQH9EO\n'
    'nOowM5xLUUfLP/PQdszsHeiSfdwESKQohpOcKgCHDLDn79MxytJ/HxSkU7rGQzMc\n'
    'oh4PvZrJb4v8V0xvwu2JEsXamWkF/cI6blFdl883BgEacea+bo5n5qA4lI70bn8X\n'
    'QObGOlECgYAURWOAKLd7RzgNrBorqof4ZZxdNXgOGq9jb4FE+bWI48EvTVGBmt7u\n'
    '9pHA57UX0Nf1UQ/i3dKAvm5GICDUuWHvUnnb3m+pbx0w91YSXR9t8TVNdJ2dMhNu\n'
    'ZSEUFQWbkQLUGtorzjqGssXHxKVa+9riPpztJNDl+8oHhu28wu4WyQ==\n'
    '-----END RSA PRIVATE KEY-----\n'
)


TEST_AUTHORIZATION_SIGNATURE = (
    'Signature VoT78HQQohH09yd4L+ujFhJYhCylF34eZbC70/MI0/uYnwfYTB7FhUCE'
    'Zo3oAW3+g1JcUKKtLi/nirU1DiGTefdoGYH6iK9c050dK3rp3Ytf9932OhGT7pdXT0'
    'vXG6tSYr6asNixeoGJ+Deo0fJ3GBcSLEPH/BhN9Vqqjy05zFFLiuDhT8dYvOO26l5m'
    'wc8up/lLuM3oFmdZN44ywnQEi9RjHyy72fdhslTBYMeXCOJneo9uPAiRcv95Fz5dgT'
    'qz+hfSBLiS4lC0AAp7jKXTd4K+JCnMqbFROMZHpHoxvsMRGT9L6vVrlwVDeJm2lf5M'
    'dVngMakUcJ+ehC760PpYLg=='
)


TEST_BAD_SIGNATURE = (
    'Signature JWR/2Ym1oF38RqJ8TXBYO/b92xmv3NiAwiUMlYFHwz/zBj8Yh5Lt2JIsT'
    'AaovJguXlAFP/dVZKsGlC+GJJPqixLwW4MTdCCtwZThNJgAXDH1cCa+JGqan865NWek'
    'LaKAng5nX0BgFV6bJMX71sAf7Xl4jqAiE/HjkslflG28eb2VkG6gPLGNl+JCIUnEFRK'
    'u83HYr2yNR3OoECLf49n7aL1TBz4ZusoyFZn/5lHXYQnY6HhF7EDgjQJxv7CADErrng'
    'sTukqUFTfDi7/tFZtPpwo3mZq9sHaxO9AKj+F2NVXrbD+01rltf4ClI8kGrkUBKqd/K'
    '8rk1SxAgXhH4vGCYQ=='
)


TEST_COMPOUND_KEY = {
    'payload': {
        'client_id': 'test_client_id',
        'client_secret': 'test_client_secret',
        'grant_type': 'test_grand_type',
        'resource': 'test_resource'
    },
    'prefix': 'Bearer',
    'url': 'test_oauth_url'
}


TEST_CREDENTIALS = {
        'outbound': {
            'service': 0,
            'credentials': [
                {
                    'storage_key': 'test_storage_key1',
                    'value': TEST_COMPOUND_KEY,
                    'credential_type': 'compound_key'
                },
                {
                    'storage_key': 'test_storage_key2',
                    'value': TEST_PRIVATE_KEY,
                    'credential_type': 'bink_private_key'
                }
            ]
        },
        'inbound': {
            'service': 0,
            'credentials': [{
                'storage_key': 'test_storage_key3',
                'value': TEST_PUBLIC_KEY,
                'credential_type': 'merchant_public_key'}]
        }
}


EMPTY_CREDENTIALS = {
        'outbound': {
            'service': 0,
            'credentials': []
        },
        'inbound': {
            'service': 0,
            'credentials': []
        }
}


CONFIG_CLASS_ARGS = [
    'test-slug',
    Configuration.JOIN_HANDLER,
    'vault_url',
    'vault_token',
    'config_service_url'
]


MOCK_CONFIG_JSON = {
    "id": 1,
    "merchant_id": "test-slug",
    "merchant_url": "test-request-link",
    "handler_type": Configuration.JOIN_HANDLER,
    "integration_service": Configuration.SYNC_INTEGRATION,
    "callback_url": "test-callback-link",
    "retry_limit": 1,
    "log_level": 1,
    "country": "GB",
    "security_credentials": {
        "inbound": {
            "service": Configuration.RSA_SECURITY,
            "credentials": []
        },
        "outbound": {
            "service": Configuration.OAUTH_SECURITY,
            "credentials": [
                {
                    "credential_type": "compound_key",
                    "storage_key": "test-storage-key"
                }
            ]
        }
    }
}


MOCK_VAULT_RESPONSE = {
    'data': {
        'data': {
            'value': 'test_rsa_key'
        }
    }
}


class MockRequest:
    headers = {'X-REQ-TIMESTAMP': int(time.time())}
    status_code = 200

    @staticmethod
    def get_data():
        return json.dumps({'message': 'success'}).encode()
