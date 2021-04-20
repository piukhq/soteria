from soteria.configuration import Configuration

"""
Test getting a secret from the vault in dev.
Requires a connection to dev Europa, port forward to dev Europa on port 9000
VAULT_TOKEN is unused in Azure vault, this is legacy Hashicorp vault parameter.
VAULT_URL - The azure key vault URI

To get the information form azure key vault for iceland-bonus-card, soteria first requests the config data stored
in Europa. The config data from Europa has the key vaults secret name to retrieve secrets from the vault.
"""


def get_secret_from_dev_key_vault():
    provider_slug = "iceland-bonus-card"
    VAULT_URL = "https://bink-uksouth-dev-com.vault.azure.net/"
    VAULT_TOKEN = ""
    EUROPA_URL = "http://localhost:9000/config_service"

    config = Configuration(
        provider_slug,
        Configuration.JOIN_HANDLER,
        VAULT_URL,
        VAULT_TOKEN,
        EUROPA_URL,
    )

    return config


config = get_secret_from_dev_key_vault()

print(config.security_credentials)

