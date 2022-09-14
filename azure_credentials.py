import logging
import os
from random import uniform
from time import sleep
from typing import Optional

import azure.identity
import azure.identity.aio
import requests
from azure.core.credentials import AccessToken
from requests.exceptions import RequestException
from retry import retry

from simple_logger import get_logger

LOGGER = get_logger(__name__)
MAX_AUTH_ENDPOINT_ATTEMPTS = 30
IS_RUNNING_IN_AZURE = os.environ.get('IS_RUNNING_IN_AZURE', False)

# Dial back the azure identity _internal logging to avoid spamming output
logging.getLogger('azure.identity._internal.decorators').setLevel(logging.WARNING)
logging.getLogger('azure.identity._internal.get_token_mixin').setLevel(logging.WARNING)
logging.getLogger('azure.identity.aio._internal.decorators').setLevel(logging.WARNING)
logging.getLogger('azure.identity.aio._internal.get_token_mixin').setLevel(logging.WARNING)
logging.getLogger('azure.identity.aio._credentials.managed_identity').setLevel(logging.WARNING)
logging.getLogger('azure.identity.aio._credentials.environment').setLevel(logging.WARNING)


def AzureCredentials(use_async: bool = False) -> '_AzureCredentialsBase':
    if use_async:
        return _AsyncAzureCredentials()
    return _AzureCredentials()


class _AzureCredentialsBase:
    """
    A class that obtains and caches Azure credentials. AzureCredentials().get_azure_credential() will try
    to obtain credentials using the following logic:

     1. If IS_RUNNING_IN_AZURE is true use ManagedIdentityCredential
     2. Else tries AzureCliCredential

    This class also contains some workarounds to deal with timeouts and other
    exception cases when running in multiple processes.
    """

    _instance: Optional['_AzureCredentialsBase'] = None
    _azure_identity = None
    use_async: Optional[bool] = None

    def __new__(cls) -> '_AzureCredentialsBase':
        if cls._instance is None:
            cls._recreate()

        # help type-checking know that cls._instance cannot be None at this point by
        # doing an assertion
        assert cls._instance is not None
        return cls._instance

    @classmethod
    def _recreate(cls):
        cls._instance = super(_AzureCredentialsBase, cls).__new__(cls)
        cls._azure_identity = None

        if os.environ.get('IS_RUNNING_IN_AZURE'):
            cls._azure_authentication_in_azure()
        else:
            cls._azure_cli_authentication()

    @classmethod
    def _azure_authentication_in_azure(cls):
        identity = azure.identity.aio if cls.use_async else azure.identity
        cls._managed_identity_prep()
        LOGGER.info('credentials, method=managed_identity')
        cls._azure_identity = identity.ManagedIdentityCredential()

    @classmethod
    def _azure_cli_authentication(cls):
        identity = azure.identity.aio if cls.use_async else azure.identity
        LOGGER.info('credentials, method=azure_cli')
        cls._azure_identity = identity.AzureCliCredential()

    @classmethod
    @retry(
        exceptions=requests.RequestException,
        tries=MAX_AUTH_ENDPOINT_ATTEMPTS,
        delay=0.1,
        logger=logging.getLogger(__name__),
    )
    def _wait_for_auth_endpoint(cls, timeout=1) -> None:
        # When running within AzureContainerInstance, Managed Identity auth endpoint
        # isn't available in the first few seconds. Wait until auth endpoint becomes available.
        requests.get('http://169.254.169.254/metadata/identity/oauth2/token', timeout=timeout)

    @classmethod
    def _managed_identity_prep(cls) -> None:
        # Hack around Azure limitations: sleep a random amount of time
        # so that when we have 48+ threads all calling the Managed Identity
        # endpoint at the start of training, we do not get rate-limited.
        world_size = int(os.environ.get('WORLD_SIZE', 1))
        sleep_time_s = max(5, int(world_size / 2))  # Expecting 100ms per worker thread and 4+ workers per rank
        sleep(uniform(0, sleep_time_s))

        try:
            cls._wait_for_auth_endpoint()
        except RequestException:
            raise RuntimeError('Failed to reach Managed Identity Endpoint')
        if cls._azure_identity:
            return cls._azure_identity

    @classmethod
    def get_azure_credential(cls) -> AccessToken:
        if cls._azure_identity:
            return cls._azure_identity

        raise RuntimeError('Failed all authentication methods')


class _AzureCredentials(_AzureCredentialsBase):
    use_async = False
    _instance: Optional['_AzureCredentials'] = None
    _azure_identity = None


class _AsyncAzureCredentials(_AzureCredentialsBase):
    use_async = True
    _instance: Optional['_AsyncAzureCredentials'] = None
    _azure_identity = None


class AzureCredentialsDefault():
    def __init__(self, use_async=False):
        self.use_async = use_async
        self.identity = None
        if os.environ.get('IS_RUNNING_IN_AZURE'):
            self._azure_authentication_in_azure()
        else:
            self._azure_cli_authentication()

    def _azure_authentication_in_azure(self):
        identity = azure.identity.aio if self.use_async else azure.identity
        LOGGER.info('credentials, method=managed_identity')
        self.identity = identity.ManagedIdentityCredential()

    def _azure_cli_authentication(self):
        identity = azure.identity.aio if self.use_async else azure.identity
        LOGGER.info('credentials, method=azure_cli')
        self.identity = identity.AzureCliCredential()

    def get_azure_credential(self):
        return self.identity