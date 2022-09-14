from concurrent.futures import ThreadPoolExecutor
import os 
import logging
from azure.storage.blob import BlobServiceClient
from azure_credentials import AzureCredentials, AzureCredentialsDefault
from simple_logger import get_logger

logging.getLogger().setLevel(logging.INFO)
logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
LOGGER = get_logger(__name__)

if not os.environ.get("AZURE_STORAGE_ACCOUNT"):
    raise Exception("Please set AZURE_STORAGE_ACCOUNT as an environment variable")

STORAGE_ACCOUNT = os.environ.get("AZURE_STORAGE_ACCOUNT")
STORAGE_ACCOUNT_URL = f'https://{STORAGE_ACCOUNT}.blob.core.windows.net/'
CONTAINER_NAME = 'test-container'
NUMBER_OF_TASKS = 4

def get_container_client_singleton():
    container_client = BlobServiceClient(
        account_url=STORAGE_ACCOUNT_URL,
        credential=AzureCredentials().get_azure_credential(),
    ).get_container_client(CONTAINER_NAME)
    return container_client

def get_container_client_default():
    container_client = BlobServiceClient(
        account_url=STORAGE_ACCOUNT_URL,
        credential=AzureCredentialsDefault().get_azure_credential(),
    ).get_container_client(CONTAINER_NAME)
    return container_client

def fetch_data_singleton():
    container_client = get_container_client_singleton()
    blob_path = f'test.txt'
    blob_client = container_client.get_blob_client(blob_path)
    _ = blob_client.download_blob().readall()

def fetch_data_default():
    container_client = get_container_client_default()
    blob_path = f'test.txt'
    blob_client = container_client.get_blob_client(blob_path)
    _ = blob_client.download_blob().readall()


if __name__ == "__main__":
    LOGGER.info("I'm using a thread pool with singleton authentication. The authentication will be performed only once")
    with ThreadPoolExecutor() as executor:
        
        for _ in range(0, NUMBER_OF_TASKS):
            future = executor.submit(fetch_data_singleton)
            future.result()
    LOGGER.info("Using normal Azure credentials class in a thread pool")
    with ThreadPoolExecutor() as executor:
        
        for _ in range(0, NUMBER_OF_TASKS):
            future = executor.submit(fetch_data_default)
            future.result()