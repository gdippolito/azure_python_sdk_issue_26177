# Introduction
This repo has been created to prove the limitation of ManagedIdentityCredential() authentication method when running an application with many threads. Since the token is not cached between different threads every call to ManagedIdentityCredential() will cause a request to the managed identity endpoint. 

This repository works with both azure cli and managed identity and prove how creating a singleton would reduce authentication calls.   

# Assumptions
1. You have a storage account 
2. You have a container named `test-container` within the storage account
3. You have a file named `test.txt` within the container

## Run using AzureCLICredentials

```
pip3 install -r requirements.txt
AZURE_STORAGE_ACCOUNT=<put-storage-account-name-here> python azure_client.py
```

## Run using Managed identity

```
pip3 install -r requirements.txt
IS_RUNNING_IN_AZURE=True AZURE_STORAGE_ACCOUNT=<put-storage-account-name-here> python azure_client.py
```

