# cloud_secrets_retrieval
Python script to test retrieval of secrets from AWS, Azure, and GCP

# Requirements

Script execution depends on providing various arguments at runtime that enable authentication and retrieval from the target cloud provider.

## All providers

| **Script Argument** | **Environment Variable** | **Description** |
|:------------ |:------------ |:------------ |
| `--cloud_provider`        | ---        | Which cloud provider to retrieve secrets from. Options: `aws`, `azure`, `gcp`        |

## AWS Secrets Manager

All AWS invocations require the following:

| **Script Argument** | **Environment Variable** | **Description** |
|:------------ |:------------ |:------------ |
| `--auth_method`        | ---        | Which authentication method to use. Options: `credential_file`, `access_keys`        |
| `aws_region`        | `AWS_SECRET_REGION`        | AWS region where secret is stored        |
| `aws_secret_name`        | `AWS_SECRET_NAME`        | Name of the AWS secret        |

### Default Credentials File

This method retrieves the AWS credential from the default credential file use by the AWS CLI. (`~/.aws/credentials`)

| **Script Argument** | **Environment Variable** | **Description** |
|:------------ |:------------ |:------------ |
| `--profile_name`        | ---        | **OPTIONAL** name of the profile to use from the credentials file. Default: `default`        |

### Explicit Access Keys

This method allows the user to provide the Access Key and Secret Access Key to authenticate with AWS.

| **Script Argument** | **Environment Variable** | **Description** |
|:------------ |:------------ |:------------ |
| `access_key_id`        | `AWS_ACCESS_KEY_ID`        | AWS access key ID        |
| `secret_access_key`        | `AWS_SECRET_ACCESS_KEY`        | AWS secret access key        |

## Azure Key Vault

| **Script Argument** | **Environment Variable** | **Description** |
|:------------ |:------------ |:------------ |
| `--azure_secret_name`        | `AZ_SECRET_NAME`        | Name for this Azure secret        |
| `--azure_vault_url`        | `AZ_VAULT_URL`        | URL for the Azure vault        |
| `--client_id`        | `AZURE_CLIENT_ID`        | Azure Service Principal id to access the secret        |
| `--client_secret`        | `AZURE_CLIENT_SECRET`        | Azure Secret value to use for authentication        |
| `--tenant_id`        | `AZURE_TENANT_ID`        | Azure Tenant where Service Principal is stored        |
| `--subscription_id`        | `AZURE_SUBSCRIPTION_ID`        | Azure Subscription where secret is managed        |

## GCP Secret Manager

| **Script Argument** | **Environment Variable** | **Description** |
|:------------ |:------------ |:------------ |
| `--credentials_file`        | `GOOGLE_APPLICATION_CREDENTIALS`        | GCP Service Account credentials file        |
| `--project_id`        | `GOOGLE_CLOUD_PROJECT`        | GCP project ID        |
| `--secret_id`        | `GCP_SECRET_ID`        | GCP secret ID        |

# Usage

## AWS

### Default Credentials File

```bash
./cloud_secrets_retrieval.py --cloud_provider aws --auth_method credential_file --aws_region $AWS_SECRET_REGION --aws_secret_name $AWS_SECRET_NAME [--profile_name]
```

### Explicit Access Keys

```bash
./cloud_secrets_retrieval.py --cloud_provider aws --auth_method access_keys --aws_region $AWS_SECRET_REGION --aws_secret_name $AWS_SECRET_NAME --access_key_id $AWS_ACCESS_KEY_ID --secret_access_key $AWS_SECRET_ACCESS_KEY
```

## Azure

```bash
./cloud_secrets_retrieval.py --cloud_provider azure --client_id $AZURE_CLIENT_ID --client_secret $AZURE_CLIENT_SECRET --tenant_id $AZURE_TENANT_ID --subscription_id $AZURE_SUBSCRIPTION_ID --azure_secret_name $AZ_SECRET_NAME  --azure_vault_url $AZ_VAULT_URL
```

## GCP

```bash
./cloud_secrets_retrieval.py  --cloud_provider gcp --credentials_file $GOOGLE_APPLICATION_CREDENTIALS --project_id $GOOGLE_CLOUD_PROJECT --secret_id $GCP_SECRET_ID
```

# To-Do
* Refactor to Golang to remove Python dependencies
