import argparse
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import boto3
from botocore.exceptions import ClientError
from google.cloud import secretmanager
import os
import sys

###--- REGION: Functions ---###
def parser_arguments():
    """
    Parses script arguments and grabs env vars as needed.

    Args:
        None.

    Returns:
        args (Namespace): Parsed command-line arguments.
    """
    # Create the argument parser
    parser = argparse.ArgumentParser(
        description='''Script to test retrieval of secrets from AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager.\n\nAWS Examples:\nDefault Credential File:\n  ./cloud_secrets_retrieval.py --cloud_provider aws --auth_method credential_file --aws_region $AWS_SECRET_REGION --aws_secret_name $AWS_SECRET_NAME\nExplicit Access Keys:\n  ./cloud_secrets_retrieval.py --cloud_provider aws --auth_method access_keys --aws_region $AWS_SECRET_REGION --aws_secret_name $AWS_SECRET_NAME --access_key_id $AWS_ACCESS_KEY_ID --secret_access_key $AWS_SECRET_ACCESS_KEY\n\nAzure Example:\n  ./cloud_secrets_retrieval.py --cloud_provider azure --client_id $AZURE_CLIENT_ID --client_secret $AZURE_CLIENT_SECRET --tenant_id $AZURE_TENANT_ID --subscription_id $AZURE_SUBSCRIPTION_ID --azure_secret_name $AZ_SECRET_NAME  --azure_vault_url $AZ_VAULT_URL\n\nGCP Example:\n  ./cloud_secrets_retrieval.py  --cloud_provider gcp --credentials_file $GOOGLE_APPLICATION_CREDENTIALS --project_id $GOOGLE_CLOUD_PROJECT --secret_id $GCP_SECRET_ID\n\n------------------''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Set the cloud provider
    parser.add_argument("--cloud_provider", choices=["aws", "azure", "gcp"], help="Which cloud provider to retrieve secrets from")

    # AWS arguments
    aws_group = parser.add_argument_group('AWS Arguments')
    aws_group.add_argument("--auth_method", choices=["credential_file", "access_keys"], help="Authentication method to use")
    aws_group.add_argument("--profile_name", default="default", help="Optional AWS profile name in credential file. Default: 'default'")
    aws_group.add_argument("--access_key_id", help="AWS access key ID", metavar='AWS_ACCESS_KEY_ID')
    aws_group.add_argument("--secret_access_key", help="AWS secret access key", metavar='AWS_SECRET_ACCESS_KEY')
    aws_group.add_argument("--aws_secret_name", help="AWS secret name", metavar='AWS_SECRET_NAME')
    aws_group.add_argument("--aws_region", help="AWS region", metavar='AWS_SECRET_REGION')

    # Azure Arguments
    azure_group = parser.add_argument_group('Azure Arguments')
    azure_group.add_argument("--azure_secret_name", help="Name for this Azure secret", metavar='AZ_SECRET_NAME')
    azure_group.add_argument("--azure_vault_url", help="URL for the Azure vault", metavar='AZ_VAULT_URL')
    azure_group.add_argument("--client_id", help="Azure Service Principal id to access the secret", metavar='AZURE_CLIENT_ID')
    azure_group.add_argument("--client_secret", help="Azure Secret value to use for authentication", metavar='AZURE_CLIENT_SECRET')
    azure_group.add_argument("--tenant_id", help="Azure Tenant where Service Principal is stored", metavar='AZURE_TENANT_ID')
    azure_group.add_argument("--subscription_id", help="Azure Subscription where secret is managed", metavar='AZURE_SUBSCRIPTION_ID')

    # GCP Arguments
    gcp_group = parser.add_argument_group('GCP Arguments')
    gcp_group.add_argument("--credentials_file", help="GCP Service Account credentials file", metavar='GOOGLE_APPLICATION_CREDENTIALS')
    gcp_group.add_argument("--project_id", help="GCP project ID", metavar='GOOGLE_CLOUD_PROJECT')
    gcp_group.add_argument("--secret_id", help="GCP secret ID", metavar='GCP_SECRET_ID')

    args = parser.parse_args()

    # Check for env vars
    args.access_key_id = args.access_key_id or os.getenv('AWS_ACCESS_KEY_ID')
    args.secret_access_key = args.secret_access_key or os.getenv('AWS_SECRET_ACCESS_KEY')
    args.secret_name = args.aws_secret_name or os.getenv('AWS_SECRET_NAME')    # custom env var for this script
    args.aws_region = args.aws_region or os.getenv('AWS_SECRET_REGION')    # custom env var for this script
    args.azure_secret_name = args.azure_secret_name or os.getenv('AZ_SECRET_NAME')           # custom env var for this script
    args.azure_vault_url = args.azure_vault_url or os.getenv('AZ_VAULT_URL')           # custom env var for this script
    args.client_id = args.client_id or os.getenv('AZURE_CLIENT_ID')
    args.client_secret = args.client_secret or os.getenv('AZURE_CLIENT_SECRET')
    args.tenant_id = args.tenant_id or os.getenv('AZURE_TENANT_ID')
    args.subscription_id = args.subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
    args.credentials_file = args.credentials_file or os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
    args.project_id = args.project_id or os.getenv('GOOGLE_CLOUD_PROJECT')
    args.secret_id = args.secret_id or os.getenv('GCP_SECRET_ID')          # custom env var for this script

    # Print cloud provider and associated argument names and their values
    arg_dict = vars(args)
    print(f"Cloud Provider: {args.cloud_provider.upper()}")
    if args.cloud_provider == 'aws':
        print("AWS Arguments:")
        for arg_name in ['auth_method', 'profile_name', 'access_key_id', 'secret_access_key', 'secret_name', 'aws_region']:
            arg_value = arg_dict.get(arg_name)
            if arg_value is None:
                print(f"  {arg_name}: Not provided")
            else:
                env_var = f"(from {os.getenv(arg_name.upper(), '')})" if os.getenv(arg_name.upper()) else ""
                print(f"  {arg_name}: {arg_value} {env_var}")
    elif args.cloud_provider == 'azure':
        print("Azure Arguments:")
        for arg_name in ['azure_secret_name', 'azure_vault_url', 'client_id', 'client_secret', 'tenant_id', 'subscription_id']:
            arg_value = arg_dict.get(arg_name)
            if arg_value is None:
                print(f"  {arg_name}: Not provided")
            else:
                env_var = f"(from {os.getenv(arg_name.upper(), '')})" if os.getenv(arg_name.upper()) else ""
                print(f"  {arg_name}: {arg_value} {env_var}")
    elif args.cloud_provider == 'gcp':
        print("GCP Arguments:")
        for arg_name in ['credentials_file', 'project_id', 'secret_id']:
            arg_value = arg_dict.get(arg_name)
            if arg_value is None:
                print(f"  {arg_name}: Not provided")
            else:
                env_var = f"(from {os.getenv(arg_name.upper(), '')})" if os.getenv(arg_name.upper()) else ""
                print(f"  {arg_name}: {arg_value} {env_var}")

    return args

def validate_args(args):
    """
    Validates arguments provided to the script.

    Args:
        args (Namespace): Parsed command-line arguments.

    Returns:
        None.
    """
    # AWS
    if args.cloud_provider == 'aws':
        if not args.auth_method:
            print("Error: --auth_method is required when using AWS.")
            sys.exit(1)
        elif args.auth_method == 'credential_file':
            if not args.aws_region or not args.secret_name:
                print("Error: --aws_region and --secret_name are required when using 'credential_file' authentication method.")
                sys.exit(1)
        elif args.auth_method == 'access_keys':
            if not args.aws_region or not args.secret_name or not args.access_key_id or not args.secret_access_key:
                print("Error: --aws_region, --secret_name, --access_key_id, and --secret_access_key are required when using 'access_keys' authentication method.")
                sys.exit(1)
    # Azure
    elif args.cloud_provider == 'azure':
        if not args.azure_secret_name or not args.client_id or not args.client_secret or not args.tenant_id or not args.subscription_id:
            print("Error: --azure_secret_name, --client_id, --client_secret, --tenant_id, and --subscription_id are required when using Azure.")
            sys.exit(1)
    # GCP
    elif args.cloud_provider == 'gcp':
        if not args.credentials_file or not args.project_id or not args.secret_id:
            print("Error: --credentials_file, --project_id, and --secret_id are required when using GCP.")
            sys.exit(1)
    # Catch error
    else:
        print("Error: Invalid cloud provider specified, must be one of 'aws', 'azure' or 'gcp'.")
        sys.exit(1)

def retrieve_aws_secret(args):
    """
    Retrieves a secret from AWS Secrets Manager.

    Args:
        args (Namespace): Parsed command-line arguments.

    Returns:
        dict: A dictionary containing the secret value and metadata, or an error message.
    """
    if args.auth_method == 'credential_file':
        session = boto3.Session(profile_name=args.profile_name)
    elif args.auth_method == 'access_keys':
        session = boto3.Session(
            aws_access_key_id=args.access_key_id,
            aws_secret_access_key=args.secret_access_key
        )
    else:
        return {'error': "Invalid authentication method specified."}

    secrets_manager = session.client(service_name='secretsmanager', region_name=args.aws_region)

    try:
        get_secret_value_response = secrets_manager.get_secret_value(
            SecretId=args.secret_name
        )
    except ClientError as e:
        return handle_aws_client_error(e, args.secret_name)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret_value = get_secret_value_response['SecretString']
        else:
            secret_value = get_secret_value_response['SecretBinary']

        return {
            'secret_name': args.secret_name,
            'secret_value': secret_value
        }

def handle_aws_client_error(error, secret_name):
    """
    Handles AWS client errors for Secrets Manager.

    Args:
        error (ClientError): The ClientError exception raised.
        secret_name (str): The name of the secret being retrieved.

    Returns:
        dict: A dictionary containing the error message.
    """
    error_code = error.response['Error']['Code']
    if error_code == 'ResourceNotFoundException':
        error_message = f"The requested secret: {secret_name} - was not found"
    elif error_code == 'InvalidRequestException':
        error_message = f"The request was invalid due to: {error}"
    elif error_code == 'InvalidParameterException':
        error_message = f"The request had invalid params: {error}"
    elif error_code == 'DecryptionFailure':
        error_message = f"The requested secret can't be decrypted using the provided KMS key: {error}"
    elif error_code == 'InternalServiceError':
        error_message = f"An error occurred on service side: {error}"
    else:
        error_message = f"Unexpected error occurred: {error}"

    return {'error': error_message}

def retrieve_azure_secret(args):
    """
    Retrieves a secret from Azure Key Vault.

    Args:
        args (Namespace): Parsed command-line arguments.

    Returns:
        dict: A dictionary containing the secret value and metadata, or an error message.
    """
    try:
        # Force the environment vars that Azure picks up by default
        os.environ['AZURE_CLIENT_ID'] = args.client_id
        os.environ['AZURE_CLIENT_SECRET'] = args.client_secret
        os.environ['AZURE_TENANT_ID'] = args.tenant_id
        os.environ['AZURE_SUBSCRIPTION_ID'] = args.subscription_id
        # Initialize the Azure client
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=args.azure_vault_url, credential=credential)
    except Exception as e:
        return {'error': f"Failed to authenticate with Azure: {e}"}

    try:
        # Retrieve the secret
        secret = client.get_secret(args.azure_secret_name)
        # Access the secret value
        secret_value = secret.value
    except Exception as e:
        return {'error': f"Failed to get '{args.azure_secret_name}': {e}"}

    return {
        'secret_name': args.azure_secret_name,
        'secret_value': secret_value
    }

def retrieve_gcp_secret(args):
    """
    Retrieves a secret from Google Cloud Secret Manager.

    Args:
        args (Namespace): Parsed command-line arguments.

    Returns:
        dict: A dictionary containing the secret value and metadata, or an error message.
    """
    try:
        # Force the environment vars that GCP picks up by default
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = args.credentials_file
        os.environ['GOOGLE_CLOUD_PROJECT'] = args.project_id
        # Initialize the GCP client
        client = secretmanager.SecretManagerServiceClient()
    except Exception as e:
        return {'error': f"Failed to authenticate with GCP: {e}"}

    try:
        # Build the resource name of the secret
        secret_version_name = client.secret_version_path(
            args.project_id, args.secret_id, "latest"
        )
        print(f"\nACCESSING: {secret_version_name}")

        # Access the secret version
        response = client.access_secret_version(request={"name": secret_version_name})

        # Extract the secret payload
        secret_value = response.payload.data.decode("UTF-8")
    except Exception as e:
        return {'error': f"Failed to get '{args.secret_id}': {e}"}

    return {
        'secret_name': args.secret_id,
        'secret_value': secret_value
    }

###--- REGION: Invocation ---###
# Setup the argument values
args = parser_arguments()

# Validate the arguments provided
validate_args(args)

# Retrieve the secret
if args.cloud_provider == 'aws':
    secret_result = retrieve_aws_secret(args)
    if 'error' in secret_result:
        print(secret_result['error'])
    else:
        print(f"\nRESULTS:\nSecret name: {secret_result['secret_name']}")
        print(f"Secret value: {secret_result['secret_value']}")

elif args.cloud_provider == 'azure':
    secret_result = retrieve_azure_secret(args)
    if 'error' in secret_result:
        print(secret_result['error'])
    else:
        print(f"\nRESULTS:\nSecret name: {secret_result['secret_name']}")
        print(f"Secret value: {secret_result['secret_value']}")

elif args.cloud_provider == 'gcp':
    secret_result = retrieve_gcp_secret(args)
    if 'error' in secret_result:
        print(secret_result['error'])
    else:
        print(f"\nRESULTS:\nSecret name: {secret_result['secret_name']}")
        print(f"Secret value\n{secret_result['secret_value']}")
