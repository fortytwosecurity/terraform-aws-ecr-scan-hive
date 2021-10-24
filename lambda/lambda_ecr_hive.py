import json
import boto3
import os
import urllib.request
import urllib
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

def hive_rest_call(alert, url, apikey):

    api = TheHiveApi(hiveurl, apikey)
    
    # Create the alert
    try:
      response = api.create_alert(alert)

      # Print the JSON response 
      print(json.dumps(response.json(), indent=4, sort_keys=True))

    except AlertException as e:
      print("Alert create error: {}".format(e))

  
    # Load into a JSON object and return that to the calling function
    return json.loads(response.decode('utf-8'))


def hive_build_data(accountId, repoName, region, severity,
                    severityHive, reference):

    description = "A vulnerability has been found in the repo " \
        + repoName + " with rating " + severity + " in account " \
        + accountId + " in region " + region \
        + ". Please remediate the issue."

    title = severity + " ECR Finding " + repoName
    source = repoName + ":" + region + ":" + accountId

    alert = Alert(title=title,
        tlp=3,
        tags=[repoName, accountId, region, severity],
        description=description,
        type='external',
        source=source,
        sourceRef=reference,

    )

    print("Hive alert: ", json.dumps(alert))

    return alert


def get_hive_secret(boto3, secretarn):
    service_client = boto3.client('secretsmanager')
    secret = service_client.get_secret_value(SecretId=secretarn)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    # Run validations against the secret
    required_fields = ['apikey', 'url']
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    return secret_dict


def lambda_handler(event, context):
    # import Lambda ENV details from context
    accountId = context.invoked_function_arn.split(":")[4]
    awsRegion = context.invoked_function_arn.split(":")[3]
    # createHiveAlert = os.environ['createHiveAlert']
    createHiveAlert = True

    print("ECR alert: ", event)

    # Get ECR event details
    eventDetails = event['detail']
    reference = event['id']
    repoName = eventDetails['repository-name']
    findingsevcounts = eventDetails['finding-severity-counts']
    numCritical = 0
    numMedium = 0
    numHigh = 0
    numLow = 0
    if findingsevcounts.get('CRITICAL'):
        numCritical = findingsevcounts['CRITICAL']
    if findingsevcounts.get('MEDIUM'):
        numMedium = findingsevcounts['MEDIUM']
    if findingsevcounts.get('HIGH'):
        numHigh = findingsevcounts['HIGH']
    if findingsevcounts.get('LOW'):
        numLow = findingsevcounts['LOW']
    # send finding to Security Hub
    severity = ""
    severityHive = 1

    if numLow:
        severity = "LOW"
        severityHive = 1
    if numMedium:
        severity = "MEDIUM"
        severityHive = 2
    if numHigh:
        severity = "HIGH"
        severityHive = 3
    if numCritical:
        severity = "CRITICAL"
        severityHive = 3

    if createHiveAlert:
        hiveSecretArn = os.environ['hiveSecretArn']
        hiveSecretData = get_hive_secret(boto3, hiveSecretArn)
        hiveUrl = hiveSecretData['url']
        hiveApiKey = hiveSecretData['apikey']
        json_data = hive_build_data(accountId, repoName, awsRegion, severity,
                                    severityHive, reference)
        json_response = hive_rest_call(json_data, hiveUrl, hiveApiKey)
        print("Created Hive alert ", json_response)
