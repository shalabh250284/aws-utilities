#!/usr/bin/env python
import boto3
import collections
import datetime
import os
import requests
import time
import boto.ec2
import logging
import sys
import argparse
import subprocess
import urllib
import json

from operator import attrgetter
from operator import itemgetter

# create logger
logger = logging.getLogger('simple_example')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)-7s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

# The Function queries EC2 Metadata URL and returns a response
def getEC2Metadata():
    logger.debug("Querying EC2 Metadata URL for exploring data")
    url = "http://169.254.169.254/latest/dynamic/instance-identity/document"
    logger.debug("EC2 Metadata URL is set to: " + url)

    logger.debug("Making a API call to EC2 URL")
    myResponse = requests.get(url)

    logger.debug("Validating the Response")
    if(myResponse.ok):
        logger.debug("Got a Valid response from ECS")
        logger.debug("Converting the response into JSON")
        jData = json.loads(myResponse.content)
    else:
        # If response code is not ok (200), print the resulting http error code with description
        logger.error("Response code is not ok (200), printing the resulting http error code with description")
        myResponse.raise_for_status()
    return jData

# The Function queries KMS API to retrive KMS details
def getKMSId(KMS,region='us-east-1'):
    logger.debug("Fetchig KMS ARN for a provided kms key")
    result = ''
    try:
        logger.debug("Initiating a connection to KMS API")
        client = boto3.client('kms',region_name=region)
        logger.debug("Got a successful connection, now we will fetch all the KMS keys")
        response = client.list_aliases()
        logger.info("Iterate over the KMS Alias to find the requested KMS key: %s", KMS)
        for alias in response['Aliases']:
            if alias['AliasName'] == KMS:
                logger.info("Found the requested key in the list, we will fetch the details now")
                result = client.describe_key(KeyId=alias['TargetKeyId'])['KeyMetadata']['Arn']
                logger.info("ARN for the requested key: %s is %s", KMS,result)
                return result
            if result == '':
                logger.warning("Requested KMS key %s is not found in %s region", KMS, region)
                return False
    except Exception as e:
        logger.error("Error fetching KMS key: %s, failed with error",KMS, e)
        return False

# The Function queries EC2 API to retrive all the details about the requested instance
def getec2Info(instanceId,region='us-east-1'):
    logger.debug("Fetching EC2 details for a provided Instance ID")
    try:
        logger.info("Validating if Instance Id has been passed to the function")
        if instanceId is None:
            logger.warn("Instance ID was not passed as a variable to the function, we will run it for current Instance Id")
            instanceId = getInstanceId()
        ec2_client = boto3.client('ec2', region_name=region)
        response = ec2_client.describe_instances(InstanceIds=[ str(instance_id) ])
        return response
    except Exception as e:
        logger.error("Error fetching Instance Id: %s", e)
        return False

# Query EC2 Data for Current region
def getRegionName():
    logger.debug("Inspecting EC2 data for current Region")
    ec2Metadata = getEC2Metadata()

    logger.debug("Validate if we have the correct data")
    if 'region' in  ec2Metadata.keys():
        logger.debug("Found data, will extract Region now")
        region = ec2Metadata['region']
    else:
        logger.error("Region is not present in the dataset, Aborting!")
        exit(1)
    return region

# Query EC2 Data for InstanceId
def getInstanceId():
    logger.debug("Inspecting EC2 data for InstanceId")
    ec2Metadata = getEC2Metadata()

    logger.debug("Validate if we have the correct data")
    if 'instanceId' in  ec2Metadata.keys():
        logger.debug("Found data, will extract InstanceId now")
        instanceId = ec2Metadata['instanceId']
    else:
        logger.error("InstanceId is not present in the dataset, Aborting!")
        exit(1)
    return instanceId

