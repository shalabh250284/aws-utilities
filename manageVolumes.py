#!/usr/bin/env python
import boto3
import collections
import datetime
import os
import requests
import time
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
def getEc2Info(instanceId=None,region='us-east-1'):
    logger.debug("Fetching EC2 details for a provided Instance ID")

    try:
        logger.info("Validating if Instance Id has been passed to the function")
        if instanceId is None:
            logger.info("Instance ID was not passed as a variable to the function, we will run it for current Instance Id")
            instanceId = getInstanceId()
        else:
            logger.info("Instance Id override is available, we will fetch information for InstanceId: %s", instanceId) 

        logger.debug("Initiating a connection to EC2 API")
        ec2_client = boto3.client('ec2', region_name=region)

        logger.debug("Got a successful connection, now we will fetch the details about provided InstanceId")
        response = ec2_client.describe_instances(InstanceIds=[ str(instanceId) ])
        logger.info("Retrived data for InstanceId: %s", instanceId)
        return response
    except Exception as e:
        logger.error("Error fetching details using EC2 API on an Instance with Id: instanceId %s", e)
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

# Function to retrive the Value of a Tag applied to an EC2 instance
def getTagValue(tagName=None,instanceId=None):
    logger.debug("Inspecting EC2 Information for extracting Tag Values")
    try:
        tagValue = ''
        
        logger.info("Validating if Instance Id has been passed to the function")
        if instanceId is None:
            logger.info("Instance ID was not passed as a variable to the function, we will run it for current Instance Id")
            instanceId = getInstanceId()
        else:
            logger.info("Instance Id override is available, we will fetch information for InstanceId: %s", instanceId)

        logger.info("Retriving EC2 information now")
        response = getEc2Info(instanceId)

        logger.info("Successfully retrived EC2 information, now extracting metadata about tags")
        tags = response['Reservations'][0]['Instances'][0]['Tags']
        if tagName is None:
            logger.info("Since no specific Tag is asked, I will return all the tags")
            return tags

        logger.debug("Itterating over Tags to extract the requuested tag: %s", tagName)
        for tag in tags:
            logger.debug("Validating if the Key %s matches requested Tag Name %s", tag['Key'].lower(), tagName.lower())
            if tag['Key'].lower() == tagName.lower():
                logger.info("Found the Tag: %s, will return the Value", tagName)
                tagValue = tag['Value']
                if tagValue == '':
                    logger.warn("Tag %s was found with a Null value", tagName)
                else:
                    logger.info("Returning the Tag Value now")
                return tagValue
    except Exception as e:
        logger.error("Error fetching EC2 Tags: %s", e)
        raise

# Function to get the Stack Information of a current instance
def getCfInfo(region='us-east-1'):
    logger.debug("Inspecting Cloudformation to extract Parameters")
    try:
        paramValue = ''

        logger.debug("Initiating a call to Cloudformation API to fetch the details")
        cf = boto3.client('cloudformation', region_name=region)

        logger.info("Find the Cloudformation Stack ID for the current instance")
        ec2_cf_id = getTagValue('aws:cloudformation:stack-id')
        logger.info("Cloudformation Id for this instance is: %s", ec2_cf_id)

        stack_overview = {}
        logger.debug("We will not extract the details of the current stack: %s", ec2_cf_id)
        try:
            logger.debug("Making an API call to describe_stacks to fetch the stack information")
            cfInfo = cf.describe_stacks(StackName=ec2_cf_id)['Stacks'][0]
            return cfInfo
        except Exception as e:
            logger.error("Error fetching EC2 Parameters: %s", e)
            raise
    except Exception as e:
        logger.error("Error fetching EC2 Parameters: %s", e)
        raise

# Function to retrive the Value of a Parameter used during stack creation
def getParamValue(paramName=None,region='us-east-1'):
    logger.debug("Inspecting CF Information for extracting Parameter Values")
    try:
        paramValue = ''

        logger.info("Retriving CF information now")
        response = getCfInfo()

        logger.info("Successfully retrived CF information, now extracting metadata about parameters")
        parameters = response['Parameters']

        if paramName is None:
            logger.info("Since no specific parameter is asked, I will return all the parameters")
            return parameters

        logger.debug("Itterating over Parameters to extract the requuested parameter: %s", paramName)
        for parameter in parameters:
            logger.debug("Validating if the Key %s matches requested Parameter Name %s", parameter['ParameterKey'].lower(), paramName.lower())
            if parameter['ParameterKey'].lower() == paramName.lower():
                logger.info("Found the Parameter: %s, will return the Value", paramName)
                paramValue = parameter['ParameterValue']
                if paramValue == '':
                    logger.warn("Parameter %s was found with a Null value", paramName)
                else:
                    logger.info("Returning the Parameter Value now")
                return paramValue
    except Exception as e:
        logger.error("Error fetching EC2 Tags: %s", e)
        raise

# Function creates a Snapshot of the EBS volumes attached to the instance
def createSnapshots(AppId):
    logger.info("Initiating a snapshot for this instance")
    logger.debug("Finding the stack Name this Instance belongs to")
    stackName = getTagValue('aws:cloudformation:stack-name')

    logger.info("The Stack name of this Instance is %s. Backups will be tagged with the Stack Name", stackName)
    logger.debug("Proceeding to prepare for Snapshots")

    try:
        logger.debug("Checking all the Mounts configured in /proc/mounts")
        d = {}
        for i in file('/proc/mounts'):
            if i[0] == '/':
                i = i.split()
                d[i[0]] = i[1]
        return 
        logger.info("Fetchig EC2 information to grab Volumes from the mapped devices")
        response = getEc2Info()
        volumes = response['Reservations'][0]['Instances'][0]['BlockDeviceMappings']
        logger.debug("Successfully retrived volume information %s", volumes) 

        logger.debug("Iterating over the Volumes to Snapshot each of them")
        for vol in volumes:
            logger.debug("Lets ensure that the Device %s is present in /proc/mounts",vol['DeviceName'])
            if d.has_key(vol['DeviceName']):
                logger.debug("Device %s found in /proc/mounts, we will snapshot the disk by its VolumeId", vol['DeviceName'])
                vol_id = vol['Ebs']['VolimeId']
                snap_dec = AppId + d[vol['DeviceName']]
                logger.debug("Device details: Name: %s, volID: %s, snap_desc: %s", vol['DeviceName'], vol_id, snap_dec)

                try:
                    logger.info("Attempting Snapshot: VolumeId=%s and Description=%s", vol_id, snap_dec)
                    snap = ec2_client.create_snapshot(VolumeId=vol_id, Description=snap_dec)
                    snapshotId = snap['SnapshotId']
                    logger.info("Snapshot started with snapshotId: %s", snapshotId)
                except Exception as e:
                    logger.error("Snapshot failed to start for snapShotId: %s with error %s", snapshotId, e)
                    raise
                logger.debug("Since Snapshot is successful, We will tag the snapshot")
                my_tags = [{
                            "Key" : "Name",
                            "Value": snap_dec
                          },
                          {
                            "Key" : "AppId",
                            "Value": AppId
                          },
                          {
                            "Key" : "StackName",
                            "Value": stackName
                          },
                          {
                            "Key" : "Type",
                            "Value": "Automated"
                          }]
                logger.info("Making an API call to tag the snapshot: %s with tags: %s", snapshotId, my_tags)
                try:
                    ec2_client.create_tags(
                        Resources = [snapshotId],
                        Tags = mytags
                    )
                    logger.info("Successfully tagged the Snapshot")
                except Exception as e:
                    logger.error("Failed to tag the Snapshot: %s. Failed with error %e", snapshotId, e)
                    raise
                logger.debug("As a post step, Now I will attempt to cleanup last snapShots created by this Automation")
                cleanupSnapshots(snap_desc,AppId)
                
            else:
                logger.debug("I dont have a Volume on disk - %s to backup as Snapshot", vol['DeviceName'])
    except Exception as e:
        logger.error("Error fetching EC2 Parameters: %s", e)
        return False
        
def cleanupSnapshots(Name,AppId):
    logger.info("Initiating cleanup of Snapshots")
    logger.debug("Finding the stack Name this Instance belongs to")
    stackName = getTagValue('aws:cloudformation:stack-name')

    logger.debug("Preparing Filters for cleanup process")
    filters = [
        { 'Name': 'tag:Name', 'Values': [Name], },
        { 'Name': 'tag:AppId', 'Values': [AppId], },
        { 'Name': 'tag:StackName', 'Values': [stackName], },
        { 'Name': 'tag:Type', 'Values': ['Automated'], },
        { 'Name': 'status', 'Values': ['completed'], },
    ]

    logger.info("Initiating the process to cleanup Snapshot")
    try:
        response = ec2_client.describe_snapshots(Filters=filters)
        response['Snapshots'].sort(key=itemgetter('StartTime'),reverse=True)
        for snapshot in response['Snapshots'][5:]:
            logger.info("deleting")
            try:
                ec2_client.delete_snapshot(SnapshotId=snapshot['SnapshotId'])
            except Exception as e:
                logger.error("Error Deleting snap: %s", e)
    except Exception as e:
        logger.error("Error fetching EC2 Parameters: %s", e)
        return False
