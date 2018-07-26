#!/usr/bin/env python
import requests
import json
import boto3
import logging


# create logger
logger = logging.getLogger('simple_example')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)7s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

# The Function queries ECS Metadata URL and return a response
def getECSMetadata():
    logger.debug("Querying ECS Metadata URL for exploring data")

    url = "http://localhost:51678/v1/metadata"
    logger.debug("ECS Metadata URL is set to: " + url)

    logger.debug("Making a API call to ECS URL")
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

# Query ECS Data for ContainerID
def getContainerID():
    logger.debug("Inspecting ECS data for ContainerID")
    ECSMetadata = getECSMetadata()

    logger.debug("Validate if we have the correct data")
    if 'ContainerInstanceArn' in  ECSMetadata.keys():
        logger.debug("Found ContainerInstanceArn, will extract ContainerID now")
        ContainerID = ECSMetadata['ContainerInstanceArn'].split('/')[-1]
    else:
        logger.error("ContainerInstanceArn is not present in the dataset, Aborting!")
        exit(1)
    return ContainerID

# Query ECS Data for Cluster Name 
def getClusterName():
    logger.debug("Inspecting ECS data for Cluster Name")
    ECSMetadata = getECSMetadata()

    logger.debug("Validate if we have the correct data")
    if 'Cluster' in  ECSMetadata.keys():
        logger.debug("Found Cluster Name in the data set")
        clusterName = ECSMetadata['Cluster']
    else:
        logger.error("Cluster Name is not present in the dataset, Aborting!")
        exit(1)
    return clusterName

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

# Adding attributes to Container Instances
def putContainerAttributes():
    logger.debug("Checking Current Region Name to initialize ECS calls")
    region = getRegionName()
    logger.info("Current region of this Instance is: " + region)
    
    logger.debug("Checking ContainerID to prepare for boto call")
    containerID = getContainerID()
    logger.info("ContainerID of this instance is: " + containerID)
    
    logger.debug("Checking Cluster Name to prepare for boto call")
    clusterName = getClusterName()
    logger.info("Cluster Name for this instance is: " + clusterName)

    logger.debug("Initilizing boto call for ecs library")
    client = boto3.client('ecs', region_name=region)

    response = client.put_attributes(cluster=clusterName, attributes=[{ 'name': 'foo', 'value': 'bar', 'targetType': 'container-instance', 'targetId': containerID }, ] )

putContainerAttributes()
