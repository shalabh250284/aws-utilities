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
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

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
d = getECSMetadata()
print d

url = "http://169.254.169.254/latest/dynamic/instance-identity/document"

myResponse = requests.get(url)
if(myResponse.ok):
    jData = json.loads(myResponse.content)
    print jData
else:
  # If response code is not ok (200), print the resulting http error code with description
    myResponse.raise_for_status()
