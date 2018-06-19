#!/usr/bin/env python3


# developed by Gabi Zapodeanu, TSA, GPO, Cisco Systems


import requests
from init import UCSD_URL, UCSD_PASSW, UCSD_USER
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


def get_ucsd_api_key():
    """
    Create a UCSD user api key for authentication of the UCSD API's requests
    Call to UCSD, /app/api/rest?formatType=json&opName=getRESTKey&user=
    :return: the UCSD user API Key
    """

    url = UCSD_URL + '/app/api/rest?formatType=json&opName=getRESTKey&user=' + UCSD_USER + '&password=' + UCSD_PASSW
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}
    ucsd_api_key_json = requests.get(url, headers=header, verify=False)
    ucsd_api_key = ucsd_api_key_json.json()
    print('UCSD API key: ', ucsd_api_key)
    return ucsd_api_key


def execute_ucsd_workflow(ucsd_api_key, workflow_name):
    """
    Execute an UCSD workflow
    Call to UCSD, /app/api/rest?formatType=json&opName=userAPISubmitWorkflowServiceRequest&opData=
    :param ucsd_api_key: UCSD user API key
    :param workflow_name: workflow name, parameters if needed
    :return:
    """
    url = UCSD_URL + '/app/api/rest?formatType=json&opName=userAPISubmitWorkflowServiceRequest&opData={param0:"' + \
          workflow_name + '", param1: {}, param2:-1}'
    header = {'content-type': 'application/json', 'accept-type': 'application/json', "X-Cloupia-Request-Key": ucsd_api_key}
    response = requests.post(url=url, headers=header, verify=False)
