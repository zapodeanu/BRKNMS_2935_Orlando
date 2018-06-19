#!/usr/bin/env python3


# developed by Gabi Zapodeanu, TSA, GPO, Cisco Systems


import requests
import json
import urllib3

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth

from config import ASAv_URL, ASAv_USER, ASAv_PASSW
ASAv_AUTH = HTTPBasicAuth(ASAv_USER, ASAv_PASSW)

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


def get_asav_access_list(interface_name):
    """
    Find out the existing ASAv interface with the name {interface_name} Access Control List
    Call to ASAv - /api/access/in/{interfaceId}/rules
    :param interface_name: ASA interface_name
    :return: Access Control List id number
    """

    url = ASAv_URL + '/api/access/in/' + interface_name + '/rules'
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}
    response = requests.get(url, headers=header, verify=False, auth=ASAv_AUTH)
    acl_json = response.json()
    # print(json.dumps(response.json(), indent=4, separators=(' , ', ' : ')))
    acl_id_number = acl_json['items'][0]['objectId']
    return acl_id_number


def create_asav_access_list(acl_id, interface_name, outside_ip, inside_ip):
    """
    Insert in line 1 a new ACL entry to existing interface ACL
    Call to ASAv - /api/access/in/{interfaceId}/rules, post method
    :param acl_id: ASA ACL id number
    :param interface_name: ASA interface_name
    :param outside_ip: outside client IP address
    :param inside_ip: inside client IP address
    :return: Response Code - 201 if successful
    """

    url = ASAv_URL + '/api/access/in/' + interface_name + '/rules/' + str(acl_id)
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}

    post_data = {
        'sourceAddress': {
            'kind': 'IPv4Address',
            'value': outside_ip
        },
        'destinationAddress': {
            'kind': 'IPv4Address',
            'value': inside_ip
        },
        'sourceService': {
            'kind': 'NetworkProtocol',
            'value': 'ip'
        },
        'destinationService': {
            'kind': 'NetworkProtocol',
            'value': 'ip'
        },
        'permit': True,
        'active': True,
        'ruleLogging': {
            'logStatus': 'Informational',
            'logInterval': 300
        },
        'position': 1,
        'isAccessRule': True
    }
    response = requests.post(url, json.dumps(post_data), headers=header, verify=False, auth=ASAv_AUTH)
    return response.status_code


def delete_asav_access_list(acl_id, interface_name):
    """
    Delete ACL entry line 1 to existing interface ACL
    Call to ASAv - /api/access/in/{interfaceId}/rules, delete method
    :param acl_id: ASA ACL id number
    :param interface_name: ASA interface_name
    :return: Response Code - None if successful
    """

    url = ASAv_URL + '/api/access/in/' + interface_name + '/rules/'+str(acl_id)
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}
    response = requests.delete(url, headers=header, verify=False, auth=ASAv_AUTH)
    return response.status_code

