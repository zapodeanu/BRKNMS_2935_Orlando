#!/usr/bin/env python3


# developed by Gabi Zapodeanu, TSA, GPO, Cisco Systems


import json

import requests
import urllib3
from requests.auth import HTTPBasicAuth  # for Basic Auth
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

from config import RO_HOST, PASS, USER

ROUTER_AUTH = HTTPBasicAuth(USER, PASS)


def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data:
    :return:
    """

    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))


def get_restconf_int_oper_status(interface):

    url = 'https://' + RO_HOST + '/restconf/data/interfaces-state/interface=' + interface
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    response = requests.get(url, headers=header, verify=False, auth=ROUTER_AUTH)
    interface_info = response.json()
    oper_data = interface_info['ietf-interfaces:interface']
    return oper_data


# get interface operation data using RESTCONF

json_info = get_restconf_int_oper_status('GigabitEthernet1')
pprint(json_info)