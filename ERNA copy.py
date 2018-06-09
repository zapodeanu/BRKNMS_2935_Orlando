#!/usr/bin/env python3


# developed by Gabi Zapodeanu, TSA, GPO, Cisco Systems


# import Python packages


import urllib3
import time
import datetime
import logging
import sys
import requests
import json
import select
import re

# import functions modules

import utils
import spark_apis
import dnac_apis
import asav_apis
import init
import netconf_restconf

from PIL import Image, ImageDraw, ImageFont  # for image processing
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth


from init import SPARK_AUTH, SPARK_URL, TROPO_KEY
from init import GOOGLE_API_KEY
from init import DNAC_URL, DNAC_USER, DNAC_PASS
from init import ASAv_URL, ASAv_USER, ASAv_PASSW
from init import UCSD_URL, UCSD_KEY

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)
ASAv_AUTH = HTTPBasicAuth(ASAv_USER, ASAv_PASSW)

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

# The following declarations need to be updated based on your lab environment

# Spark related
ROOM_NAME = 'ERNA'
from init import APPROVER_EMAIL

# UCSD related
UCSD_CONNECT_FLOW = 'Gabi_VM_Connect_VLAN_10'
UCSD_DISCONNECT_FLOW = 'Gabi_VM_Disconnect_VLAN_10'

# VDI IPv4 address
VDI_IP = '172.16.203.50'

# ASAv
OUTSIDE_INT = 'outside'


def main():
    """
    Vendor will join Spark Room with the name {ROOM_NAME}
    It will ask for access to an IP-enabled device - named {IPD}
    The code will map this IP-enabled device to the IP address {172.16.41.55}
    Access will be provisioned to allow connectivity from DMZ VDI to IPD
    """

    last_person_email = 'gzapodea@cisco.com'
    timer = 2

    # save the initial stdout
    initial_sys = sys.stdout

    # the user will be asked if interested to run in demo mode or in
    # production (logging to files - erna_log.log, erna_err.log))

    user_input = utils.get_input_timeout('If running in Demo Mode please enter y ', 10)

    if user_input != 'y':

        # open a log file 'erna.log'
        file_log = open('erna_log.log', 'w')

        # open an error log file 'erna_err.log'
        err_log = open('erna_err.log', 'w')

        # redirect the stdout to file_log and err_log
        sys.stdout = file_log
        sys.stderr = err_log

        # configure basic logging to send to stdout, level DEBUG, include timestamps
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, format=('%(asctime)s - %(levelname)s - %(message)s'))

    # the local date and time when the code will start execution

    date_time = str(datetime.datetime.now().replace(microsecond=0))
    print('\nThe app started running at this time ' + date_time)

    user_input = 'y'
    user_input = utils.get_input_timeout('Enter y to skip next section : ', 10)

    if user_input != 'y':
        # verify if Spark Space exists, if not create Spark Space, and add membership (optional)

        spark_room_id = spark_apis.get_room_id(ROOM_NAME)
        if spark_room_id is None:
            spark_room_id = spark_apis.create_room(ROOM_NAME)
            print('- ', ROOM_NAME, ' -  Spark room created')

            # invite membership to the room
            spark_apis.add_room_membership(spark_room_id, APPROVER_EMAIL)

            spark_apis.post_room_message(ROOM_NAME, 'To require access enter :  IPD')
            spark_apis.post_room_message(ROOM_NAME, 'Ready for input!')
            print('Instructions posted in the room')
        else:
            print('- ', ROOM_NAME, ' -  Existing Spark room found')

            spark_apis.post_room_message(ROOM_NAME, 'To require access enter :  IPD')
            spark_apis.post_room_message(ROOM_NAME, 'Ready for input!')
        print('- ', ROOM_NAME, ' -  Spark room id: ', spark_room_id)

        # check for messages to identify the last message posted and the user's email who posted the message
        # check for the length of time required for access

        last_message = (spark_apis.last_user_message(ROOM_NAME))[0]

        while last_message == 'Ready for input!':
            time.sleep(5)
            last_message = (spark_apis.last_user_message(ROOM_NAME))[0]
            if last_message == 'IPD':
                last_person_email = (spark_apis.last_user_message(ROOM_NAME))[1]
                spark_apis.post_room_message(ROOM_NAME, 'How long time do you need access for? (in minutes)  : ')
                time.sleep(10)
                if (spark_apis.last_user_message(ROOM_NAME))[0] == 'How long time do you need access for? (in minutes)  : ':
                    timer = 30 * 60
                else:
                    timer = int(spark_apis.last_user_message(ROOM_NAME)[0]) * 60
            elif last_message != 'Ready for input!':
                spark_apis.post_room_message(ROOM_NAME, 'I do not understand you')
                spark_apis.post_room_message(ROOM_NAME, 'To require access enter :  IPD')
                spark_apis.post_room_message(ROOM_NAME, 'Ready for input!')
                last_message = 'Ready for input!'

        print('\nThe user with this email: ', last_person_email, ' asked access to IPD for ', (timer/60), ' minutes')




    # get the WJT Auth token to access DNA
    dnac_token = dnac_apis.get_dnac_jwt_token(DNAC_AUTH)
    print('\nThe DNA Center auth token is: ', dnac_token)

    # IPD IP address - DNS lookup if available

    IPD_IP = '10.93.140.35'

    # locate IPD in the environment using DNA C
    ipd_location_info = dnac_apis.locate_client_ip(IPD_IP, dnac_token)

    remote_device_hostname = ipd_location_info[0]  # the network device the IPD is connected to
    vlan_number = ipd_location_info[2]  # the access VLAN number
    interface_name = ipd_location_info[1]  # the interface number is connected to

    device_location = dnac_apis.get_device_location(remote_device_hostname, dnac_token)  # network device location
    location_list_info = device_location.split('/')
    remote_device_location = location_list_info[-1]  # select the building name

    print('\nThe IPD is connected to:')
    print('this interface:', interface_name, ', access VLAN:', vlan_number)
    print('on this device:', remote_device_hostname)
    print('located:       ', remote_device_location)

    # request approval

    if user_input != 'y':
        spark_apis.post_room_message(ROOM_NAME, ('The user with this email ' + last_person_email +
                                                 ' asked access to IPD for ' + str(timer / 60) + ' minutes'))
        spark_apis.post_room_message(ROOM_NAME, 'The IPD is connected to the switch ' + remote_device_hostname +
                                     ' at our location ' + remote_device_location)
        spark_apis.post_room_message(ROOM_NAME, 'To approve enter: Y/N')

        # check for messages to identify the last message posted and the user's email who posted the message.
        # looking for user - Director email address, and message = 'Y'

        last_message = (spark_apis.last_user_message(ROOM_NAME))[0]

        while last_message == 'To approve enter: Y/N':
            time.sleep(5)
            last_message = (spark_apis.last_user_message(ROOM_NAME))[0]
            approver_email = (spark_apis.last_user_message(ROOM_NAME))[1]
            if last_message == 'y' or 'Y':
                if approver_email == APPROVER_EMAIL:
                    print('Access Approved')
                else:
                    last_message = 'To approve enter: Y/N'

        print('\nApproval process completed')

    # get UCSD API key
    # ucsd_key = get_ucsd_api_key()

    # execute UCSD workflow to connect VDI to VLAN, power on VDI
    # execute_ucsd_workflow(ucsd_key, UCSD_CONNECT_FLOW)

    print('UCSD connect flow executed')

    # deployment of interface configuration files to the DC router
    dc_device_hostname = 'PDX-RO'
    template_project = 'ERNA'
    print('\nThe DC device name is: ', dc_device_hostname)

    dc_int_config_file = 'DC_Interface_Config.txt'
    dc_int_templ = dc_int_config_file.split('.')[0]  # select the template name from the template file

    cli_file = open(dc_int_config_file, 'r')  # open file with the template
    cli_config = cli_file.read()  # read the file

    # validation of dc router cli template
    valid = dnac_apis.check_ipv4_duplicate(dc_int_config_file)
    if not valid:
        print('\nDC Router CLI Templates validated')
        dc_temp_valid = True

    dnac_apis.upload_template(dc_int_templ, template_project, cli_config, dnac_token)  # upload the template to DNA C
    depl_id_dc_int = dnac_apis.deploy_template(dc_int_templ, template_project, dc_device_hostname, dnac_token)  # deploy
    time.sleep(1)

    # deployment of routing configuration files to the DC router
    dc_rout_config_file = 'DC_Routing_Config.txt'
    dc_rout_templ = dc_rout_config_file.split('.')[0]  # select the template name from the template file

    cli_file = open(dc_rout_config_file, 'r')  # open file with the template
    cli_config = cli_file.read()  # read the file

    dnac_apis.upload_template(dc_rout_templ, template_project, cli_config, dnac_token)  # upload the template to DNA C
    depl_id_dc_routing = dnac_apis.deploy_template(dc_rout_templ, template_project, dc_device_hostname, dnac_token)


    print('\nDeployment of the configurations to the DC Router, ', dc_device_hostname, 'started')

    time.sleep(1)

    # deployment of interface configuration files to the Remote router

    remote_int_config_file = 'Remote_Interface_Config.txt'
    remote_int_templ = remote_int_config_file.split('.')[0]  # select the template name from the template file

    cli_file = open(remote_int_config_file, 'r')  # open file with the template
    cli_config = cli_file.read()  # read the file

    dnac_apis.upload_template(remote_int_templ, template_project, cli_config, dnac_token)  # upload the template to DNA C
    depl_id_remote_int = dnac_apis.deploy_template(remote_int_templ, template_project, remote_device_hostname, dnac_token)   # deploy
    time.sleep(1)

    # deployment of routing configuration files to the Remote router

    remote_rout_config_file = 'Remote_Routing_Config.txt'
    remote_rout_templ = remote_rout_config_file.split('.')[0]  # select the template name from the template file

    cli_file = open(remote_rout_config_file, 'r')  # open file with the template
    cli_config = cli_file.read()  # read the file

    # update the template with the localized info for the IPD
    # replace the $VlanId with the localized VLAN access
    # replace the $IPD with the IPD ip address

    cli_config = cli_config.replace('$IPD', IPD_IP)
    cli_config = cli_config.replace('$VlanId', vlan_number)

    # validation of remote router cli template
    valid = dnac_apis.check_ipv4_duplicate(remote_rout_config_file)
    if not valid:
        print('\nRemote Device CLI Templates validated')
        remote_templ_valid = True

    dnac_apis.upload_template(remote_rout_templ, template_project, cli_config, dnac_token)  # upload the template to DNA C
    depl_id_remote_routing = dnac_apis.deploy_template(remote_rout_templ, template_project, remote_device_hostname, dnac_token)   # deploy

    print('\nDeployment of the configurations to the Remote device, ', remote_device_hostname, ' started')

    time.sleep(1)

    # check the deployment status after waiting for all jobs to complete - 5 seconds
    print('\nWait for DNA Center to complete template deployments')
    time.sleep(10)

    dc_interface_status = dnac_apis.check_template_deployment_status(depl_id_dc_int, dnac_token)
    dc_routing_status = dnac_apis.check_template_deployment_status(depl_id_dc_routing, dnac_token)
    remote_interface_status = dnac_apis.check_template_deployment_status(depl_id_remote_int, dnac_token)
    remote_routing_status = dnac_apis.check_template_deployment_status(depl_id_remote_routing, dnac_token)

    print('Templates deployment status: ', dc_interface_status, dc_routing_status, remote_interface_status, remote_routing_status)
    if dc_interface_status == 'SUCCESS' and dc_routing_status ==  'SUCCESS' and remote_interface_status == 'SUCCESS' and remote_routing_status == 'SUCCESS':
        print('\nAll templates deployment have been successful\n')
        templ_deploy_status = True

    # synchronization of devices configured - DC and Remote Router
    dc_sync_status = dnac_apis.sync_device(dc_device_hostname, dnac_token)[0]
    remote_sync_status = dnac_apis.sync_device(remote_device_hostname, dnac_token)[0]

    if dc_sync_status == 202:
        print('\nDNA Center started the DC Router resync')
    if remote_sync_status == 202:
        print('\nDNA Center started the Remote Router resync')

    dc_router_tunnel = netconf_restconf.get_restconf_int_oper_status('Tunnel201')
    remote_router_tunnel = netconf_restconf.get_netconf_int_oper_status('Tunnel201')

    print('\nThe Tunnel 201 interfaces operational state:')
    print('From ', remote_device_hostname, ' using NETCONF -', dc_router_tunnel)
    print('From ', dc_device_hostname, ' using RESTCONF -', remote_router_tunnel)

    print('\nWait for DNA Center to complete the resync of the two devices')

    time.sleep(240)

    # start a path trace to check the path segmentation
    path_trace_id = dnac_apis.create_path_trace('172.16.202.1', IPD_IP, dnac_token)

    print('\nWait for Path Trace to complete')
    time.sleep(20)

    path_trace_info = dnac_apis.get_path_trace_info(path_trace_id, dnac_token)
    print('\nPath Trace status: ', path_trace_info[0])
    print('\nPath Trace details: ', path_trace_info[1])


    # create ASAv outside interface ACL to allow traffic

    outside_acl_id = asav_apis.get_asav_access_list(OUTSIDE_INT)
    asav_status = asav_apis.create_asav_access_list(outside_acl_id, OUTSIDE_INT, VDI_IP, IPD_IP)
    if asav_status == 201:
        print('ASAv access list updated to allow traffic from ', VDI_IP, ' to ', VDI_IP, ' on the interface ', OUTSIDE_INT)
    else:
        print('Error updating the ASAv access list on the interface ', OUTSIDE_INT)

    # Spark notification

    spark_apis.post_room_message(ROOM_NAME, 'Requested access to this device: IPD, located in our office ' +
                                 remote_device_location + ' by user ' + last_person_email + ' has been granted for '
                                 + str(int(timer / 60)) + ' minutes')


    # Tropo notification - voice call

    voice_notification_result = spark_apis.tropo_notification()

    spark_apis.post_room_message(ROOM_NAME, 'Tropo Voice Notification: ' + voice_notification_result)


    # time.sleep(timer)
    input('\nInput any key to continue ! ')

    #
    #  restore configurations to initial state
    #

    #  restore DC router config

    dc_del_file = 'DC_Delete.txt'
    dc_del_templ = dc_del_file.split('.')[0]

    cli_file = open(dc_del_file, 'r')
    cli_config = cli_file.read()

    dnac_apis.upload_template(dc_del_templ, template_project, cli_config, dnac_token)
    depl_id_dc_del = dnac_apis.deploy_template(dc_del_templ, template_project, dc_device_hostname, dnac_token)

    print('\nDC Router restored to the baseline configuration')

    time.sleep(1)

    #  restore Remote router config

    remote_del_file = 'Remote_Delete.txt'
    remote_del_templ = remote_del_file.split('.')[0]

    cli_file = open(remote_del_file, 'r')
    cli_config = cli_file.read()

    # update the template with the local info for the IPD
    # replace the $VlanId with the local VLAN access
    # replace the $IPD with the IPD ip address

    cli_config = cli_config.replace('$IPD', IPD_IP)
    cli_config = cli_config.replace('$VlanId', vlan_number)

    dnac_apis.upload_template(remote_del_templ, template_project, cli_config, dnac_token)

    print('\nRemote Router restored to the baseline configuration')

    time.sleep(1)

    # remove the ASAv outside interface ACLE that allowed traffic between VDI and IPD

    outside_acl_id = asav_apis.get_asav_access_list(OUTSIDE_INT)
    asav_status = asav_apis.delete_asav_access_list(outside_acl_id, OUTSIDE_INT)
    if asav_status == 204:
        print('\nASAv access list on the interface ', OUTSIDE_INT, ' restored to the baseline configuration')
    else:
        print('Error while restoring the ASAv access list on the interface ', OUTSIDE_INT)

    # execute UCSD workflow to discoconnect VDI to VLAN, power on VDI
    # execute_ucsd_workflow(ucsd_key, UCSD_DISCONNECT_FLOW)

    print('\nUCSD disconnect flow executed')

    # Spark notification

    spark_apis.post_room_message(ROOM_NAME, 'Access to this device: IPD has been terminated')

    # update the database with script execution

    access_log_file = open('access_logs.csv', 'a')
    data_to_append = [date_time, last_person_email, IPD_IP, approver_email, dc_temp_valid, remote_templ_valid,
                      templ_deploy_status, dc_router_tunnel, remote_router_tunnel, path_trace_info]
    access_log_file.write(data_to_append)
    access_log_file.close()

    print('\nRecords database updated, file saved')

    # restore the stdout to initial value
    sys.stdout = initial_sys

    # the local date and time when the code will end execution

    date_time = str(datetime.datetime.now().replace(microsecond=0))

    print('\n\nEnd of application run at this time ', date_time)


if __name__ == '__main__':
    main()

