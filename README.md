# BRKNMS_2935_Orlando
Repo for Cisco Live Orlando 2018

This repo will be used to share the sample code that will be presented at CL Orlando 2018 session - BRKNMS-2935

Software included:

- ERNA_CL.py - full lab/POC Python code.
- config.py - init file for variables
- dnac_apis.py - Python module with various DNA Center functions
- spark_apis.py - Python module with various Spark functions
- service_now_apis.py - Python module with various ServiceNow functions
- utils.py - Python module with few handy functions
- netconf_restconf.py - RESTCONF and NETCONF interface operational status

This session will showcase the use of the open REST API's available in:

- DNA Center
- ASAv
- Cisco UCS Director
- Spark
- Tropo
- ServiceNow
- IOS XE RESTCONF and NETCONF

The application will dynamically provision secured remote access to Enterprise resources for a third party entity. The code will configure firewalls, routers, switches, and Data Center compute resources.

CLI Templates to be deployed to the DC and Remote L3 switch are included:

- DC_Config - configuration file for the DC CSR1000v
- DC_Remove - configuration file to restore the initial configuration for the DC CSR1000v
- Remote_Config - configuration file for the remote Layer 3 Access Switch
- Remote_Remove - configuration file to restore the initial configuration for the remote Layer 3 Access Switch

This code is shared as a demo, only.
