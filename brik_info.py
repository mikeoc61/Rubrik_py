#!/usr/bin/env python3

'''
+-------------------------------------------------------------------------------
+
+ brik_info.py
+
+ Python3 program to gain experience authenticating to and interacting with
+ Rubrik Clusters via REST APIs. Authenticates User with Brik and requests
+ basic info which is then displayed on the console.
+
+ Developed and tested on:
+
+  MacOS 10.13.4 with Python 3.6.5
+
+-------------------------------------------------------------------------------
'''

__author__      = "Michael E. O'Connor"
__copyright__   = "Copyright 2018"

import sys
import signal
import requests
import urllib3

#-----------------------------------------------------------------------------
# Mask annoying SSL InsecureRequestWarnings due to calling a HTTPS URL without
# certificate verification enabled. See:
# https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
#-----------------------------------------------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#---------------------------------------------------------------
# Define constants that should probably be read from environment
#---------------------------------------------------------------

Login = '<username>'

Pass = '<userpass>'

URL_Base = 'https://<IP or FQDN of brik>/api/v1/'

# Requests Hook function to raise exceptions on HTTP request errors

def check_for_errors(resp, *args, **kwargs):
    resp.raise_for_status()

#------------------------------------------------------------
# Main body of program
#------------------------------------------------------------

def get_brik_info():

    #------------------------------------------------------------------------
    # Establish a requests Session and associate hook for HTTP error checks.
    # Setting up Session will speed up multiple requests to same URL target
    # as the underlying TCP connection will be reused.
    #------------------------------------------------------------------------

    s = requests.Session()

    s.hooks['response'] = [check_for_errors]

    #-------------------------------------------------------------------------
    # Retrieve a session token by authenticating user with Brik and
    # check for errors. On error, terminate program after printng error string.
    # Eliminates annoying Python Stack Trace output on request failures which
    # may simply be due to underlying network connectivity issues. If this 1st
    # attempt to communicate with Brik succeeds, it's likely subsequent
    # requests will as well.
    #-------------------------------------------------------------------------

    try:

        resp = s.post(URL_Base + 'session', verify = False, auth =(Login, Pass), timeout=5)

    except requests.exceptions.RequestException as e:
        print ('\n**Request Error (Did you forget to open Lab VPN?):\n' + str(e))
        sys.exit(1)

    #-------------------------------------------------------------------------
    # Requests are working so let's start doing something useful
    # We're now authenticated so update future request headers with Auth Token
    #-------------------------------------------------------------------------

    token = resp.json()

    authorization = 'Bearer ' + token['token']

    s.headers.update({'Content-Type': 'application/json', 'Authorization': authorization})

    #-------------------------------------------------------------------------
    # Request basic Cluster info from Brik and output to console
    #-------------------------------------------------------------------------

    resp = s.get(URL_Base + 'cluster/me', verify = False)

    brik_info = resp.json()

    print ('\nRubrik Cluster General Info:\n')

    for item in brik_info:
        if item == 'timezone':
            print ('  {0:30}: {timezone[timezone]}'.format ('timezone', **brik_info))
        elif item == 'geolocation':
            print ('  {0:30}: {geolocation[address]}'.format ('geolocation', **brik_info))
        else:
            print ('  {0:30}: {1}'.format (item, brik_info[item]))

    #-------------------------------------------------------------------------
    # Request summary info on all known VMware VCenters and output to console
    #-------------------------------------------------------------------------

    resp = s.get(URL_Base + 'vmware/vcenter', verify = False)

    vcenter_info = resp.json()

    print ('\nVMware vCenter General Info:')

    for key in vcenter_info.keys():
        if (key == 'hasMore') or (key == 'total'):
           continue
        elif key == 'data':
            for item in vcenter_info[key]:
                for sub_key in item:
                    if sub_key == 'hostname':
                        print ('\n{0:30}: {1}'.format (sub_key, item[sub_key]))
                        continue
                    elif sub_key == 'caCerts':
                        item[sub_key] = '<CERTIFICATE NOT DISPLAYED>'
                    print ('  {0:28}: {1}'.format (sub_key, item[sub_key]))


# Signal handler for CTRL-C manual termination

def signal_handler(signal, frame):
    print("\nProgram terminated manually")
    sys.exit(0)

# If called from shell as script

if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)

    get_brik_info()
