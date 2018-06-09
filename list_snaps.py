#!/usr/bin/env python3

'''
+-------------------------------------------------------------------------------
+
+ list_snaps.py
+
+ Python3 program to gain experience authenticating to and interacting with
+ Rubrik Clusters via REST APIs. Expects to have a VMware VM name (full or
+ partial) as a command line argument and then lists general info about the VM
+ and information on all known snapshots.
+
+ If VM search returns more than one matching VM, user is asked to further
+ restrict the search so there is only one resulting match.
+
+ Developed and tested on:
+
+  MacOS 10.13.3/4 with Python 3.6.4/5
+
+-------------------------------------------------------------------------------
'''

__author__      = "Michael E. O'Connor"
__copyright__   = "Copyright 2018"

import sys
import signal
import requests
import urllib.parse
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

Login = '<Rubrik User Name>'

Pass = '<Rubrik User Password>'

URL_Base = 'https://<IP or FQDN of Rubrik Cluster>/api/v1/'

# Requests Hook function to raise exceptions on HTTP request errors

def check_for_errors(resp, *args, **kwargs):
    resp.raise_for_status()

#------------------------------------------------------------
# Main body of program
#------------------------------------------------------------

def list_my_snaps():

    #------------------------------------------------------------------------
    # Establish a requests Session and associate hook for HTTP error checks.
    # Setting up Session will speed up multiple requests to same URL target
    # as the underlying TCP connection will be reused.
    #------------------------------------------------------------------------

    s = requests.Session()

    s.hooks['response'] = [check_for_errors]

    #-------------------------------------------------------------------------
    # Retrieve a session token by authenticating user with Rubric Cluster and
    # check for errors. On error, terminate program after printng error string.
    # Eliminates annoying Python Stack Trace output on request failures which
    # may simply be due to underlying network connectivity issues. If this 1st
    # attempt to communicate with the Cluster succeeds, it's likely subsequent
    # requests will as well.
    #-------------------------------------------------------------------------

    try:
        resp = s.post(URL_Base + 'session', verify = False, auth =(Login, Pass), timeout=5)
    except requests.exceptions.RequestException as e:
        print ('\n**Request Error (Did you forget to open Lab VPN?):\n' + str(e))
        sys.exit(1)

    #-------------------------------------------------------------------------
    # Requests are working so let's start doing something useful.
    # We're now authenticated so update future request headers with Auth Token
    #-------------------------------------------------------------------------

    token = resp.json()

    authorization = 'Bearer ' + token['token']

    s.headers.update({'Content-Type': 'application/json', 'Authorization': authorization})

    #-------------------------------------------------------------------------
    # Parse search string from user provided arg, test for more than one
    #-------------------------------------------------------------------------

    if len(sys.argv) == 2:
        vm_name = sys.argv[1]
        print ("Locating Snapshots associated with VM [{}]".format(vm_name))
    else:
        print ("Sorry, please provide the full or partial VM name: ")
        print ("Usage: {} <VM Name>".format (sys.argv[0]))
        return 0

    #-------------------------------------------------------------------------
    # We now have a VM name (or partial name) to search on. Format request and
    # send to the Cluster. If we find a match, print out some general info.
    #-------------------------------------------------------------------------

    resp = s.get(URL_Base + 'vmware/vm?name=' + vm_name, verify = False)

    vm_info = resp.json()

    total = vm_info['total']

    if (total == 0):
        print ('Sorry, [{}] records found for [{}]'.format (total, vm_name))
        print ('Please refine search criteria')
        sys.exit(1)
    else:
        print ('\nListing of matching VMs:\n')

    interesting = ['name',
         'hostName',
         'id',
         'ipAddress',
         'configuredSlaDomainName',
         'vcenterId']

    for key in vm_info.keys():
        if key == 'data':
            for item in vm_info[key]:
                for sub_key in item:
                    if sub_key in interesting:
                        print ('  {0:25}: {1}'.format (sub_key, item[sub_key]))
                    if (sub_key == 'id'):
                        vm_id = item[sub_key]
                if (total > 1):
                    print ('-' * 92)

    #------------------------------------------------------------------------
    # At this point, we're only able to check for snapshots associated with
    # a single VM. If more than 1, bail with request to further refine search
    #------------------------------------------------------------------------

    if (total != 1):
        print ('\nTotal number of records returned = {}'.format (total))
        print ('Please refine search criteria to list available snaps')
        sys.exit(1)

    #-------------------------------------------------------------------------
    # Narrowed down search to 1 successful match, list available snapshots
    #-------------------------------------------------------------------------

    URL = URL_Base + 'vmware/vm/' + urllib.parse.quote_plus(vm_id) + '/snapshot'

    resp = s.get(URL, verify = False)

    snap_info = resp.json()

    total = snap_info['total']

    print ('\n[{}] available Snaps for VM ID: {}\n'.format (total, vm_id))

    #-----------------------------------------------------------------------
    # If we find some snapshots, list them along with date, id and cloud
    # state. If no snaps are found, exit gracefully
    #-----------------------------------------------------------------------

    if (total == 0):
        sys.exit(0)
    else:
        print('         Date                             Snap ID                Cloud')
        print('-' * 70)
        for key in snap_info.keys():
            if key == 'data':
                for item in snap_info[key]:
                    for sub_key in item:
                        if (sub_key == 'date'):
                            print (' {0}:  {1}:  {2}'.format (item[sub_key], item['id'], item['cloudState']))

    #------------------------------------------------------------------------
    # All done so close user session and invalidate the session token
    #------------------------------------------------------------------------

    try:
        resp = s.delete(URL_Base + 'session/me', verify = False)
    except requests.exceptions.RequestException as e:
        print ('\n**Request Error while attempting to close session:\n' + str(e))
        sys.exit(1)

    sys.exit(0)

# Signal handler for CTRL-C manual termination

def signal_handler(signal, frame):
    print("\nProgram terminated manually")
    sys.exit(0)

# If called from shell as script

if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)

    list_my_snaps()
