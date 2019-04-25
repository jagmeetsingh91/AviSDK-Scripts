#!/usr/bin/env python
#
# Created on July 26, 2018
# @author: jagmeet@avinetworks.com
#
# AVISDK based Script to patch VS config to enable scaleout_ecmp.
#
# Requires AVISDK ("pip install avisdk")
# Usage:- python avi_vs_patch.py -c <Controller-IP> -u <user-name> -p <password> -v <vs_name>
# Note:- This script works for Avi Controller version 17.2.1 onwards

import argparse
import json
from avi.sdk.avi_api import ApiSession
from requests import urllib3


def main():
    parser = argparse.ArgumentParser(description="AVISDK based Script to patch a VS to enable scaleout_ecmp")
    parser.add_argument("-u", "--username", required=False, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument("-c", "--controller", required=True, help="Controller IP address")
    parser.add_argument("-t", "--tenant", required=False, help="Tenant Name")
    parser.add_argument("-v", "--vs_name", required=True, help="Virtual Service Name")
    parser.add_argument("-a", "--api_version", required=False, help="Api Version")

    args = parser.parse_args()

    # Defining required variable from required arguments
    user = str([args.username if args.username else "admin"][0])
    password = args.password
    controller = args.controller
    tenant = str([args.tenant if args.tenant else "admin"][0])
    api_version = str([args.api_version if args.api_version else "17.2.1"][0])
    vs_name = args.vs_name

    # Get Api Session
    urllib3.disable_warnings()
    api = ApiSession.get_session(controller, user, password, tenant=tenant, api_version=api_version)

    # Getting VS object by name
    resp = api.get_object_by_name("virtualservice", vs_name)

    # Checking if scaleout_ecmp is already enabled, then no need to patch. Preform exit
    # Get the VS uuid to perform patch
    if resp['scaleout_ecmp']:
        print "The Intended VS: %s has scaleout_ecmp enabled already." % vs_name
        exit(1)
    else:
        vs_uuid = resp['uuid']

    # Defining data to patch
    data = {
            "replace": 
                    {
                        "scaleout_ecmp": "True"
                    }
            }

    # Patching the VS to set scaleout_ecmp as True
    resp = api.patch('virtualservice/%s' %vs_uuid, data=data)
    if resp.status_code in range(200, 299):
        print "\n"
        print "VS patched successfully, Dumping updated VS json object below :"
        print "\n===========\n"
        print json.dumps(json.loads(resp.text), indent=2)
        print "\n===========\n"
    else:
        print('Error in patching virtualservice :%s' % resp.text)
        exit(0)


if __name__ == "__main__":
    main()
