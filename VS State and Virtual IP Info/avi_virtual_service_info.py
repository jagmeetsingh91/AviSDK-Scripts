#!/usr/bin/env python
#
# Created on Nov 14, 2017
# @author: aziz@avinetworks.com, jagmeet@avinetworks.com
#
# AVISDK based Script to get the status and configuration information of the Virtual Services
#
# Requires AVISDK ("pip install avisdk") and PrettyTable ("pip install PrettyTable")
# Usage:- python avi_virtual_service_info.py -c <Controller-IP> -u <user-name> -p <password>
# Note:- This script works for Avi Controler version 17.1.1 onwards
 
import json
import argparse
from avi.sdk.avi_api import ApiSession
from requests.packages import urllib3
from prettytable import PrettyTable
from prettytable import ALL as ALL
 
urllib3.disable_warnings()
 
def get_vs_list(api, api_version):
    vs_list = []
    rsp = api.get('virtualservice', api_version=api_version)
    for vs in rsp.json()['results']:
        vs_list.append(vs['uuid'])
    return vs_list
 
def get_vs_oper_info(api, api_version, vs_list):
    oper_dict = {}
    for vs in vs_list:
        rsp = api.get('virtualservice-inventory/%s' % vs, api_version=api_version)
        vs_data = rsp.json()
        req_vs_data = { "state": vs_data['runtime']['oper_status']['state'], "name": vs_data['config']['name'],
                        "uuid": vs_data['config']['uuid'] }
        i = 1
        for vips in vs_data['config']['vip']:
            req_vs_data["vip_"+str(i)] = vips
            i = i+1
        j = 1
        for dns in vs_data['config']['dns_info']:
            req_vs_data["dns_"+str(j)] = dns
            j = j+1
        if vs_data['runtime']['oper_status']['state'] in oper_dict.keys():
            oper_dict[vs_data['runtime']['oper_status']['state']].append(req_vs_data)
        else:
            oper_dict[vs_data['runtime']['oper_status']['state']] = []
            oper_dict[vs_data['runtime']['oper_status']['state']].append(req_vs_data)
    return oper_dict
 
def main():
     
    #Getting Required Args
    parser = argparse.ArgumentParser(description="AVISDK based Script to get the status and configuration"+
                                                 " information of the Virtual Services")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument("-c", "--controller", required=True, help="Controller IP address")
    parser.add_argument("-t", "--tenant", required=False, help="Tenant Name")
    parser.add_argument("-a", "--api_version", required=False, help="Tenant Name")
    args = parser.parse_args()
     
    user = args.username
    host = args.controller
    password = args.password
    if args.tenant:
        tenant=args.tenant
    else:
        tenant="*"
 
    if args.api_version:
        api_version=args.api_version
    else:
        api_version="17.1.1"
     
    #Getting API session for the intended Controller.
    api = ApiSession.get_session(host, user, password, tenant=tenant, api_version=api_version)
     
    #Getting the list of VirtualService(s).
    vs_list =  get_vs_list(api, api_version)
     
    #Getting VS information
    oper_dict = get_vs_oper_info(api, api_version, vs_list)
     
    #print "Final Oper Dict:" + str(oper_dict)
 
    for state, vs in oper_dict.iteritems():
        print("VS in State:%s [%s]" % (state, len(vs)))
        table = PrettyTable(hrules=ALL)
        table.field_names = ["VS Name","VIP_ID", "VIP_Address", "DNS_INFO"]
        for vss in vs:
            vips = list()
            dns_info = list()
            vip_count = 0
            dns_count = 0
            if 'vip_1' in vss.keys():
                vips = [value for key, value in vss.iteritems() if 'vip' in key.lower()]
                vip_count = len(vips)
            if 'dns_1' in vss.keys():           
                dns_info = [value for key, value in vss.iteritems() if 'dns' in key.lower()]
                dns_count = len(dns_info)
            vs_name = vss['name']
            vip_ids = ''
            vips_list = ''
            dns_list = ''
            for vip in vips:
                vip_ids += vip['vip_id'] + "\n"
                vips_list += vip['ip_address']['addr']
                if vip.get('floating_ip', None):
                    vips_list += '- ' + vip['floating_ip']['addr']
                vips_list+='\n'
            for dns in dns_info:
                dns_list += dns['fqdn'] + "\n"
            table.add_row([vs_name, vip_ids[:-1], vips_list[:-1], dns_list[:-1]])
 
        print table
        print "\n"
 
if __name__ == "__main__":
    main()
