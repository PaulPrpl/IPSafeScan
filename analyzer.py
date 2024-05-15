#!/bin/env python3


import requests
import ipaddress
import time
import json
import sys
import re

report_list = []
trash_list = []

# Get VT Api Key "VT_API_SECRET_KEY" in .env
with open('.env', 'r') as f:
    for line in f.readlines():
        if re.match(re.compile('VT_API_SECRET_KEY=.+'), line):
            VT_API_SECRET_KEY = line.split('=')[1]

    try: VT_API_SECRET_KEY
    except:
        print('could not get your VT API key. Aborting')
        sys.exit(1)

args = sys.argv[1::]

def valid_ip(ip_addr):

    address = ipaddress.ip_address(ip_addr)

    def discard(ip_addr, message):
        if ip_addr not in trash_list:
            print(f'{ip_addr} : {message}')
            trash_list.append(ip_addr)
        return False

    try:
        if address.is_global:
            return True
        else:
            return False
    except:
        discard(ip_addr, 'Invalid IP address')


def get_ip_from_files(files):
    REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    pattern = re.compile(REGEX)
    ip_list = []

    for file in files:
        try:
            with open(file, 'r') as f:
                f_lines = f.readlines()
        except:
            break
    for line in f_lines:
        ip_addresses = pattern.findall(line)
        if len(ip_addresses) > 0:
            ip_list.append(ip_addresses)
    
    return(ip_list)

def get_vt_report(ip_addr):
    VT_IP_REPORT_ENDPOINT = 'https://www.virustotal.com/api/v3/ip_addresses/'
    API_KEY = {'x-apikey': VT_API_SECRET_KEY}
    vt_answer = requests.get(VT_IP_REPORT_ENDPOINT+str(ip_addr), headers=API_KEY)
    #print(vt_answer.text)
    record = f"ip_vt_analysis_{ip_addr}_{str(int(time.time()))}.json"
    record_location = './outputs'
    output = record_location+'/'+record

    with open(output, 'w') as data:
        data.write(vt_answer.text)
        print(f"Output successfuly written in {output}")

    report_list.append(output)

def develop_vt_report(report_list):
    for report in report_list:
        try:
            with open(report, 'r') as f:
                data = json.load(f)
        except:
            print(f"could not load JSON file {report}")
            break

        id = data['data']['id']
        stats = data['data']['attributes']['last_analysis_stats']
        reviews = []

        whitelist = ['clean', 'unrated']

        for vendor in data['data']['attributes']['last_analysis_results']:
            vendor_obj = data['data']['attributes']['last_analysis_results'][vendor]
            if vendor_obj['result'] not in whitelist:
                reviews.append(vendor_obj)

        res = {'ip': id, 'stats': stats}
        if len(reviews) > 0:
            res['reviewers'] = reviews
        print(json.dumps(res, indent=4))
            

ip_list = get_ip_from_files(args)
scan_list = []

for ip_set in ip_list:
    try: selected_ip = ip_set[1]
    except:
        pass
    if valid_ip(selected_ip):
        if selected_ip not in scan_list:
            scan_list.append(selected_ip)

print(f'Will be scanned :')
for ip in scan_list:
    print(ip)

for ip_addr in scan_list:
    get_vt_report(ip_addr)

develop_vt_report(report_list)
