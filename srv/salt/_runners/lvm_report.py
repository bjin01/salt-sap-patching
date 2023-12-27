from __future__ import absolute_import, print_function, unicode_literals
from cryptography.fernet import Fernet
# Import python libs
import logging
import json
import subprocess
import csv
import salt.client
import six
from datetime import datetime,  timedelta

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler = logging.FileHandler('/var/log/diskinfo.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

log.addHandler(file_handler)

def __virtual__():
    return True

def run(**kwargs):

    '''
    This is a runner module.
    List disk information and output into csv file. 
    This module will make a minion presence check prior gathering disk information.
    The minion presence check avoids module stuck due to offline minions.

    Keyword arguments: The two keyword args specify the salt-run manage.up timeouts.
    Default is: timeout=2 gather_job_timeout=10

    CLI Example:

    .. code-block:: bash

        salt-run lvm_report.run

        
        salt-run lvm_report.run timeout=2 gather_job_timeout=15
    '''

    if "timeout" in kwargs and "gather_job_timeout" in kwargs:
        present_minions = _minion_presence_check(timeout=kwargs["timeout"], gather_job_timeout=kwargs["gather_job_timeout"])
    else:
        present_minions = _minion_presence_check()
    #present_minions = [""]

    fields = ["size", "type", "path", "fstype", "fssize", "fsused", "fsuse%", "fsavail", "mountpoint", "type", "uuid"]
    system_diskinfo_list = []
    result = []
    data_list = []
    if len(present_minions) == 0:
        return "No online minions detected."
    
    for p in present_minions:
        print(p)
        # Run the command and capture the output
        command = ['lvs']
        
        output = __salt__['salt.execute'](p, 'cmd.run', ['df -h -t xfs -t btrfs -t ext3 -t ext4 -t nfs --output=source,fstype,size,used,avail,pcent,target'])
        lines = output[p].strip().split('\n')
        headers = ['Filesystem','Type','Size','Used','Available','Use%','Mounted on']
        data = [line.split() for line in lines[1:]]

        output_lvs = __salt__['salt.execute'](p, 'cmd.run', ['lvs --reportformat json 2>/dev/null'])
        output_vgs = __salt__['salt.execute'](p, 'cmd.run', ['vgs --reportformat json 2>/dev/null'])
        output_pvs = __salt__['salt.execute'](p, 'cmd.run', ['pvs --reportformat json 2>/dev/null'])

        lvm_headers = ['lv_name','vg_name','lv_size']
        vg_headers = ["vg_size", "vg_free", "lv_count", "pv_count"]
        pv_headers = ['pv_devices', 'pv_fmt', 'pv_sizes', 'pv_free']
        
        if "command not found" in output_lvs[p] or output_lvs[p] == "":
            lv_data = ""
            print("no lvm on this host {}".format(p))
        else:
            lv_data = json.loads(output_lvs[p])
            vg_data = json.loads(output_vgs[p])
            pv_data = json.loads(output_pvs[p])

        for fs in data:
            data_set = dict()
            data_set["host"] = p
            for i in range(len(headers)):
                """ print("headers[i]: {}".format(headers[i]))
                print("data[i]: {}".format(fs[i])) """
                
                data_set[headers[i]] = fs[i]
            #print(data_set)
        
            if not isinstance(lv_data, dict):
                for lvm_head in lvm_headers:
                    data_set[lvm_head] = 'n/a'
                for vg_head in vg_headers:
                    data_set[vg_head] = 'n/a'
                for pv_head in pv_headers:
                    data_set[pv_head] = 'n/a'
            else:
                if len(lv_data["report"][0]["lv"]) > 0:
                    for l in lv_data["report"][0]["lv"]:
                        if l['vg_name'] != "" and l['lv_name'] != "":
                            lv_path = "/dev/mapper/{}-{}".format(l['vg_name'], l['lv_name'])
                            if lv_path == data_set['Filesystem']:
                                #print("found {}".format(lv_path))
                                data_set['lv_name'] = l['lv_name']
                                data_set['lv_size'] = l['lv_size']
                                data_set['vg_name'] = l['vg_name']
                                vg_result = _get_vg_info(l['vg_name'], vg_data)
                                data_set['vg_size'] = vg_result['vg_size']
                                data_set['vg_free'] = vg_result['vg_free']
                                data_set['lv_count'] = vg_result['lv_count']
                                data_set['pv_count'] = vg_result['pv_count']
                                pv_result = _get_pv_info(l['vg_name'], pv_data)
                                data_set['pv_devices'] = pv_result['pv_devices']
                                data_set['pv_fmt'] = pv_result['pv_fmt']
                                data_set['pv_sizes'] = pv_result['pv_sizes']
                                data_set['pv_free'] = pv_result['pv_free']
                            else:
                                for lvm_head in lvm_headers:
                                    data_set[lvm_head] = 'n/a'
                                for vg_head in vg_headers:
                                    data_set[vg_head] = 'n/a'
                                for pv_head in pv_headers:
                                    data_set[pv_head] = 'n/a'
                else:
                    for lvm_head in lvm_headers:
                        data_set[lvm_head] = 'n/a'
                    for vg_head in vg_headers:
                        data_set[vg_head] = 'n/a'
                    for pv_head in pv_headers:
                        data_set[pv_head] = 'n/a'
                                
            data_list.append(data_set)
        
        
        if isinstance(lv_data, dict):
            if len(lv_data["report"][0]["lv"]) > 0:
                for l in lv_data["report"][0]["lv"]:
                    match_found = False
                    data_set1 = dict()
                    if l['vg_name'] != "" and l['lv_name'] != "":
                        lv_path = "/dev/mapper/{}-{}".format(l['vg_name'], l['lv_name'])
                        for mount in data:
                            for i in range(len(headers)):
                                if lv_path == mount[i]:
                                    match_found = True
                        if not match_found:
                            data_set1["host"] = p
                            for i in range(len(headers)):
                                data_set1[headers[i]] = "n/a"
                            data_set1['lv_name'] = l['lv_name']
                            data_set1['lv_size'] = l['lv_size']
                            data_set1['vg_name'] = l['vg_name']
                            #print("send vg_name to func {}".format(l['vg_name']))
                            vg_result = _get_vg_info(l['vg_name'], vg_data)
                            data_set1['vg_size'] = vg_result['vg_size']
                            data_set1['vg_free'] = vg_result['vg_free']
                            data_set1['lv_count'] = vg_result['lv_count']
                            data_set1['pv_count'] = vg_result['pv_count']
                            pv_result = _get_pv_info(l['vg_name'], pv_data)
                            data_set1['pv_devices'] = pv_result['pv_devices']
                            data_set1['pv_fmt'] = pv_result['pv_fmt']
                            data_set1['pv_sizes'] = pv_result['pv_sizes']
                            data_set1['pv_free'] = pv_result['pv_free'] 
                            data_list.append(data_set1)
        
        
        #print(output_lvs[p])
        
                            
    #print(data_list)
    if "json_file" in kwargs:
        _write_json(data_list, kwargs["json_file"])
    else:
        _write_json(data_list)

    if "csv_file" in kwargs:
        _write_csv(data_list, kwargs["csv_file"])
    else:
        _write_csv(data_list, file="/tmp/diskinfo.csv")
    
    
    result.append(data_set)


       
    return system_diskinfo_list

def _get_vg_info(vg_name, vg_data):
    vg_info = dict()
    if isinstance(vg_data, dict):
        if len(vg_data["report"][0]["vg"]) > 0:
            for v in vg_data["report"][0]["vg"]:
                if vg_name == v['vg_name']:
                    vg_info['vg_name'] = v['vg_name']
                    vg_info['vg_size'] = v['vg_size']
                    vg_info['vg_free'] = v['vg_free']
                    vg_info['lv_count'] = v['lv_count']
                    vg_info['pv_count'] = v['pv_count']

    return vg_info

def _get_pv_info(vg_name, pv_data):
    pv_info = dict()
    pv_devices = ""
    pv_sizes = ""
    pv_frees = ""
    if isinstance(pv_data, dict):
        if len(pv_data["report"][0]["pv"]) > 0:
            for p in pv_data["report"][0]["pv"]:
                if vg_name == p['vg_name']:
                    pv_devices += p['pv_name'] + " "
                    pv_sizes += p['pv_size'] + " "
                    pv_frees += p['pv_free'] + " "
                    pv_info['pv_fmt'] = p['pv_fmt']

            pv_info['pv_devices'] = pv_devices
            pv_info['pv_sizes'] = pv_sizes
            pv_info['pv_free'] = pv_frees
    return pv_info

def _write_json(mydict, file="/tmp/diskinfo.json"):
    with open(file, 'w') as convert_file: 
     convert_file.write(json.dumps(mydict))

def _write_csv(final_list, file="/tmp/diskinfo.csv"):
    print("Writting to csv file!")
    if len(final_list) != 0:
        print("The csv file locates in {}".format(file))
        try:
            with open(file, 'w') as csvfile:
                a = 0
                for f in final_list:
                    if isinstance(f, dict):
                        if a == 0:
                            print("type {} q is: {}".format(type(f),f))
                            csv_columns = f.keys()
                            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)

                            writer.writeheader()
                            a += 1
                        writer.writerow(f)
                        
        except IOError:
            print("I/O error")

    return

def _getvgs(path, output_pvs):
    for r in output_pvs["report"]:
        for v in r["pv"]:
            if path == v["pv_name"]:
                return v["vg_name"]
    return

def _minion_presence_check(timeout=2, gather_job_timeout=10):
    print("checking minion presence... using timeout {}, gather_job_timeout: {}".format(timeout,gather_job_timeout))
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout])
    #print("Online minions: \n{}".format(online_minions))
    return online_minions


