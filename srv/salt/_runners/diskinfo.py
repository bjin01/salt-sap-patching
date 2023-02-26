from __future__ import absolute_import, print_function, unicode_literals
from cryptography.fernet import Fernet
# Import python libs
import logging
import json
import os
import csv
import salt.client
from salt.ext import six
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

def list(**kwargs):

    if "presence_check_timeouts" in kwargs:
        present_minions = _minion_presence_check(kwargs['presence_check_timeouts']['timeout'],
                                                 kwargs['presence_check_timeouts']['gather_job_timeout'])
    else:
        present_minions = _minion_presence_check()
    #present_minions = ["pxesap02.bo2go.home", "pxesap01.bo2go.home"]

    fields = ["type", "path", "fstype", "fssize", "fsused", "fsuse%", "fsavail", "mountpoints", "type"]
    system_diskinfo_list = []
    
    for p in present_minions:        
        output_lsblk = __salt__['salt.execute'](p, 'cmd.run', 
                    ["lsblk --json -p -o PATH,PARTTYPENAME,FSTYPE,FSSIZE,FSUSED,FSUSE%,FSAVAIL,MOUNTPOINTS,TYPE,UUID"])
        output_pvs = __salt__['salt.execute'](p, 'cmd.run', 
                    ["pvs --reportformat json"])
        json_lsblk_out = json.loads(output_lsblk[p])

        for o in json_lsblk_out["blockdevices"]:
            system_diskinfo = {}
            if o["parttypename"] == "Linux filesystem" and o["type"] == "part":
                system_diskinfo[o['uuid']] = {}
                system_diskinfo[o['uuid']]["hostname"] = p
                system_diskinfo[o['uuid']]["path"] = o["path"]
                system_diskinfo[o['uuid']]["lvm-group"] = "None"
                for f in fields:
                    if f == "mountpoints":
                        if len(o[f]) == 1:
                            system_diskinfo[o['uuid']][f] = o[f][0]
                        else:
                            system_diskinfo[o['uuid']][f] = o[f]
                    else:
                        system_diskinfo[o['uuid']][f] = o[f]
                system_diskinfo_list.append(system_diskinfo)
                continue

            if o["parttypename"] == "Linux LVM" and o["type"] == "part":
                vgs = _getvgs(o["path"], json.loads(output_pvs[p]))
                system_diskinfo[o['uuid']] = {}
                system_diskinfo[o['uuid']]["hostname"] = p
                if vgs and not vgs == "":
                    for k in json_lsblk_out["blockdevices"]:
                        dev_mapper_path = "/dev/mapper/{}".format(vgs)
                        if dev_mapper_path in k["path"]:
                            system_diskinfo[o['uuid']] = {}
                            system_diskinfo[o['uuid']]["hostname"] = p
                            system_diskinfo[o['uuid']]["path"] = o["path"]
                            system_diskinfo[o['uuid']]["lvm-group"] = vgs
                            #print(vgs)
                            for f in fields:
                                if f == "mountpoints":
                                    if len(k[f]) == 1:
                                        system_diskinfo[o['uuid']][f] = k[f][0]
                                    else:
                                        system_diskinfo[o['uuid']][f] = k[f]
                                else:
                                    system_diskinfo[o['uuid']][f] = k[f]
                                #print("{}: {}".format(f,k[f]))
                system_diskinfo_list.append(system_diskinfo)
                                
                            
        system_diskinfo_list.append(system_diskinfo)
    #print(system_diskinfo_list)
    _write_csv(system_diskinfo_list)
    return True

def _write_csv(final_list, file="/tmp/diskinfo.csv"):
    if len(final_list) != 0:
        print("The csv file locates in {}".format(file))
        try:
            with open(file, 'w') as csvfile:
                a = 0
                for f in final_list:
                    for p, q in f.items():
                        if a == 0:
                            csv_columns = q.keys()
                            #print(csv_columns)
                            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)

                            writer.writeheader()
                            a += 1
                        writer.writerow(q)
                        
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
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout])
    #print("Online minions: \n{}".format(online_minions))
    return online_minions