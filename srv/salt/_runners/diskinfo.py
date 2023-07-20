from __future__ import absolute_import, print_function, unicode_literals
from cryptography.fernet import Fernet
# Import python libs
import logging
import json
import os
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

def list(**kwargs):

    '''
    This is a runner module.
    List disk information and output into csv file. 
    This module will make a minion presence check prior gathering disk information.
    The minion presence check avoids module stuck due to offline minions.

    Keyword arguments: The two keyword args specify the salt-run manage.up timeouts.
    Default is: timeout=2 gather_job_timeout=10

    CLI Example:

    .. code-block:: bash

        salt-run diskinfo.list

        
        salt-run diskinfo.list timeout=2 gather_job_timeout=15
    '''

    if "timeout" in kwargs and "gather_job_timeout" in kwargs:
        present_minions = _minion_presence_check(timeout=kwargs["timeout"], gather_job_timeout=kwargs["gather_job_timeout"])
    else:
        present_minions = _minion_presence_check()
    #present_minions = [""]

    fields = ["size", "type", "path", "fstype", "fssize", "fsused", "fsuse%", "fsavail", "mountpoint", "type", "uuid"]
    system_diskinfo_list = []
    
    for p in present_minions:        
        print("Collecting diskinfo via salt at {}".format(p))
        output_lsblk = __salt__['salt.execute'](p, 'cmd.run', 
                    ["/usr/bin/lsblk --json -p -o PATH,PARTTYPENAME,SIZE,FSTYPE,FSSIZE,FSUSED,FSUSE%,FSAVAIL,MOUNTPOINT,TYPE,UUID"])
        output_pvs = __salt__['salt.execute'](p, 'cmd.run', 
                    ["pvs --reportformat json"])
        if output_lsblk[p] != "":
            #print(output_lsblk[p])
            json_lsblk_out = json.loads(output_lsblk[p])

        for o in json_lsblk_out["blockdevices"]:
            system_diskinfo = {}
            
            #if o["parttypename"] == "Linux filesystem" and o["type"] == "part":
            if o["uuid"] != "" and o["type"] == "part":
                system_diskinfo[o['uuid']] = {}
                system_diskinfo[o['uuid']]["hostname"] = p
                system_diskinfo[o['uuid']]["path"] = o["path"]
                system_diskinfo[o['uuid']]["lvm-group"] = "None"
                for f in fields:
                    if "mountpoint" in f:
                        if type(o[f]) ==  list:
                            if len(o[f]) == 1:
                                system_diskinfo[o['uuid']][f] = o[f][0]
                            else:
                                system_diskinfo[o['uuid']][f] = o[f]
                        else:
                            system_diskinfo[o['uuid']][f] = o[f]
                    else:
                        system_diskinfo[o['uuid']][f] = o[f]
                system_diskinfo_list.append(system_diskinfo)
                continue

            if o["parttypename"] == "Linux LVM" or o["fstype"] == "LVM2_member":
                vgs = _getvgs(o["path"], json.loads(output_pvs[p]))
                system_diskinfo[o['uuid']] = {}
                system_diskinfo[o['uuid']]["hostname"] = p
                system_diskinfo[o['uuid']]["lvm-group"] = ""
                """ if vgs and not vgs == "":
                    print(vgs)
                    for k in json_lsblk_out["blockdevices"]:
                        dev_mapper_path = "/dev/mapper/{}".format(vgs)
                        if dev_mapper_path in k["path"]:
                            system_diskinfo[o['uuid']] = {}
                            system_diskinfo[o['uuid']]["hostname"] = p
                            system_diskinfo[o['uuid']]["path"] = o["path"]
                            system_diskinfo[o['uuid']]["lvm-group"] = vgs """
                if type(vgs) ==  list:
                    for s in vgs:
                        system_diskinfo[o['uuid']]["lvm-group"] += s + "; "
                        #print(system_diskinfo[o['uuid']]["lvm-group"])
                else:
                    system_diskinfo[o['uuid']]["lvm-group"] = vgs
                    #print(system_diskinfo[o['uuid']]["lvm-group"])

                for f in fields:
                    if "mountpoint" in f:
                        if type(o[f]) ==  list:
                            if len(o[f]) == 1:
                                system_diskinfo[o['uuid']][f] = o[f][0]
                            else:
                                system_diskinfo[o['uuid']][f] = o[f]
                        else:
                            system_diskinfo[o['uuid']][f] = o[f]
                    else:
                        system_diskinfo[o['uuid']][f] = o[f]

                system_diskinfo_list.append(system_diskinfo)
            
            if o["type"] == "lvm":
                system_diskinfo[o['uuid']] = {}
                system_diskinfo[o['uuid']]["hostname"] = p
                system_diskinfo[o['uuid']]["path"] = o["path"]
                system_diskinfo[o['uuid']]["lvm-group"] = ""

                #"/dev/mapper/tempvg-lv_temp"
                if "/dev/mapper/" in o["path"]:
                    val1 = o["path"].split("/")
                    val2 = val1[len(val1)-1]
                    val3 = val2.split("-", 2)
                    vg = val3[0]
                    lvm = val3[1]
                    #print("vg is: {}, lvm is: {}".format(vg, lvm))
                    system_diskinfo[o['uuid']]["lvm-group"] = vg

                for f in fields:
                    if "mountpoint" in f:
                        if type(o[f]) ==  list:
                            if len(o[f]) == 1:
                                system_diskinfo[o['uuid']][f] = o[f][0]
                            else:
                                system_diskinfo[o['uuid']][f] = o[f]
                        else:
                            system_diskinfo[o['uuid']][f] = o[f]
                    else:
                        system_diskinfo[o['uuid']][f] = o[f]

                system_diskinfo_list.append(system_diskinfo)
                                
                            
        system_diskinfo_list.append(system_diskinfo)
    
    _write_csv(system_diskinfo_list)
    return system_diskinfo_list

def _write_csv(final_list, file="/tmp/diskinfo.csv"):
    print("Writting to csv file!")
    if len(final_list) != 0:
        print("The csv file locates in {}".format(file))
        try:
            with open(file, 'w') as csvfile:
                a = 0
                for f in final_list:
                    for p, q in f.items():
                        if a == 0:
                            csv_columns = q.keys()
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
    print("checking minion presence... using timeout {}, gather_job_timeout: {}".format(timeout,gather_job_timeout))
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout])
    #print("Online minions: \n{}".format(online_minions))
    return online_minions


