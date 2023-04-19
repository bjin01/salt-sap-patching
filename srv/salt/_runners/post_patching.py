from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
from cryptography.fernet import Fernet
import atexit
import logging
import csv
import os
import salt.client
from salt.ext import six
import yaml

from datetime import datetime,  timedelta

# Below part is to supress undefinedvariable warnings in IDE for dunder dicts e.g. __salt__
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
log = logging.getLogger(__name__)

_sessions = {}


def __virtual__():
    '''
    Check for suse manager configuration in master config file
    or directory and load runner only if it is specified
    '''
    return True

def start(filename):
    
    with open(filename, 'r') as file:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
        minion_dict = yaml.load(file, Loader=yaml.FullLoader)

    local = salt.client.LocalClient()
    print("start ds_agent.service")
    ret_start_svc = []
    for a, b in minion_dict.items():
        print("{}: {}".format(a, b))
        ret_start_service = local.cmd_iter_no_block(list(b), 'service.start', ["ds_agent.service", "no_block=True"], tgt_type="list")
        for i in ret_start_service:
            #print(i)
            ret_start_svc.append(i)
            ret_start_svc.remove(i)
    return 

def stop(filename):
    
    with open(filename, 'r') as file:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
        minion_dict = yaml.load(file, Loader=yaml.FullLoader)

    local = salt.client.LocalClient()
    print("stop ds_agent.service")
    ret_stop_svc = []
    for a, b in minion_dict.items():
        print("{}: {}".format(a, b))
        ret_stop_service = local.cmd_iter_no_block(list(b), 'service.stop', ["ds_agent.service", "no_block=True"], tgt_type="list")
        for i in ret_stop_service:
            #print(i)
            ret_stop_svc.append(i)
            ret_stop_svc.remove(i)
    return

def set_pl(file, patchlevel):
    ret = dict()
    if not os.path.exists(file):
        ret["input_file"] = "File Not found: {}.".format(file)
        return ret

    with open(file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    post_patching_minions = []
    for a, b in data.items():
        post_patching_minions = b
        print("Preparing to set Patch Level for: {}: {}".format(a,post_patching_minions))
        if len(post_patching_minions) == 0:
            ret["comment"] = "No minions given."
            return ret

    local = salt.client.LocalClient()
        #print("minion_list: {}".format(list(minion_list)))
    ret_sync = []
    print("Sync modules to minions.")
    ret1 = local.cmd_batch(list(post_patching_minions), 'saltutil.sync_modules', tgt_type="list", batch='10%')
    for result in ret1:
        ret_sync.append(result)
        ret_sync.remove(result)
    
    print("Set patch level: {} on minions.".format(patchlevel))

    ret1 = local.cmd_batch(list(post_patching_minions), 'postpatching.set_patchlevel', [patchlevel], tgt_type="list", batch='10%')
    for result in ret1:
        ret_sync.append(result)

    return ret_sync

def report(file, csv_file="/srv/pillar/sumapatch/post_patching_report.csv"):
    ret = dict()
    if not os.path.exists(file):
        ret["input_file"] = "File Not found: {}.".format(file)
        return ret

    with open(file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    minion_list = []
    for a, b in data.items():
        print("Preparing to set Patch Level for: {}: {}".format(a,b))
        minion_list = b
        if len(minion_list) == 0:
            ret["comment"] = "no minions found."
            return ret
    
    local = salt.client.LocalClient()
    #print("minion_list: {}".format(list(minion_list)))
    ret_sync = []
    print("sync grains files to minions.")
    ret1 = local.cmd_batch(list(minion_list), 'saltutil.sync_grains', tgt_type="list", batch='10%')
    for result in ret1:
        ret_sync.append(result)
        ret_sync.remove(result)

    ret_refresh = []
    print("refresh grains on minions.")
    ret2 = local.cmd_batch(list(minion_list), 'saltutil.refresh_grains', tgt_type="list", batch='10%')
    for result in ret2:
        ret_refresh.append(result)
        ret_refresh.remove(result)
    
    print("Collect OS Version from minions.")
    ret["OS_Version"] = []
    ret3 = local.cmd_batch(list(minion_list), 'grains.get', ["oscodename"], tgt_type="list", batch='10%')
    for result in ret3:
        ret["OS_Version"].append(result)
    
    print("Collect Patch Level from minions.")
    ret["Patch_Level"] = []
    ret4 = local.cmd_batch(list(minion_list), 'grains.get', ["root_info:SYSPL"], tgt_type="list", batch='10%')
    for result in ret4:
        ret["Patch_Level"].append(result)
    
    print("Collect uname from minions.")
    ret["kernel"] = []
    ret5 = local.cmd_batch(list(minion_list), 'cmd.run', ["uname -r"], tgt_type="list", batch='10%')
    for result in ret5:
        ret["kernel"].append(result)
    
    print("Collect uptime from minions.")
    ret["uptime"] = []
    ret6 = local.cmd_batch(list(minion_list), 'cmd.run', ["uptime"], tgt_type="list", batch='10%')
    for result in ret6:
        if isinstance(result, dict):
            for a, b in result.items():
                val = b.split(",", 1)
                result = {a: val[0]}
            ret["uptime"].append(result)
        else:
            ret["uptime"].append(result)
    
    final_ret = dict()
    for x, y in ret.items():
        if len(y) > 0:
            for s in y:
                for host, _ in s.items():
                    final_ret[host] = {}

    for x, y in ret.items():

        if x == "uptime":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        final_ret[host].update({"uptime": value})
    
        if x == "kernel":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        print("{}: {}".format(host, value))
                        #final_ret[host] = {}
                        final_ret[host].update({"kernel": value})
        if x == "OS_Version":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        #final_ret[host] = {}
                        final_ret[host].update({"OS_Version": value})
        if x == "Patch_Level":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        #final_ret[host] = {}
                        final_ret[host].update({"Patch_Level": value})
 
    final_ret["csv_file"] = _write_csv(final_ret, csv_file)
    return final_ret

def _write_csv(dictionary, csv_file="/srv/pillar/sumapatch/post_patching_report.csv"):
    
    with open(csv_file, 'w+', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Server Name', 'OS Version', 'Patch Level', 'Kernel Version', 'Uptime'])
        for server_name, details in dictionary.items():
            writer.writerow([server_name, details['OS_Version'], details['Patch_Level'], details['kernel'], details['uptime']])
    return csv_file
    