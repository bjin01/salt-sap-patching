from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
from cryptography.fernet import Fernet
import logging
import csv
import os
import salt.client
import six
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

def _minion_accepted():
    import salt.wheel

    wheel = salt.wheel.WheelClient(__opts__)
    accepted_minions = wheel.cmd('key.list', ['accepted'])
    print(accepted_minions)
    return accepted_minions

def _minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    accepted_minions = _minion_accepted()
    for m in list(minion_list):
        if m not in accepted_minions["minions"]:
            print("Minion {} not accepted.".format(m))
            minion_list.remove(m)


    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    """ timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout) """
    minion_status_list = runner.cmd('manage.status', ["tgt={}".format(minion_list), "tgt_type=list", timeout, gather_job_timeout], print_event=False)

    return minion_status_list

def _all_minion_presence_check(timeout=2, gather_job_timeout=10):
    print("checking minion presence from all systems...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    """ timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout) """
    minion_status_list = runner.cmd('manage.status', ["tgt=*", "tgt_type=glob", timeout, gather_job_timeout], print_event=False)

    return minion_status_list

def start(filename, state_name="", presence_check=False):
    
    with open(filename, 'r') as file:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
        minion_dict = yaml.load(file, Loader=yaml.FullLoader)

    local = salt.client.LocalClient()
    
    for a, b in minion_dict.items():
        #print("{}: {}".format(a, b))
        if presence_check:
            minion_status_list = _minion_presence_check(b, timeout=2, gather_job_timeout=10)
            b = minion_status_list["up"]
        print("start ds_agent.service")
        not_needed = local.cmd_iter_no_block(list(b), 'service.start', ["ds_agent.service", "no_block=True"], tgt_type="list")
        for w in not_needed:
            x = []
            x.append(w)

        if state_name != "":
            print("apply state: {}".format(state_name))
            not_needed = local.cmd_iter_no_block(list(b), 'state.apply', [state_name], tgt_type="list")
            for w in not_needed:
                x = []
                x.append(w)
    
        try:
            if presence_check:
                if len(minion_status_list["down"]) != 0:
                    print("Following minions is or are down:")
                    print(minion_status_list["down"])
                    return minion_status_list["down"]
                else:
                    print("All given minions are online.")
                    return True
        except:
            return True
    

def stop(filename, state_name="", presence_check=False):
    
    with open(filename, 'r') as file:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
        minion_dict = yaml.load(file, Loader=yaml.FullLoader)

    local = salt.client.LocalClient()
    print("stop ds_agent.service")
    for a, b in minion_dict.items():
        if presence_check:
            minion_status_list = _minion_presence_check(b, timeout=2, gather_job_timeout=10)
            b = minion_status_list["up"]
        #print("{}: {}".format(a, b))
        not_needed = local.cmd_iter_no_block(list(b), 'service.stop', ["ds_agent.service", "no_block=True"], tgt_type="list")
        for w in not_needed:
            x = []
            x.append(w)

        if state_name != "":
            print("execute state: {}.".format(state_name))
            not_needed = local.cmd_iter_no_block(list(b), 'state.apply', [state_name], tgt_type="list")
            for w in not_needed:
                x = []
                x.append(w)
    
    try:
        if presence_check:
            if len(minion_status_list["down"]) != 0:
                print("Following minions is or are down:")
                print(minion_status_list["down"])
                return minion_status_list["down"]
            else:
                print("All given minions are online.")
                return True
    except:
        return True
    return True

def set_pl(file, patchlevel, presence_check=False):
    ret = dict()
    if not os.path.exists(file):
        ret["input_file"] = "File Not found: {}.".format(file)
        return ret

    with open(file) as f:
        data = yaml.load(f, Loader=yaml.FullLoader)

    post_patching_minions = []
    for a, b in data.items():
        if presence_check:
            minion_status_list = _minion_presence_check(b, timeout=2, gather_job_timeout=10)
            b = minion_status_list["up"]
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
    
    ret_refresh = []
    print("refresh grains on minions.")
    ret2 = local.cmd_batch(list(post_patching_minions), 'saltutil.refresh_grains', tgt_type="list", batch='10%')
    for result in ret2:
        ret_refresh.append(result)
        ret_refresh.remove(result)

    try:
        if presence_check:
            if len(minion_status_list["down"]) != 0:
                print("Following minions is or are down:")
                print(minion_status_list["down"])
            else:
                print("All given minions are online.")
    except Exception as e: print(e)
        

    return ret_sync

def _get_staging_value(result):
    staging_value = {}
    
    if isinstance(result, dict):
        for a, b in result.items():
            hostname = a
            values = []
            if len(b) > 0:
                values = str(b).split("-")
            else:
                staging_value[hostname] = "No masterplan found"
                return staging_value

            # Check if there are at least 3 values and the 3rd value has at least 2 letters
            if len(values) >= 3 and len(values[2]) == 2:
                third_value_second_letter = values[2][1]  # Get the 2nd letter of the 3rd value

                # Check the letter and assign the corresponding output
                if third_value_second_letter == 'a':
                    staging_value[hostname] = "Abnahme"
                elif third_value_second_letter == 't':
                    staging_value[hostname] = "Test"
                elif third_value_second_letter == 'p':
                    staging_value[hostname] = "Prod"
                else:
                    staging_value[hostname] = third_value_second_letter
            else:
                staging_value[hostname] = "Invalid input format."

    return staging_value

def report(file, csv_file="/srv/pillar/sumapatch/post_patching_report.csv", all_server=False, presence_check=False):
    ret = dict()
    minion_list = []
    offline_minions = []
    if not all_server:
        if not os.path.exists(file):
            ret["input_file"] = "File Not found: {}.".format(file)
            return ret

        with open(file) as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
        
        for a, b in data.items():
            if presence_check:
                minion_status_list = _minion_presence_check(b, timeout=2, gather_job_timeout=10)
                minion_list = minion_status_list["up"]
                #print("online minions: {}".format(minion_list))
                offline_minions = minion_status_list["down"]
        
        
    else:
        minion_status_list = _all_minion_presence_check(timeout=2, gather_job_timeout=10)
        minion_list = minion_status_list["up"]
        offline_minions = minion_status_list["down"]

    if len(minion_list) == 0:
        ret["comment"] = "no minions found."
        return ret

    print("Collecting clm project and stage info from minions.") 
    runner = salt.runner.RunnerClient(__opts__)
    clm_stage_info = runner.cmd('clm_info.find_clm_stage', ["input_file={}".format(file)], print_event=True)
    if len(clm_stage_info) == 0:
        print("No clm info found from SUSE Manager.")               

    
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
    
    print("Collect no_patch from minions.")
    ret["no_patch"] = []
    ret3 = local.cmd_batch(list(minion_list), 'grains.get', ["no_patch"], tgt_type="list", batch='10%')
    for result in ret3:
        ret["no_patch"].append(result)
    
    print("Collect master plan and staging info from minions.")
    ret["Master_Plan"] = []
    ret["Staging"] = []
    ret_masterplan = local.cmd_batch(list(minion_list), 'grains.get', ["srvinfo:INFO_MASTERPLAN"], tgt_type="list", batch='10%')
    for result in ret_masterplan:
        ret["Staging"].append(_get_staging_value(result))
        ret["Master_Plan"].append(result)

    print("Collect Patch Level from minions.")
    ret["Patch_Level"] = []
    ret4 = local.cmd_batch(list(minion_list), 'grains.get', ["root_info:SYSPL"], tgt_type="list", batch='10%')
    for result in ret4:
        ret["Patch_Level"].append(result)
    
    print("Collect kernel version from minions.")
    ret["kernel"] = []
    ret5 = local.cmd_batch(list(minion_list), 'grains.get', ["kernelrelease"], tgt_type="list", batch='10%')
    for result in ret5:
        ret["kernel"].append(result)
    
    print("Collect uptime from minions.")
    ret["uptime"] = []
    ret6 = local.cmd_batch(list(minion_list), 'cmd.run', ["uptime"], tgt_type="list", batch='10%')
    for result in ret6:
        if isinstance(result, dict):
            for a, b in result.items():
                if isinstance(b, str):
                    val = b.split(",", 1)
                    result = {a: val[0]}
                else:
                    result = {a: "no result"}
            ret["uptime"].append(result)
        else:
            ret["uptime"].append(result)
    
    final_ret = dict()
    for x, y in ret.items():
        if len(y) > 0:
            for s in y:
                for host, _ in s.items():
                    final_ret[host] = {}

    if len(clm_stage_info) > 0:
        for clm_data in clm_stage_info:
            for host, clm in clm_data.items():
                if host in minion_list:
                    if clm["clm_project"] != "":
                        final_ret[host].update({"clm_project": clm["clm_project"]})
                        final_ret[host].update({"clm_stage": clm["clm_stage"]})
                    else:
                        final_ret[host].update({"clm_project": ""})
                        final_ret[host].update({"clm_stage": ""})

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
        
        if x == "no_patch":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        print("{}: {}".format(host, value))
                        #final_ret[host] = {}
                        if value == True:
                            final_ret[host].update({"no_patch": "True"})
                        elif value == False:
                            final_ret[host].update({"no_patch": "False"})
                        else:
                            final_ret[host].update({"no_patch": "not set"})
        
        if x == "Master_Plan":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        #final_ret[host] = {}
                        final_ret[host].update({"Master_Plan": value})
        
        if x == "Staging":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        #final_ret[host] = {}
                        final_ret[host].update({"Staging": value})
                        
        if x == "Patch_Level":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        #final_ret[host] = {}
                        final_ret[host].update({"Patch_Level": value})
 
    final_ret["z_csv_file"] = _write_csv(final_ret, csv_file, offline_minions=offline_minions)
    return final_ret

def _write_csv(dictionary, csv_file="/srv/pillar/sumapatch/post_patching_report.csv", offline_minions=[]):
    #print(dictionary.keys())
    with open(csv_file, 'w+', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Server Name', 'status',  'OS Version', 'no_patch', 'Master_Plan', 'Staging', 'clm_project', 'clm_stage', 'Patch Level', 'Kernel Version', 'Uptime'])
        for server_name, details in dictionary.items():
            #print(details)
            writer.writerow([server_name, "online", details['OS_Version'], details["no_patch"], details['Master_Plan'], details['Staging'], details['clm_project'], details['clm_stage'], details['Patch_Level'], details['kernel'], details['uptime']])
        if len(offline_minions) > 0:
            for down_minion in offline_minions:
                writer.writerow([down_minion, "offline", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"])

    return csv_file
    