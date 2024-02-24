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
    accepted_minions = wheel.cmd('key.list', ['accepted'], print_event=False)
    #print(accepted_minions)
    return accepted_minions

def _minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    accepted_minions = _minion_accepted()
    for m in list(minion_list):
        if m not in accepted_minions["minions"]:
            #print("Minion {} not accepted.".format(m))
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




def report(file="", csv_file="/srv/pillar/sumapatch/post_patching_report.csv", all_server=False, presence_check=False):
    """
    Collect information via grains and suse manager api and write to a csv file.

    .. note::

        This runner module uses salt execution module baseproduct.get that needs to be deployed to the minions.
        Following information and columns will be collected:
        ['Name', 'status', 'Operating System (baseproduct),', 'Last Checkin', 'Kernel', 'Uptime']

    CLI Examples:

    .. code-block:: bash
        collect from a given yaml file with minion names:
        salt-run csv.report file=minions.list csv_file=/tmp/csv.txt presence_check=True

        Or collect from all minions from the salt-master host.
        salt-run csv.report csv_file /tmp/csv.txt all_server=True presence_check=True
        
    """
    ret = dict()
    ret_offlines = dict()
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

    """ print("Collecting clm project and stage info from minions.") 
    runner = salt.runner.RunnerClient(__opts__)
    clm_stage_info = runner.cmd('clm_info.find_clm_stage', ["input_file={}".format(file)], print_event=True)
    if len(clm_stage_info) == 0:
        print("No clm info found from SUSE Manager.") """        

    print("collect last checkin time from suse manager.")
    ret["Last Checkin"] = []
    ret_offlines["Last Checkin"] = []
    all_minions_suma = [x for n in (minion_list,offline_minions) for x in n]
    runner = salt.runner.RunnerClient(__opts__)
    last_checkin = runner.cmd('lastcheckin.get', ["minion_list={}".format(all_minions_suma)], print_event=False)
    for l in last_checkin:
        if l["name"] in minion_list:
            temp_dict = dict()
            temp_dict[l["name"]] = l["last_checkin"]
            ret["Last Checkin"].append(temp_dict)
        
        if l["name"] in offline_minions:
            temp_dict = dict()
            temp_dict[l["name"]] = l["last_checkin"]
            ret_offlines["Last Checkin"].append(temp_dict)

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
    
      
    print("Collect SUSE base product name.")
    ret["baseproduct"] = []
    ret4 = local.cmd_batch(list(minion_list), 'baseproduct.get', [], tgt_type="list", batch='10%')
    for result in ret4:
        ret["baseproduct"].append(result)
    
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

    for x, y in ret.items():

        if x == "Last Checkin":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        final_ret[host].update({"Last Checkin": value})

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
        if x == "baseproduct":
            if len(y) > 0:
                for s in y:
                    for host, value in s.items():
                        #final_ret[host] = {}
                        final_ret[host].update({"baseproduct": value})
        
        
 
    final_ret["z_csv_file"] = _write_csv(final_ret, csv_file, offline_minions=ret_offlines)
    return final_ret

def _write_csv(dictionary, csv_file="/srv/pillar/sumapatch/post_patching_report.csv", offline_minions={}):
    #print(dictionary.keys())
    with open(csv_file, 'w+', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Name', 'status', 'Operating System,', 'Last Checkin', 'Subscriptions', 'Owner', 'Kernel', 'Latest kernel available', 'Uptime'])
        for server_name, details in dictionary.items():
            if "kernel" not in details.keys() or not details['kernel']:
                details['kernel'] = "n/a"
            
            if "uptime" not in details.keys() or not details['uptime']:
                details['uptime'] = "n/a"

            if "baseproduct" not in details.keys() or not details['baseproduct']:
                details['baseproduct'] = "n/a"

            if "Owner" not in details.keys() or not details['Owner']:
                details['Owner'] = "n/a"

            if "Subscriptions" not in details.keys() or not details['Subscriptions']:
                details['Subscriptions'] = "n/a"

            if "Last Checkin" not in details.keys() or not details['Last Checkin']:
                details['Last Checkin'] = "n/a"
            
            if "status" not in details.keys() or not details['status']:
                details['status'] = "n/a"

            if "Latest kernel available" not in details.keys() or not details['Latest kernel available']:
                details['Latest kernel available'] = "n/a"

            #print(details)
            writer.writerow([server_name, "online", details['baseproduct'], details["Last Checkin"], 
                             details['Subscriptions'], details['Owner'], details['kernel'], details['Latest kernel available'], details['uptime']])
        if isinstance(offline_minions["Last Checkin"], list) and len(offline_minions["Last Checkin"]) > 0:
            for o in offline_minions["Last Checkin"]:
                if isinstance(o, dict):
                    for h, last_checkin in o.items():
                        host = h
                        if not last_checkin:
                            last_checkin = "n/a"
                    writer.writerow([host, "offline", "n/a", last_checkin, "n/a", "n/a", "n/a", "n/a", "n/a"])

    return csv_file
    