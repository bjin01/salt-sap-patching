# -*- coding: utf-8 -*-
'''
Patching Preparation module
================

.. versionadded:: 3004-150400.8.17.7

Runner for running few pre-patching steps

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import atexit
import logging
import os

import subprocess
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
file_handler = logging.FileHandler('/var/log/patching/patching.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

log.addHandler(file_handler)

_sessions = {}


def __virtual__():
    return True

def _get_diff(li1, li2):
    li_dif = [i for i in li1 + li2 if i not in li1 or i not in li2]
    return li_dif

def run(suma_minion_list, state_name="", timeout=2, gather_job_timeout=10):
    masterplan_info = []
    minion_list_without_poor_size = []
    minion_list_with_poor_size = []
    final_minion_list = dict()
    #minion_list = ["pxesap01.bo2go.home", "pxesap02.bo2go.home", "jupiter.bo2go.home", "saturn"]
    #minion_list = ["jupiter.bo2go.home", "saturn", "pxesap01.bo2go.home"]
    minion_list = _minion_presence_check(suma_minion_list, timeout, gather_job_timeout)
    offline_minions = []
    offline_minions = _get_diff(suma_minion_list, minion_list)
    final_minion_list["offline_minions"] = offline_minions
    #minion_list = []
    local = salt.client.LocalClient()
    #print("minion_list: {}".format(list(minion_list)))
    ret_sync = []
    print("sync grains files to minions.")
    ret1 = local.cmd_batch(list(minion_list), 'saltutil.sync_grains', tgt_type="list", batch='10%')
    for result in ret1:
        
        ret_sync.append(result)
        ret_sync.remove(result)
    #print("ret_sync {}".format(ret_sync))

    ret_refresh = []
    print("refresh grains on minions.")
    ret2 = local.cmd_batch(list(minion_list), 'saltutil.refresh_grains', tgt_type="list", batch='10%')
    for result in ret2:
        ret_refresh.append(result)
        ret_refresh.remove(result)
    #print("ret_refresh {}".format(ret_refresh))

    print("get btrfs grains on minions.")
    ret = local.cmd_batch(list(minion_list), 'grains.get', ["btrfs:for_patching"], tgt_type="list", batch='10%')
    #ret = local.cmd_iter(list(minion_list), 'grains.get', ["btrfs:for_patching"], tgt_type="list")
    for result in ret:
        
        if isinstance(result, dict):
            for a, b in result.items():
                if b != "" or b == "ok":
                    minion_list_without_poor_size.append(a)
                    
                if b == "no":
                    minion_list_with_poor_size.append(a)
                    minion_list.remove(a)

    
    minion_list_no_patch = []
    print("Evaluate no_patch exceptions through grains.")
    ret = local.cmd_batch(list(minion_list), 'grains.get', ["no_patch"], tgt_type="list", batch='10%')
    #ret = local.cmd_iter(list(minion_list), 'grains.get', ["btrfs:for_patching"], tgt_type="list")
    for result in ret:
        
        if isinstance(result, dict):
            for a, b in result.items():
                if b:
                    minion_list_no_patch.append(a)
                    minion_list.remove(a)
                

    ret = local.cmd_batch(list(minion_list), 'grains.get', ["srvinfo:INFO_MASTERPLAN"], tgt_type="list", batch='10%')
    for result in ret:
        masterplan_info.append(result)

    if state_name != "":
        print("apply state {}.".format(state_name))
        not_needed = local.cmd_iter_no_block(list(minion_list), 'state.apply', [state_name], tgt_type="list")
        for w in not_needed:
            x = []
            x.append(w)

    print("rebuild rpm DB.")
    not_needed = local.cmd_iter_no_block(list(minion_list), 'cmd.run', ["rpm --rebuilddb"], tgt_type="list")
    for w in not_needed:
        x = []
        x.append(w)

    print("stop ds_agent.service")
    not_needed = local.cmd_iter_no_block(list(minion_list), 'service.stop', ["ds_agent.service", "no_block=True"], tgt_type="list")
    for w in not_needed:
        x = []
        x.append(w)
    
    final_minion_list["qualified_minions"] = minion_list
    final_minion_list["btrfs_disqualified"] = minion_list_with_poor_size
    final_minion_list["no_patch_execptions"] = minion_list_no_patch
    final_minion_list["masterplan_list"] = masterplan_info
    
    return final_minion_list

def _minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [minion_list, "tgt_type=list", timeout, gather_job_timeout], print_event=False)

    return online_minions