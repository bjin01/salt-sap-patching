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

def run(timeout=2, gather_job_timeout=10):
    grains_info = []
    minion_list_without_poor_size = []
    minion_list_with_poor_size = []
    minion_list = _minion_presence_check(timeout, gather_job_timeout)
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
    for result in ret:
        grains_info.append(result)
        if isinstance(result, dict):
            for a, b in result.items():
                if b != "" or b == "ok":
                    minion_list_without_poor_size.append(a)
                if b == "no":
                    minion_list_with_poor_size.append(a)

    print("entire minion_list_without_poor_size {}".format(minion_list_without_poor_size))

    print("rebuild rpm DB.")
    ret_rpm = []
    ret_rpm_rebuild = local.cmd_iter_no_block(list(minion_list), 'cmd.run', ["rpm --rebuilddb"], tgt_type="list")
    for i in ret_rpm_rebuild:
        #print(i)
        ret_rpm.append(i)
        ret_rpm.remove(i)
    
    print("stop ds_agent.service")
    ret_stop_svc = []
    ret_stop_service = local.cmd_iter_no_block(list(minion_list), 'service.stop', ["postfix.service", "no_block=True"], tgt_type="list")
    for i in ret_stop_service:
        #print(i)
        ret_stop_svc.append(i)
        ret_stop_svc.remove(i)
    return minion_list_without_poor_size, minion_list_with_poor_size

def _minion_presence_check(timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout], print_event=False)
    return online_minions