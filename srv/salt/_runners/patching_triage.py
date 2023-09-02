
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
from cryptography.fernet import Fernet
import logging
import csv
import os
import salt.client
import six
import json
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



def _minion_presence_check(minion_list, timeout=5, gather_job_timeout=15):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    """ timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout) """
    minion_status_list = runner.cmd('manage.status', ["tgt={}".format(minion_list), "tgt_type=list", timeout, gather_job_timeout], print_event=False)

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
            minion_status_list = _minion_presence_check(b, timeout=5, gather_job_timeout=15)
            b = minion_status_list["up"]
       
        ret_refresh = []
        print("run state.highstate. It takes some time.")
        ret2 = local.cmd_batch(list(b), 'state.highstate', tgt_type="list", batch='10%')
        for result in ret2:
            ret_refresh.append(result)
            ret_refresh.remove(result)

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