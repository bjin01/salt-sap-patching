from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
from cryptography.fernet import Fernet
import atexit
import logging
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
