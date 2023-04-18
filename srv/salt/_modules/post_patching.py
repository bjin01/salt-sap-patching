# -*- coding: utf-8 -*-
'''
A saltstack execution module written for post patching tasks.

.. versionadded:: pending

:maintainer:    Bo Jin <bo.jin@suse.com>
:maturity:      alpha
:platform:      SLES-for-SAP 15SP4 and newer
:depends:       python: xml, salt

:configuration: This module requires salt-minion to be installed.

.. code-block:: yaml

'''

from __future__ import absolute_import, unicode_literals, print_function
import logging
from salt import exceptions
import os
import re

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
    __context__: Any = None

__virtualname__ = 'postpatching'
srvinfo_file = "/admin/config/srvinfo"
root_info_file = "/root/info"

LOGGER = logging.getLogger(__name__)

def __virtual__():    
    return __virtualname__

def set_patchlevel(syspl, srvinfo=srvinfo_file, root_info=root_info_file):
    '''
    salt "*" postpatching.set_patchlevel 2023-Q2
    '''
    ret = dict()
    if not os.path.exists(srvinfo):
        ret["srvinfo"] = "File Not found."
        __context__["retcode"] = 42
    else:
        ret["srvinfo"] = set_srvinfo(syspl, srvinfo=srvinfo_file)

    if not os.path.exists(root_info):
        ret["root_info"] = "File Not found."
        __context__["retcode"] = 42
    else:
        ret["root_info"] = set_rootinfo(syspl, root_info=root_info_file)

    return ret

def set_rootinfo(val, root_info=root_info_file):
    ret = dict()
    with open(root_info, "r") as f:
        # read the content of the file into a list
        content = f.readlines()

    # loop through the list and replace the value of SYSPL
    for i in range(len(content)):
        if re.findall(r"^SYSPL", content[i]):
            # replace the old value with the new value
            content[i] = f"SYSPL        = \"{val}\"\n"
            ret["root_info"] = content[i]

    # save the modified content back to the file
    with open(root_info, "w") as f:
        f.writelines(content)
    
    if not "root_info" in ret.keys():
        ret = "No matching SYSPL found."
        __context__["retcode"] = 42
        return ret
    
    return ret["root_info"]

def set_srvinfo(val, srvinfo=srvinfo_file):
    ret = dict()
    with open(srvinfo, "r") as f:
        # read the content of the file into a list
        content = f.readlines()

    # loop through the list and replace the value of SYSPL
    for i in range(len(content)):
        if re.findall(r"^INFO_SYSPL", content[i]):
            # replace the old value with the new value
            content[i] = f"INFO_SYSPL::{val}\n"
            ret["srvinfo"] = content[i]

    # save the modified content back to the file
    with open(srvinfo, "w") as f:
        f.writelines(content)
    
    if not "srvinfo" in ret.keys():
        ret = "No matching INFO_SYSPL found."
        __context__["retcode"] = 42
        return ret
    
    return ret["srvinfo"]
