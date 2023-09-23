from __future__ import absolute_import, unicode_literals, print_function
import logging
import json
import salt.config
import salt.loader
from salt import exceptions
import salt.utils.path
from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
    __context__: Any = None
    __grains__: Any = None

__virtualname__ = 'mytest'

def __virtual__():    
    return __virtualname__


__opts__ = salt.config.minion_config('/etc/venv-salt-minion/minion')
__grains__ = salt.loader.grains(__opts__)

def get_grains_id():
    print(__grains__['id'])
    ret = dict()
    ret["grains"] = __grains__['id']
    ret["opts"] = __opts__
    return ret
