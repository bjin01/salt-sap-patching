# custom_module.py


from __future__ import absolute_import, unicode_literals, print_function
import logging
import subprocess
import xml.etree.ElementTree as ET
from salt import exceptions
import salt.utils.path


from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
    __context__: Any = None

__virtualname__ = 'find_zypper'

LOGGER = logging.getLogger(__name__)

def __virtual__():    
    return __virtualname__

def run():
    command = "ps aux | grep zypper | grep -v grep"
    try:
        result = subprocess.check_output(command, shell=True, universal_newlines=True)
        if "Error" in result or not result.strip():
            return True
        return False
    except subprocess.CalledProcessError as e:
        
        e_str = str(e)  # Convert the exception message to a string
        
        if "returned non-zero exit status" in e_str:
            return True
        return False

def _run_zypper_xmlout_lu():
    try:
        command = "zypper --xmlout lu"
        result = subprocess.check_output(command, shell=True, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

def check_updates():
    xml_output = _run_zypper_xmlout_lu()
    if xml_output.startswith('<?xml version'):
        root = ET.fromstring(xml_output)
        update_list_elements = list(root.iter('update-list'))
        if len(update_list_elements) > 0:
            return True
    return False