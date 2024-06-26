# -*- coding: utf-8 -*-
'''
Salt execution module that interacts with btrfs snapper utility.

.. versionadded:: pending

:maintainer:    Bo Jin <bo.jin@suse.com>
:maturity:      alpha
:platform:      SLES 15SP3 and newer
:depends:       python: xml, salt, subprocess, json

:configuration: This module requires sle-ha pattern to be installed.

.. code-block:: yaml

'''

from __future__ import absolute_import, unicode_literals, print_function
import logging

from salt import exceptions
import salt.utils.path
import subprocess
import socket
import json
import os
import re
from datetime import datetime
import xml.dom.minidom
import xml.etree.ElementTree as ET

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
    __context__: Any = None

__virtualname__ = 'btrfs'

BTRFS_CMD = "/sbin/btrfs"
SNAPPER_CMD = "/usr/bin/snapper"
BTRFS_PKG = "btrfsprogs"
LOGGER = logging.getLogger(__name__)

def __virtual__():
    return __virtualname__

def _check_btrfs():
    btrfs_info = dict()
    btrfs_info["btrfs"] = {}
    precheck_cmd = ["df", "-hTP"]
    grep_cmd = ["grep", "-E", "/$"]
    regex_btrfs = r'btrfs'

    try:
        proc1 = subprocess.Popen(precheck_cmd, bufsize=0, stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(grep_cmd, bufsize=0, stdin=proc1.stdout, stdout=subprocess.PIPE)
        for line in iter(proc2.stdout.readline, b''):
            #print(line.decode('utf-8')[:-1])
            if not re.findall(regex_btrfs, line.decode('utf-8')[:-1]):
                #print("root fs is not btrfs type.")
                btrfs_info["btrfs"]["comment"] = "No btrfs, {}".format(line.decode('utf-8')[:-1])
                return btrfs_info

        proc2.stdout.close()
        proc2.wait()

    except subprocess.CalledProcessError as e:
        LOGGER.error(e)

    if os.path.exists(BTRFS_CMD) and os.path.exists(SNAPPER_CMD):
        rpm_cmd = ["rpm", "-q", BTRFS_PKG]
        try:
            version = subprocess.check_output(rpm_cmd).decode("utf-8")
        except subprocess.CalledProcessError as e:
            LOGGER.error(e)
            return e

        btrfs_info["btrfs"]['version'] = version
    else:
        btrfs_info["btrfs"] = "No btrfs rpm installed."
    return btrfs_info

def _already_snapshot_today(init_final):
    # need today in UTC format 03 Dez 2022

    today = datetime.now().strftime("%d %b %Y")
    #print("------------------today is {}".format(today))
    command_snapper_list = ['snapper', 'list', '-t', 'single']
    try:
        output = subprocess.check_output(command_snapper_list).decode("utf-8")
    except subprocess.CalledProcessError as e:
        print(f"-------------An error occurred: {e}")
        #return False

    command_date = ["date"]
    try:
        output_date = subprocess.check_output(command_date).decode("utf-8")
    except subprocess.CalledProcessError as e:
        print(f"-------------An error occurred: {e}")
        #return False

    # need to get the date part from the output_date
    output_date = output_date.splitlines()[0]
    output_date = output_date.split(" ")
    output_date = output_date[1] + " " + output_date[2] + " " + output_date[3]
    #print("------------------output_date is {}".format(output_date))

    if not "output" in locals():
        return False

    if output:
        for line in output.splitlines():
            search_txt = "SUMA {}".format(init_final)
            print("--------------------{}   {}".format(output_date, search_txt))
            if output_date in line and search_txt.strip() in line:
                #print("-----------------------Found a snapshot from today")
                return True

    return False

def snapper_create(bundle="no-bundle", init_final="", type="single", cleanup_algorithm="number", userdata="from_salt=true"):
    ret = dict()
    btrfs_version = _check_btrfs()
    if "version" in btrfs_version["btrfs"].keys():
        if _already_snapshot_today(init_final):
            ret["btrfs_version"] = btrfs_version["btrfs"]["version"]
            ret["comment"] = "There is already a single snapshot from today. Skip."
            return ret

        description = "SUMA {} snapshot {}".format(init_final, bundle)
        ret["btrfs_version"] = btrfs_version["btrfs"]["version"]
        command_arguments = ['create', '-d', description, '-c', cleanup_algorithm, '-t', type, '-u', userdata, '-p']
        command_output = _execute_snapper_command(command_arguments)
        print(command_output)
        ret["snapper_id"] = command_output
    else:
        ret["comment"] = "Not a btrfs system"
    return ret

def _execute_snapper_command(arguments):
    command = ['snapper'] + arguments

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()