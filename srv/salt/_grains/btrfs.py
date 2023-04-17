#!/usr/bin/python3.6

import os
import re
import subprocess

import logging
from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
log = logging.getLogger(__name__)

BTRFS_CMD = "/sbin/btrfs"
BTRFS_PKG = "btrfsprogs"


def get_btrfs_info():

    btrfs_info = dict()
    btrfs_info["btrfs"] = {}
    
    precheck_cmd = ["df", "-hTP"]
    grep_cmd = ["grep", "-E", "/$"]
    regex_btrfs = r'btrfs'

    try:
        proc1 = subprocess.Popen(precheck_cmd, bufsize=0, stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(grep_cmd, bufsize=0, stdin=proc1.stdout, stdout=subprocess.PIPE)
        for line in iter(proc2.stdout.readline, b''):
            print(line.decode('utf-8')[:-1])
            if not re.findall(regex_btrfs, line.decode('utf-8')[:-1]):
                print("root fs is not btrfs type.")
                btrfs_info["btrfs"]["comment"] = "No btrfs, {}".format(line.decode('utf-8')[:-1])
                btrfs_info["btrfs"]["for_patching"] = "ok"
                return btrfs_info
                
        proc2.stdout.close()
        proc2.wait()
        
    except subprocess.CalledProcessError as e:
        log.error(e)
        return e
    
    if os.path.exists(BTRFS_CMD):
        rpm_cmd = ["rpm", "-q", BTRFS_PKG]
        try:
            version = subprocess.check_output(rpm_cmd).decode("utf-8")
        except subprocess.CalledProcessError as e:
            log.error(e)
            return e
            
        btrfs_info["btrfs"]['version'] = version
    else:
        btrfs_info["btrfs"] = "No btrfs"
        return btrfs_info 
    
    btrfs_cmd = ["btrfs", "fi", "usage", "-g", "/"]
    regex = r'Free.*est'
    free_size = 0
    try:
        proc = subprocess.Popen(btrfs_cmd, bufsize=0, stdout=subprocess.PIPE)
        for line in iter(proc.stdout.readline, b''):
            log.info(line.decode('utf-8')[:-1]) # [:-1] to cut off newline char
            if re.findall(regex, line.decode('utf-8')[:-1]):
                print(line.decode('utf-8')[:-1].split()[2])
                free_size = line.decode('utf-8')[:-1].split()[2]
                free_size = float(free_size.strip("GiB"))
        proc.stdout.close()
        proc.wait()
        btrfs_info["btrfs"]["root_free"] = free_size
        btrfs_info["btrfs"]["comment"] = "size in GiB"
        if free_size >= 2.00:
            btrfs_info["btrfs"]["for_patching"] = "ok"
        else:
            btrfs_info["btrfs"]["for_patching"] = "no"
            
        return btrfs_info
    except subprocess.CalledProcessError as e:
        log.error(e)
        return e

    """ if isinstance(free_size_bytes, int):
        val = 0
        if free_size_bytes > 1024:
            print("kb")
            val = free_size_bytes / 1024
            if val > 1024:
                print("mb")
                val = val / 1024
            if val > 1024:
                print("gb")
                val = val / 1024
        btrfs_info["free_size"] = round(val) """

    return btrfs_info


if __name__ == "__main__":
    output = get_btrfs_info()
    for a, b in output.items():
        print("{}: {}".format(a,b))