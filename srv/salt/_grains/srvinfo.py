#!/usr/bin/python3.6

import os
import re
import logging
log = logging.getLogger(__name__)

def get_srvinfo():
    infofile = "/admin/config/srvinfo"
    info = {}

    if os.path.isfile(infofile):
        with open(infofile) as f:
            lines = [line.rstrip('\n') for line in f]

    for l in lines:
        keyval_info = []
        keyval_system = []
        if re.findall(r'^INFO_', l):
            keyval_info = l.split("::", 1)
            info[keyval_info[0]] = keyval_info[1]
        
        if re.findall(r'^SYSTEM_', l):
            keyval_system = l.split("::", 1)
            info[keyval_system[0]] = keyval_system[1]
        
    return info


if __name__ == "__main__":
    output = get_srvinfo()
    for a, b in output.items():
        print("{}: {}".format(a,b))