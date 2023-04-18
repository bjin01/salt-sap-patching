#!/usr/bin/python3.6

import os
import logging
log = logging.getLogger(__name__)

def get_rootinfo():
    infofile = "/root/info"
    info = dict()
    info['root_info'] = {}

    if os.path.isfile(infofile):
        with open(infofile) as f:
            lines = [line.rstrip('\n') for line in f]
    else:
        return info

    for l in lines:
        keyval_info = []
        
        keyval_info = l.split("=", 2)
        #print("-------------keyval_info: {}".format(len(keyval_info)))
        if len(keyval_info) >= 2:
            info['root_info'][keyval_info[0].strip()] = keyval_info[1].strip()
        else:
            info['root_info'][keyval_info[0].strip()] = "Unknown"
        
    return info


if __name__ == "__main__":
    output = get_rootinfo()
    for a, b in output.items():
        print("{}: {}".format(a,b))