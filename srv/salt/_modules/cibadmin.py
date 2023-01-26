# -*- coding: utf-8 -*-
'''
Salt execution module that interacts with pacemaker SAP HANA Scale-up cluster.

.. versionadded:: pending

:maintainer:    Bo Jin <bo.jin@suse.com>
:maturity:      alpha
:platform:      SLES-for-SAP 12/15

:configuration: This module requires sle-ha pattern to be installed.

.. code-block:: yaml

'''

from __future__ import absolute_import, unicode_literals, print_function
import logging

from salt import exceptions
import salt.utils.path
import subprocess
import socket
import os
import re
import time
import xml.dom.minidom
import xml.etree.ElementTree as ET

__virtualname__ = 'cibadmin'

CRMSH = 'crmsh'
CRM_COMMAND = '/usr/sbin/crm'
CIBADMIN_COMMAND = '/usr/sbin/cibadmin'
CRM_NEW_VERSION = '3.0.0'
LOGGER = logging.getLogger(__name__)

def __virtual__():    
    return __virtualname__

def _get_crm_configure_xml_info():
    ret = dict()
    try:
        output_crm_configure = subprocess.check_output(['crm', 'configure', 'show', 'xml']
                        )
    except subprocess.CalledProcessError as e:
        ret["crm_configure_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["crm_configure"] = False
        return ret

    output_string = output_crm_configure.decode("utf-8")

    with open("/tmp/crm_configure.xml","w+") as myfile:
        myfile.write(output_string)

    time.sleep(1)
    ret["crm_configure"] = True

    return ret


def find_cli_bans():
    ret = dict()
    ret_crm_configure = _get_crm_configure_xml_info()    
    if ret_crm_configure['crm_configure']:
        
        doc = ET.parse("/tmp/crm_configure_xmlout.txt")
        root_doc = doc.getroot()
        for x in root_doc.findall("./configuration/constraints"):
            print("-----------location constraints-----------{}".format(x.items()))
    return ret


def _get_crm_mon_xml_info():
    # this function should be called by other functions in this module and generate the crm_mon xml output and write output to a file.
    ret = dict()
    try:

        output_crm_node = subprocess.check_output(['crm_mon', '-1', '--output-as=xml']
                        )
    except subprocess.CalledProcessError as e:
        ret["crm_mon_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["crm_mon"] = False
        return ret


    output_string = output_crm_node.decode("utf-8")

    with open("/tmp/xmlout.txt","w") as myfile:
        myfile.write(output_string)

    time.sleep(1)
    ret["crm_mon"] = True
    return ret
    
def _check_crmsh():

    if bool(salt.utils.path.which(CRM_COMMAND)):
        version = __salt__['pkg.version'](CRMSH)
        use_crm = __salt__['pkg.version_cmp'](
            version, CRM_NEW_VERSION) >= 0
        LOGGER.info('crmsh version: %s', version)
        LOGGER.info(
            '%s will be used', 'crm')

    else:
        return {'status': False, 'message': 'failed to find binary crm. Check if crmsh is installed.'}

    if not use_crm:
        return {'status': False, 'message': 'crmsh version is too old.'}
    
    #__salt__['crmsh.version'] = use_crm
    return {'status': True, 'message': 'crmsh is installed.'}

def _search_pattern(pattern, inputs):
    
    for line in iter(inputs.stdout.readline, b''):
        if re.search(pattern, line.decode('utf-8')):
            return True    
    return False


def is_cluster_idle():
    __salt__["grains.set"]('cluster_state_idle', False)
    out_crmadmin_dc_lookup = subprocess.Popen(['crmadmin', '-D'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )

    mycmd = ['cut', '-d', ':', '-f', '2']
    out_crmadmin_dc_host = subprocess.Popen(mycmd,
                    stdin=out_crmadmin_dc_lookup.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                    )

    dc_host, err_dc_host = out_crmadmin_dc_host.communicate()
    if not err_dc_host:
        dc_host = dc_host.decode('utf-8')
        dc_host = dc_host.strip()
        if dc_host != "":
            out_cluster_idle_status = subprocess.Popen(['crmadmin', '-q', '-S', dc_host],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )

            for line in iter(out_cluster_idle_status.stdout.readline, b''):
                cluster_state = line.decode('utf-8')
                
                if re.search("S_IDLE", cluster_state):
                    __salt__["grains.set"]('cluster_state_idle', True)
                    return True

    return False

def wait_for_cluster_idle(interval, timeout):
    ret = dict()
    hostname = socket.gethostname()
    fqdnhostname = socket.getfqdn(hostname)
    __salt__["grains.set"]('cluster_state_idle', False)

    if interval <=15:
        interval = 15
    
    if timeout <= 1:
        timeout = 1
    
    timeout = time.time() + 60*timeout

    while True:
        time.sleep(interval)
        
        if is_cluster_idle():
            ret['cluster_state'] = "is idle now."
            #__salt__["event.send"]('suma/pacemaker/cluster/state/idle', {"cluster_idle": True, 'node': fqdnhostname})
            __salt__["grains.set"]('cluster_state_idle', True)

            return True

        if time.time() > timeout:
            break
    
    ret['cluster_state'] = "timeout and cluster state is not IDLE yet."
    __context__["retcode"] = 42
    return False

