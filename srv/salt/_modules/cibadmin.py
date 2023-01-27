# -*- coding: utf-8 -*-
'''
Salt execution module that interacts with pacemaker SAP HANA Scale-up cluster.

.. versionadded:: pending

:maintainer:    Bo Jin <bo.jin@suse.com>
:maturity:      alpha
:platform:      SLES-for-SAP 15SP3 and newer
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
        output_crm_configure = subprocess.check_output(['cibadmin', '--query']
                        )
    except subprocess.CalledProcessError as e:
        ret["crm_configure_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["crm_configure"] = False
        return ret

    output_string = output_crm_configure.decode("utf-8")
    #print("------output_string---------{}".format(output_string))
    
    with open("/tmp/crm_configure1.xml","w+") as myfile:
        myfile.write(output_string)

    ret["crm_configure"] = True

    return ret


def find_cli_bans():
    """
    find_cli_bans func helps to find cli-ban and cli-prefer location constraints and delete them.
    It will only remove the location constraints if cluster state is idle and the respective resource is not in maintenance mode.

    CLI Example::

        salt '*' cibadmin.find_cli_bans
    """
    location_constraints = ["cli-ban", "cli-prefer"]
    if not bool(__salt__['service.status']("pacemaker")):
        ret = dict()
        ret["comment"] = "pacemaker is not running"
        __context__["retcode"] = 42
        return ret

    ret = dict()
    ret["Message"] = []
    found_constraints = 0
    ret_crm_configure = _get_crm_configure_xml_info()    
    if ret_crm_configure['crm_configure']:
        
        doc = ET.parse("/tmp/crm_configure1.xml")
        root_doc = doc.getroot()
        
        constraints = root_doc.findall("./configuration/constraints")
        
        for s in constraints:
            for c in s[:]:
                if c.tag == "rsc_location":
                    for l in location_constraints:
                        if re.findall(l, c.attrib['id']):
                            #ret = _check_rsc_maintenance_state(c.attrib['rsc'])
                            ret[l] = c.attrib
                            ret["maintenance"] = {c.attrib['rsc']: _check_rsc_maintenance_state(c.attrib['rsc'])}
                            ret["cluster_state"] = check_cluster_idle_state()
                            if ret["maintenance"][c.attrib['rsc']] == False and ret["cluster_state"]["cluster_state"] == "S_IDLE":
                                #print("----------remove contraint: {}--".format(c.attrib))
                                s.remove(c)
                                found_constraints += 1
                            
                            if ret["maintenance"][c.attrib['rsc']]:
                                ret["Message"].append("{} in maintenance, therefore we don't remove contraints: {}.\n".\
                                    format(c.attrib['rsc'], c.attrib['id']))
                                __context__["retcode"] = 42

                            if ret["cluster_state"]["cluster_state"] != "S_IDLE":
                                ret["Message"].append("Cluster state is not IDLE: {}, therefore we don't remove contraints.\n".\
                                    format(ret["cluster_state"]["cluster_state"]))
                                __context__["retcode"] = 42    

        if found_constraints > 0:
            doc.write("/tmp/cib_input.xml")
            ret["action"] = _reload_cib("/tmp/cib_input.xml")
        else:
            ret["Message"].append("Nothing to do")
            
    return ret

def _reload_cib(file):
    ret = dict()
    try:
        output_cib_replace = subprocess.check_output(['cibadmin', '--replace', "--xml-file", file]
                        )
    except subprocess.CalledProcessError as e:
        if e.returncode == 103:
            ret["output_cib_replace_error"] = "Error code: {}, message: Update was older than existing configuration".\
                format(e.returncode)
            
        else:
            ret["output_cib_replace_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode('utf-8'))
        
        ret["output_cib_replace"] = False
        __context__["retcode"] = 42
        return ret

    if output_cib_replace.decode("utf-8") == "":
        ret["replace_output"] = "Constraints removed."
    else:
        ret["replace_output"] = output_cib_replace.decode("utf-8")
    
    return ret



def _get_crmadmin_dc():
    ret = dict()
    dc_node = ""
    try:
        output_crmadmin = subprocess.check_output(['crmadmin', '-D', '--output-as=xml']
                        )
    except subprocess.CalledProcessError as e:
        ret["output_crmadmin_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["output_crmadmin"] = False
        __context__["retcode"] = 42
        return ret

    output_string = output_crmadmin.decode("utf-8")
    #print("------output_string---------{}".format(output_string))
    root_doc = ET.fromstring(output_string)
    #root_doc = doc.getroot()
    dc = root_doc.findall("./dc")

    for d in dc:
        dc_node = d.attrib["node_name"]
        #print("---------dc node: {}----------".format(dc_node))
    
    if dc_node != "":
        try:
            output_crmadmin_state = subprocess.check_output(['crmadmin', '-S', dc_node, '--output-as=xml']
                        )
        except subprocess.CalledProcessError as e:
            ret["output_crmadmin_state_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
            ret["output_crmadmin_state"] = False
            __context__["retcode"] = 42
            return ret

        output_string = output_crmadmin_state.decode("utf-8")
        root_doc = ET.fromstring(output_string)
        #root_doc = doc.getroot()
        crmd = root_doc.findall("./crmd")

        for d in crmd:
            dc_state = d.attrib["state"]
            #print("---------dc state: {}----------".format(dc_state))
            ret["cluster_state"] = dc_state


    with open("/tmp/crmadmin_output.xml","w+") as myfile:
        myfile.write(output_string)

    ret["output_crmadmin"] = True
    return ret

def _get_crmadmin_dc_ppc64le():
    ret = dict()
    dc_node = ""
    try:
        output_crmadmin = subprocess.check_output(['crmadmin', '-D']
                        )
    except subprocess.CalledProcessError as e:
        ret["output_crmadmin_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["output_crmadmin"] = False
        __context__["retcode"] = 42
        return ret

    output_string = output_crmadmin.decode("utf-8")
    if output_string != "":
        dc_node = output_string.split(": ", 1)
        dc_node = dc_node[1].replace("\n", "")
        print("--------dc_node------------{}".format(dc_node))
        try:
            output_crmadmin_state = subprocess.check_output(['crmadmin', '-S', dc_node]
                            )
        except subprocess.CalledProcessError as e:
            ret["output_crmadmin_state_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
            ret["output_crmadmin_state"] = False
            __context__["retcode"] = 42
            return ret

        output_clusterstate = output_crmadmin_state.decode("utf-8")
        
        #print("------output_clusterstate----------{}".format(output_clusterstate))
        if re.findall(r'.*S_IDLE.*ok', output_clusterstate):
            ret["cluster_state"] = "S_IDLE"
        else:
            ret["cluster_state"] = output_clusterstate

    return ret

def check_cluster_idle_state():
    if __salt__['grains.get']("cpuarch") == "ppc64le":
        ret = _get_crmadmin_dc_ppc64le()
    else:
        ret = _get_crmadmin_dc()
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
        __context__["retcode"] = 42
        return ret


    output_string = output_crm_node.decode("utf-8")

    with open("/tmp/crm_mon_out.xml","w+") as myfile:
        myfile.write(output_string)

    ret["crm_mon"] = True
    return ret

def _check_rsc_maintenance_state(rsc_name):
    ret = dict()
    ret_crm_mon = _get_crm_mon_xml_info()    
    if ret_crm_mon['crm_mon']:
        doc = ET.parse("/tmp/crm_mon_out.xml")
        root_doc = doc.getroot()
        for x in root_doc.findall("./resources/resource"):
            #print("---------x-----{}".format(x))
            
            if re.findall(rsc_name, x.attrib["id"]):
                #print("-----------a {}, maintenance: {}-----------".format(x.attrib["id"], x.attrib["managed"]))
                if x.attrib["managed"] == "false":
                    return True
                else:
                    return False


    return False

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

