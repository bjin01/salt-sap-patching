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

__virtualname__ = 'bocrm'

CRMSH = 'crmsh'
CRM_COMMAND = '/usr/sbin/crm'
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

    with open("/tmp/crm_configure_xmlout.txt","w") as myfile:
        myfile.write(output_string)

    time.sleep(1)
    ret["crm_configure"] = True

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

def check_if_nodes_online():
    # this function analyzes crm_mon xml output about node status and returns the node information.
    ret = dict()
    node_state_list = [
        "standby",
        "standby_onfail",
        "maintenance",
        "pending",
        "unclean",
        "shutdown"
    ]

    ret["online_nodes"] = []
    ret["offline_nodes"] = []
    ret["node_problems"] = {}

    ret_get_crm_mon_xml_info = _get_crm_mon_xml_info()

    if ret_get_crm_mon_xml_info["crm_mon"]:
        doc = xml.dom.minidom.parse("/tmp/xmlout.txt")
    
        nodelist = doc.documentElement
        for child in nodelist.childNodes:
            if child.nodeName == "nodes":
                for n in child.childNodes:
                    if n.nodeName == "node":
                        if n.getAttribute("online") == "true":
                            for l in node_state_list:
                                if n.getAttribute(l) == "true":
                                    ret["node_problems"][n.getAttribute("name")] = []
                                    ret["node_problems"][n.getAttribute("name")].append(l)
                            if n not in ret["node_problems"]:
                                ret["online_nodes"].append(n.getAttribute("name"))

                        else:

                            if n.getAttribute("online") == "false":
                                ret["node_problems"][n.getAttribute("name")] = "offline"
                                ret["offline_nodes"].append(n.getAttribute("name"))
    else:
        __context__["retcode"] = 42
        ret["comment"] = ret_get_crm_mon_xml_info
        return ret
    return ret

def _get_dc():
    ret = dict()
    ret["current_dc"] = ""
    ret_get_crm_mon_xml_info = _get_crm_mon_xml_info()

    if ret_get_crm_mon_xml_info["crm_mon"]:
        doc = xml.dom.minidom.parse("/tmp/xmlout.txt")
    
        root = doc.documentElement
        for child in root.childNodes:
            if child.nodeName == "summary":
                for n in child.childNodes:
                    if n.nodeName == "current_dc":
                        present = n.getAttribute("present")
                        with_quorum = n.getAttribute("with_quorum")
                        if present == "true" and with_quorum == "true":
                            ret["current_dc"] = n.getAttribute("name")
    else:
        return ret
    return ret

def get_dc():
    #ret = dict()
    ret = _get_dc()
    return ret

def if_cluster_state_idle():

    ret = get_dc()
    hostname = socket.gethostname()
    if ret["current_dc"] != "":
        #if dc is found then we do cluster state query and match if cluster state is s_idle, if not then maintenance_approval will be set to False

        try:
            out_cluster_idle = subprocess.Popen(['crmadmin', '-q', '-S', ret["current_dc"]],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                            )
        except:
            ret["crmadmin_error"] = "error"
            return ret

        for line in iter(out_cluster_idle.stderr.readline, b''):
            ret['clusterstate'] = line.decode('utf-8').strip()
            if ret['clusterstate'] not in "S_IDLE":
                #__salt__["grains.set"]('cluster_state_idle', False)
                ret["dc_comment"] = "cluster state is not S_IDLE or the host is not current_dc."
                ret["cluster_state_idle"] = False
                ret["maintenance_approval"] = False
                #we end the func if cluster state is not s_idle. Then no need to further query the cluster.
                return ret
            
            if ret['clusterstate'] in "S_IDLE":
                #__salt__["grains.set"]('cluster_state_idle', True)
                ret["cluster_state_idle"] = True
                ret["dc_comment"] = "cluster state is in S_IDLE."
                return ret
    else:
        ret["dc_comment"] = "{} is not current dc.".format(hostname)
    return ret

def get_msl_resource_info():
    ret = dict()
    ret["resources"] = []
    ret_crm_configure = _get_crm_configure_xml_info()    
    if ret_crm_configure['crm_configure']:
        
        doc = ET.parse("/tmp/crm_configure_xmlout.txt")
        root_doc = doc.getroot()
        for child in root_doc.findall("./configuration/resources/master"):
            
            ret["resources"].append({"msl_rsc_name": child.attrib['id']})
        
        for x in root_doc.findall("./configuration/resources/master/primitive"):
            print("-----------id-----------{}".format(x.items()))
            for a, b in x.items():
                if a == "id":
                    ret["resources"].append({a: b})

        for x in root_doc.findall("./configuration/resources/master/primitive/instance_attributes/nvpair/[@name='SID']"):
            for a, b in x.items():
                if a == "value":
                    ret["resources"].append({"SID": b})
        
        for x in root_doc.findall("./configuration/resources/master/primitive/instance_attributes/nvpair/[@name='InstanceNumber']"):
            for a, b in x.items():
                if a == "value":
                    ret["resources"].append({"Instance": b})
        
        for x in root_doc.findall("./configuration/resources/master/primitive/instance_attributes/nvpair/[@name='AUTOMATED_REGISTER']"):
            for a, b in x.items():
                if a == "value":
                #tempdict = {"rsc_id": x.attrib["id"]}
                    ret["resources"].append({"AUTOMATED_REGISTER": b})
    return ret

def check_if_maintenance():
    ret = dict()
    ret["resources"] = []
    ret_crm_configure = _get_crm_configure_xml_info()    
    if ret_crm_configure['crm_configure']:
        doc = ET.parse("/tmp/crm_configure_xmlout.txt")
        root_doc = doc.getroot()
        for child in root_doc.findall(".//*[@name='maintenance']"):
            if child.attrib["value"] == "true":
                ret["resources"].append(child.attrib)
        
        for child in root_doc.findall(".//*[@name='standby']"):
            if child.attrib["value"] == "true":
                ret["resources"].append(child.attrib)
    
    if len(ret["resources"]) != 0:
        ret["comment"] = "Some resources or nodes are in maintenance or standby mode. Do not continue from here without fixing the issue first."
        __context__["retcode"] = 42

    return ret

def check_sr_status():
    ret = dict()
    node_status = dict()
    ret["diskless_node"] = []
    ret["cluster_nodes"] = []

    hostname = socket.gethostname()

    out_crm_nodes = subprocess.Popen(['crm', 'node', 'server'],
                        stdout=subprocess.PIPE
                        )
    for line in iter(out_crm_nodes.stdout.readline, b''):
        #create a list of found nodes.
        #cluster_nodes.append(line.decode('utf-8').rstrip())
        ret["cluster_nodes"].append(line.decode('utf-8').rstrip())

    if not _check_SAPHanaSR_showAttr():
        ret["error_comment"] = "SAPHanaSR_showAttr is not available."
        __context__["retcode"] = 42
        __salt__["grains.set"]("hana_info", ret, "force=True")
        return ret

    ret_check_if_nodes_online = check_if_nodes_online()
    if not ret_check_if_nodes_online["online_nodes"]:
        ret["online_nodes_error"] = "No online nodes found."
        __context__["retcode"] = 42
        __salt__["grains.set"]("hana_info", ret, "force=True")
        return ret

    try:
        output_saphana_showattr = subprocess.check_output(['SAPHanaSR-showAttr', '--format=script'],
                        universal_newlines=True
                        )
    except subprocess.CalledProcessError as e:
        ret["SAPHanaSR-showAttr_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["check_sr_status"] = False
        return ret
    
    if output_saphana_showattr == "":
        ret["no_SAPHanaSR-showAttr"] = "SAPHanaSR-showAttr output is empty. This host is not a SAP HANA host."
        ret["diskless_node"].append(hostname)
        __salt__["grains.set"]("hana_info", ret, "force=True")
        return ret

    ret["hana_primary"] = []
    ret["hana_secondary"] = []
    ret["SOK"] = False

    for i in ret_check_if_nodes_online["online_nodes"]:
        node_status[i] = []
        primary_node_online = ""

        for o in output_saphana_showattr.split('\n'):
            # Resource/msl_SAPHana_BJK_HDB00/maintenance="false"
            pattern = '^Resource/.*/maintenance="true"'
            if re.search(pattern, o):
                rsc_name = o.split("/")[1]
                ret[rsc_name] = " in maintenance mode."
                return ret
            
            pattern = "^Hosts/{}/node_state=.*online".format(i)
            if re.search(pattern, o):
                primary_node_online = o.split("/")[1]
                node_status[i].append("online")

            # Hosts/hana-1/roles="4:P:master1:master:worker:master"
            pattern = "^Hosts/{}/roles=.*4:P:master1.*".format(i)
            if re.search(pattern, o):
                primary_node_role = o.split("/")[1]
                node_status[i].append("4:P")
            
            # Hosts/hana-1/sync_state="PRIM"
            pattern = "^Hosts/{}/sync_state=.*PRIM".format(i)
            if re.search(pattern, o):
                primary_node_state = o.split("/")[1]
                node_status[i].append("PRIM")
            
            pattern = "^Hosts/{}/roles=.*4:S:master1.*".format(i)
            if re.search(pattern, o):
                primary_node_role = o.split("/")[1]
                node_status[i].append("4:S")
            
            # Hosts/hana-1/sync_state="PRIM"
            pattern = "^Hosts/{}/sync_state=.*SOK".format(i)
            if re.search(pattern, o):
                primary_node_state = o.split("/")[1]
                node_status[i].append("SOK")

            pattern = "^Hosts/{}/site=\"\"".format(i)
            if re.search(pattern, o):
                primary_node_state = o.split("/")[1]
                node_status[i].append("no_site")
            
        
        if "PRIM" in node_status[i] and "online" in node_status[i] and "4:P" in node_status[i]:
            ret["hana_primary"].append(i)

        if "SOK" in node_status[i] and "online" in node_status[i] and "4:S" in node_status[i]:
            ret["hana_secondary"].append(i)
            ret["SOK"] = True
        
        if "online" in node_status[i] and "no_site" in node_status[i]:
            ret["diskless_node"].append(i)
        
    if len(ret["hana_primary"]) == 0 or len(ret["hana_primary"]) > 1:
        ret["primary_comment"] = "primary host is having problems. Check SAPHanaSR-showAttr output."

    if len(ret["hana_secondary"]) == 0 or len(ret["hana_secondary"]) > 1:
        ret["secondary_comment"] = "secondary host is having problems. Check SAPHanaSR-showAttr output."
    
    __salt__["grains.set"]("hana_info", ret, "force=True")

    return ret

def _msl_status():
    hostname = socket.gethostname()
    ret = dict()
    ret["maintenance_approval"] = True
    ret['resources'] = []
    ret["comments"] = []
    
    ret_pacemaker = __salt__['service.status']("pacemaker")
    if not ret_pacemaker:
        ret["comment"] = "pacemaker is not running."
        ret["maintenance_approval"] = False
        return ret

    ret_if_cluster_state_idle = if_cluster_state_idle()
    if not ret_if_cluster_state_idle["cluster_state_idle"]:
        ret["if_cluster_state_idle"] = ret_if_cluster_state_idle
        ret["maintenance_approval"] = False
        return ret
    
    ret_check_if_nodes_online = check_if_nodes_online()
    if len(ret_check_if_nodes_online["node_problems"]) != 0:
        ret["check_if_nodes_online"] = ret_check_if_nodes_online
        ret["maintenance_approval"] = False
        return ret

    ret_check_if_maintenance = check_if_maintenance()
    if len(ret_check_if_maintenance["resources"]) != 0:
        ret["check_if_maintenance"] = ret_check_if_maintenance
        ret["maintenance_approval"] = False
        return ret

    ret_check_sr_status = check_sr_status()
    if hostname not in ret_check_sr_status["diskless_node"] and not ret_check_sr_status["SOK"]:
        ret["check_sr_status"] = ret_check_sr_status
        ret["maintenance_approval"] = False
        return ret

    if ret["maintenance_approval"]:
        ret["comments"] = [
            "pacemaker is running - OK",
            "cluster state is S_IDLE - OK",
            "all member nodes are online - OK",
            "resources and nodes are not in maintenance or standby - OK",
            "system replication status is SOK - OK"
        ]
    return ret

def sync_status():
    '''
    Show SAP HANA Scale-up pacemaker cluster status.

    CLI Example:

    .. code-block:: bash

        salt '*' bocrm.sync_status
    '''
    crm_ret = _check_crmsh()
    if not crm_ret['status']:
        return crm_ret

    ret = _msl_status()
    
    if not ret["maintenance_approval"]:
        __context__["retcode"] = 42
    return ret

def pacemaker():
    return __salt__['service.status']("pacemaker")

def _check_SAPHanaSR_showAttr():
    find_command = '/usr/sbin/SAPHanaSR-showAttr'
    if bool(salt.utils.path.which(find_command)):
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

def is_quorum():

    out_corosync_quorum_status = subprocess.Popen(['corosync-quorumtool', '-s'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )
    
    expected_votes = 0
    total_votes = 0

    for line in iter(out_corosync_quorum_status.stdout.readline, b''):

        if re.search("Expected votes:", line.decode('utf-8')):
            expected_votes = line.decode('utf-8').split(":")[1].strip()

        if re.search("Total votes:", line.decode('utf-8')):
            total_votes = line.decode('utf-8').split(":")[1].strip()

    if expected_votes == total_votes:

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

def set_on_msl_maintenance(msl_resource_name):
    hostname = socket.gethostname()
    ret = dict()
    ret['msl_maintenance'] = False

    verify_pattern = "\<clone id=\"{}\" multi_state=\"true\".*managed=\"true\".*>$".format(msl_resource_name)

    out_resources_xml = subprocess.Popen(['crm_mon', '-1', '--exclude=all', '--include=resources', '--output-as=xml'],
                        stdout=subprocess.PIPE
                        )
    
    if _search_pattern(verify_pattern, out_resources_xml):
        out_set_maint_mode = subprocess.Popen(['crm', 'resource', 'maintenance', msl_resource_name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                            )
        ret["run_on"] = hostname
        
        out_set_maint_mode.wait()

        if out_set_maint_mode.returncode != 0:
            for line in iter(out_set_maint_mode.stderr.readline, b''): 
                ret['msl_resource_error'] = ''.join(line.decode('utf-8'))

    out_resources_xml_after = subprocess.Popen(['crm_mon', '--exclude=all', '--include=resources', '-1', '--output-as=xml'],
                        stdout=subprocess.PIPE
                        )
                        
    verify_pattern2 = "\<clone id=\"{}\" multi_state=\"true\".*managed=\"false\".*>$".format(msl_resource_name)

    if _search_pattern(verify_pattern2, out_resources_xml_after):
        ret['msl_maintenance'] = True
        ret['comment'] = "{} is in maintenance mode now.".format(msl_resource_name)
        return ret
                
    return ret

def set_msl_maintenance(msl_resource_name):
    ret = dict()

    crm_ret = _check_crmsh()
    if not crm_ret['status']:
        __context__["retcode"] = 42
        return crm_ret

    if not bool(__salt__['service.status']("pacemaker")):
        ret = dict()
        ret["comment"] = "pacemaker is not running"
        __context__["retcode"] = 42
        return ret
    
    if not is_quorum():
        ret = dict()
        ret["comment"] = "corosync quorum failed. Node does not have quorum partition."
        __context__["retcode"] = 42
        return ret

    if not is_cluster_idle():
        ret = dict()
        ret["comment"] = "cluster state is not S_IDLE."
        __context__["retcode"] = 42
        return ret
    else:
        
        #set msl_SAPHana_BJK_HDB00 to maintenance mode 
        ret = set_on_msl_maintenance(msl_resource_name)
        if not ret["msl_maintenance"]:
            __context__["retcode"] = 42
            return ret

    return ret

def set_off_msl_maintenance(msl_resource_name):
    hostname = socket.gethostname()
    ret = dict()
    ret['msl_maintenance'] = True

    if not is_cluster_idle():
        ret['comment'] = "Cluster state is not idle."
        __context__["retcode"] = 42
        
        return ret


    verify_pattern = "\<clone id=\"{}\" multi_state=\"true\".*managed=\"false\".*>$".format(msl_resource_name)

    out_resources_xml = subprocess.Popen(['crm_mon', '--exclude=all', '--include=resources', '-1', '--output-as=xml'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )

    if _search_pattern(verify_pattern, out_resources_xml):
        ret['msl_maintenance'] = True
        ret['comment'] = "{} is still in maintenance mode".format(msl_resource_name)

        out_resources_xml = subprocess.Popen(['crm', 'resource', 'maintenance', msl_resource_name, 'off'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )
        time.sleep(3)
        if out_resources_xml.returncode != 0:
            for line in iter(out_resources_xml.stderr.readline, b''): 
                ret['msl_resource_error'] = ''.join(line.decode('utf-8'))
    
    verify_pattern_after = "\<clone id=\"{}\" multi_state=\"true\".*managed=\"true\".*>$".format(msl_resource_name)

    out_resources_xml = subprocess.Popen(['crm_mon', '--exclude=all', '--include=resources', '-1', '--output-as=xml'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )
    if _search_pattern(verify_pattern_after, out_resources_xml):
        ret['msl_maintenance'] = False
        ret['comment'] = "{} is online again.".format(msl_resource_name)

    return ret

def off_msl_maintenance(msl_resource_name):
    ret = dict()

    crm_ret = _check_crmsh()
    if not crm_ret['status']:
        __context__["retcode"] = 42
        return crm_ret

    if not bool(__salt__['service.status']("pacemaker")):
        ret = dict()
        ret["comment"] = "pacemaker is not running"
        __context__["retcode"] = 42
        return ret
    
    if not is_quorum():
        ret = dict()
        ret["comment"] = "corosync quorum failed. Node does not have quorum partition."
        __context__["retcode"] = 42
        return ret
    
    if not is_cluster_idle():
        ret = dict()
        ret["comment"] = "cluster state is not S_IDLE."
        __context__["retcode"] = 42
        return ret
    else:
        #set msl_SAPHana_BJK_HDB00 to maintenance mode 
        ret = set_off_msl_maintenance(msl_resource_name)
        if ret['msl_maintenance']:
            __context__["retcode"] = 42
        #find_cluster_nodes()
        time.sleep(3)
        return ret

    ret['comment'] = "Something went wrong."
    return ret

def start_pacemaker():
    ret = dict()

    crm_ret = _check_crmsh()

    if not crm_ret['status']:
        __context__["retcode"] = 42
        return crm_ret

    if not bool(__salt__['service.status']("pacemaker")):
        __salt__['service.start']("pacemaker")
    else:
        ret['pacemaker'] = "is already running"
        return ret

    
    if not bool(__salt__['service.status']("pacemaker")):
        ret['pacemaker'] = "Failed to start pacemaker."
        __context__["retcode"] = 42
        
    else:
        ret['pacemaker'] = "running"
    
    return ret

def stop_pacemaker():
    ret = dict()

    crm_ret = _check_crmsh()

    if not crm_ret['status']:
        ret['pacemaker'] = "crmsh is not available.."
        __context__["retcode"] = 42
        return crm_ret

    if not is_quorum():
        ret = dict()
        ret["comment"] = "corosync quorum failed. Node does not have quorum partition. Therefore we don't stop pacemaker."
        __context__["retcode"] = 42
        return ret
    
    if not is_cluster_idle():
        ret = dict()
        ret["comment"] = "cluster state is not S_IDLE therefore not stopping pacemaker."
        __context__["retcode"] = 42
        return ret

    if bool(__salt__['service.status']("pacemaker")):
        __salt__['service.stop']("pacemaker")
    else:
        ret['pacemaker'] = "is already stopped."
        return ret
    
    if bool(__salt__['service.status']("pacemaker")):
        ret['pacemaker'] = "Failed to stop pacemaker."
        __context__["retcode"] = 42
    else:
        ret['pacemaker'] = "stopped"

    return ret


#find_cluster_nodes function will search cluster nodes and identify current server roles.
def find_cluster_nodes():
    file_handler = logging.FileHandler('/tmp/saltlog.txt')
    file_handler.setLevel(logging.INFO)
    LOGGER.addHandler(file_handler)

    diskless_node_name = ""
    ret = dict()
    cluster_nodes = []
    cluster_node_info = {}
    cluster_node_info['cluster_nodes'] = []
    hostname = socket.gethostname()
    message_tag = "suma/hana/cluster/nodeinfo/{}".format(hostname)
    #First try to find the pacemaker cluster member nodes.
    out_crm_nodes = subprocess.Popen(['crm', 'node', 'server'],
                        stdout=subprocess.PIPE
                        )
    for line in iter(out_crm_nodes.stdout.readline, b''):
        #create a list of found nodes.
        cluster_nodes.append(line.decode('utf-8').rstrip())
        cluster_node_info['cluster_nodes'].append(line.decode('utf-8').rstrip())
    #cluster_node_info['cluster_nodes'] = cluster_nodes

    if len(cluster_nodes) <= 2 or len(cluster_nodes) > 3:
        cluster_node_info["diskless_node"] = None

    total_nodes = len(cluster_nodes)
    #print("++++++++++++++ cluster_nodes {}".format(cluster_nodes))

    if _check_SAPHanaSR_showAttr():
        #print("++++++++++++++ cluster_nodes {}".format(cluster_nodes))

        #finally we query the hana system replication status.
        out1 = subprocess.Popen(['SAPHanaSR-showAttr'], 
                            stdout=subprocess.PIPE,
                            )
        
        out2 = subprocess.Popen(['grep', '-A5', '-E', 'Hosts.*clone_state.*node_state'],
                            stdin=out1.stdout, 
                            stdout=subprocess.PIPE,
                            )

        #the secondary node if working correctly has a score value of 2 digits and must be 4:S and SOK
        sok_escaped = '.*online.*4:S.*SOK'
        search_pattern_sok = "^{}".format(hostname) + sok_escaped
        
        #the primary node if working properly has a score value of 10 digits and 4:P and PRIM
        prim_escaped = '.*online.*4:P.*PRIM'
        search_pattern_prim = "^{}".format(hostname) + prim_escaped
        #and if SFAIL is found we must set status to maintenance_approval = False
        search_pattern_sfail = "^{}.*SFAIL".format(hostname)

        for line in iter(out2.stdout.readline, b''):

              
            if re.search(search_pattern_sok, line.decode('utf-8')):
                ret['sr_status'] = "SOK"
                cluster_nodes.remove(hostname)
                cluster_node_info["hana_secondary"] = socket.getfqdn(hostname)
                print("---------- {}".format(line.decode('utf-8')))

            if re.search(search_pattern_prim, line.decode('utf-8')):
                cluster_node_info["hana_primary"] = socket.getfqdn(hostname)
                cluster_nodes.remove(hostname)
                ret['sr_status'] = "PRIM"

            if re.search(search_pattern_sfail, line.decode('utf-8')):
                ret['sr_status'] = "SFAIL"
                cluster_nodes.remove(hostname)
                cluster_node_info["hana_secondary"] = socket.getfqdn(hostname)
                ret["maintenance_approval"] = False
        
        if len(cluster_nodes) == total_nodes:
            cluster_node_info["diskless_node"] = socket.getfqdn(hostname)
        
        __salt__['grains.delkey']("hana_info", 'force=True')
        time.sleep(2)
        
        __salt__['grains.set']("hana_info", cluster_node_info, 'force=True')
        time.sleep(2)
        __salt__['event.send'](message_tag, {"hana_nodes": cluster_node_info})
        #LOGGER.info("event sent: {} - {}".format(hostname, cluster_node_info))
    else:
        cluster_node_info["diskless_node"] = socket.getfqdn(hostname)
        #diskless_node_name = hostname
        __salt__['grains.delkey']("hana_info", 'force=True')
        time.sleep(2)
        __salt__['grains.set']("hana_info", cluster_node_info, 'force=True')
        time.sleep(2)
        __salt__['event.send'](message_tag, {"hana_nodes": cluster_node_info})

    return {"hana_nodes": cluster_node_info}


def patch_diskless_node():

    output = find_cluster_nodes()

    return output

def move_msl_resource(interval, timeout):
    ret = dict()
    
    msl_rsc_name = ""

    try:
        output_saphana_showattr = subprocess.check_output(['SAPHanaSR-showAttr', '--format=script'],
                        universal_newlines=True
                        )
    except subprocess.CalledProcessError as e:
        ret["SAPHanaSR-showAttr_error"] = "Error code: {}, message: {}".format(e.returncode, e.output.decode("utf-8"))
        ret["check_sr_status"] = False
        return ret
    
    if output_saphana_showattr == "":
        ret["comment"] = "SAPHana_showAttr is not providing outputs. This node is not a HANA node."
        __context__["retcode"] = 42
        return ret

    ret_get_msl_resource_info = get_msl_resource_info()
    ret_sync_status = sync_status()
    
    if ret_sync_status["maintenance_approval"] and len(ret_get_msl_resource_info["resources"]) > 0:
        for a in ret_get_msl_resource_info["resources"]:
            if "msl_rsc_name" in a:
                msl_rsc_name = a["msl_rsc_name"]
        
        if msl_rsc_name:
            output_run = subprocess.run(['crm', 'resource', 'move', msl_rsc_name, 'force'])

            if output_run.returncode != 0:
                ret["comment"] = "crm resource move failed."
                __context__["retcode"] = 42
            else:
                ret["comment"] = "crm resource moved to the other node."

        if wait_for_cluster_idle(interval, timeout):
            ret["comment"] = "Cluster is idle again and {} has been moved.".format(msl_rsc_name)
    else:
        ret["ret_sync_status"] = ret_sync_status
        ret["comment"] = "Because sync_status() or get_msl_resource_info() was not successful the module failed."
        __context__["retcode"] = 42

    return ret

def delete_cli_ban_rule(msl_resource_name, interval, timeout):
    hostname = socket.gethostname()
    ret = dict()

    if not bool(__salt__['service.status']("pacemaker")):
        ret = dict()
        ret["comment"] = "pacemaker is not running"
        __context__["retcode"] = 42
        return ret
    
    if not is_quorum():
        ret = dict()
        ret["comment"] = "corosync quorum failed. Node does not have quorum partition."
        __context__["retcode"] = 42
        return ret

    if not is_cluster_idle():
        if not wait_for_cluster_idle(interval, timeout):
            ret['comment'] = "Cluster state is not idle trying function delete_cli_ban_rule."
            __context__["retcode"] = 42
        
        return ret

    # <ban id="cli-ban-msl_SAPHana_BJK_HDB00-on-hana-1" resource="msl_SAPHana_BJK_HDB00" node="hana-1" weight="-1000000" master_only="false"/>

    verify_pattern = ".*cli-ban.*{}.*node=.*{}.*".format(msl_resource_name, hostname)

    out_resources_xml = subprocess.Popen(['crm_mon', '--exclude=all', '--include=bans', '-1', '--output-as=xml'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )

    if _search_pattern(verify_pattern, out_resources_xml):

        out_resources_xml = subprocess.Popen(['crm', 'resource', 'clear', msl_resource_name ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        )
        time.sleep(3)

        if out_resources_xml.returncode != 0:
            for line in iter(out_resources_xml.stderr.readline, b''): 
                ret['clear_cli_ban_rule_output'] = ''.join(line.decode('utf-8'))

        if wait_for_cluster_idle(interval, timeout):
            out_resources_xml = subprocess.Popen(['crm_mon', '--exclude=all', '--include=bans', '-1', '--output-as=xml'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                                )
            if not _search_pattern(verify_pattern, out_resources_xml):
                ret['cleared_cli-ban'] = True
                ret['comment'] = "{} location cli-ban rule deleted.".format(msl_resource_name)
            else:
                ret['cleared_cli-ban'] = False
                ret['comment'] = "cli-ban location contraints still exist. Error."
                __context__["retcode"] = 42
                return ret
        else:
            ret['comment'] = "Checking if cluster idle timed out in delete_cli_ban_rule failed. Cluster might have problems.."
            __context__["retcode"] = 42
            return ret
    else:
        ret['comment'] = "cli-ban location contraints was not found."
        __context__["retcode"] = 42
        return ret

    return ret
    
