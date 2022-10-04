from __future__ import absolute_import, unicode_literals, print_function
import logging

from salt import exceptions
import salt.utils.path
import subprocess
import socket
import os
import re

# precheck state module call bocrm.sync_status execution module and checks if cluster current state is ok for starting a maintenance task.
def precheck(name):
    ret = dict()
    minion_id = __salt__['grains.get']('id')
    if __opts__['test']:
        ret['name'] = 'HANA SR Scale up Cluster pre-check'
        ret['changes'] = dict()
        ret['result'] = None
        ret['comment'] = 'We check the cluster status {0}'.format(minion_id)
        return ret
    
    if "hana_info" in __grains__.keys():
        del __grains__["hana_info"]
        print("----hana_info deleted-----")

    try:
        ret_from_mod = __salt__["bocrm.sync_status"]()
        
    except:
        ret["name"] = "HANA SR Scale up Cluster pre-check"
        ret['changes'] = {
            "old": "Nothing",
            "new": "the execution module bocrm.sync_status could not be loaded. The reason could be that dependant binaries are not available. crmsh and ClusterTools2 packages",
        }
        ret['comment'] = "Something went wrong."
        ret['result'] = False
        return ret


    ret['name'] = 'HANA SR Scale up Cluster pre-check'
    if not ret_from_mod:
        ret['changes'] = {"Fatal Error": "No result found from bocrm.sync_status"}
        ret['comment'] = "Something is not ok with the HANA Cluster. Do not patch OS."
        ret['result'] = False

    if not ret_from_mod["maintenance_approval"]:
        ret["result"] = False
        ret['comment'] = "Something is not ok with the HANA Cluster. Do not patch OS."
        ret['changes'] = {
            "old": "Nothing",
            "new": ret_from_mod,
        }
    
    if ret_from_mod["maintenance_approval"]:
        ret["result"] = True
        ret['comment'] = "HANA Cluster is looking good."
        ret['changes'] = {
            "old": "Nothing",
            "new": ret_from_mod,
        }   

    return ret

def set_msl_maintenance(name, msl_resource):
    """
    Set pacemaker master-slave resource to maintenance mode

    This state module does a custom thing. It calls out to the execution module
    ``crmhana`` in order to check the current system and perform any
    needed changes.

    name:
        you can provide any name for this param.
        A required argument
    msl_resource:
        provide the pacemaker master-slave resource name.
        This is a required argument. e.g. msl_SAPHana_BJK_HDB00
    
    Usage:

    .. code-block:: yaml

        maint_hana-secondary:
          crmhana.set_msl_maintenance:
            - name: hana
            - msl_resource: msl_SAPHana_BJK_HDB00

    :param name: a string
    :param msl_resource: a string
    :return: a dict with output from the execution module ``bocrm.set_msl_maintenance``
    """
    ret = {
        "name": name,
        "changes": {},
        "result": False,
        "comment": "",
    }

    try:
        ret_from_mod = __salt__["bocrm.set_msl_maintenance"](msl_resource)
    except:
        ret["name"] = "HANA SR Scale up - set {} into maintenance".format(msl_resource)
        ret['changes'] = {
            "old": "{}".format(msl_resource),
            "new": "the execution module bocrm.set_msl_maintenance failed.",
        }
        ret['comment'] = "Something went wrong."
        ret['result'] = False
        return ret
    
    if not ret_from_mod:
        ret['changes'] = {"Fatal Error": "No result found from bocrm.set_msl_maintenance"}
        ret['comment'] = "Something is not ok with the HANA Cluster. Do not patch OS."
        ret['result'] = False
    
    if ret_from_mod["msl_maintenance"]:
        ret['changes'] = {
            "old": "Nothing",
            "new": ret_from_mod,
        }   
        ret['comment'] = "msl resource is in maintenance. HANA Secondary node can be patched."
        ret['result'] = True
    else:
        ret['changes'] = {
            "old": "Nothing",
            "new": ret_from_mod,
        }   
        ret['comment'] = "msl resource is NOT maintenance. Do not continue."
        ret['result'] = False

    return ret