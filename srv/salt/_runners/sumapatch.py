# -*- coding: utf-8 -*-
'''
SUMA api runner
================

.. versionadded:: 3004-150400.8.17.7

Runner to interact with SUSE Manager using xmlrpc API

To use this runner, set up the SUMA URL, username and password in the
master configuration at ``/etc/salt/master`` or ``/etc/salt/master.d/suma_api.conf``:

.. code-block:: yaml

    suma_api:
      suma01.domain.com:
        username: 'testuser'
        password: 'encrypted-password'

.. note::
    To generate encrypted password use encrypt.py found on github

    Optionally, ``protocol`` can be specified if the SUMA server is
    not using the defaults. Default is ``protocol: https``.

'''
from __future__ import absolute_import, print_function, unicode_literals
from cryptography.fernet import Fernet
# Import python libs
import atexit
import logging
import os
import urllib3
import yaml
import json
import time
import subprocess
import salt.client
from salt.ext import six
from datetime import datetime,  timedelta

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler = logging.FileHandler('/var/log/patching/patching.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

log.addHandler(file_handler)

_sessions = {}


def __virtual__():
    '''
    Check for suse manager configuration in master config file
    or directory and load runner only if it is specified
    '''
    if not _suma_configuration():
        return False, 'No suma_api configuration found'
    return True

def _suma_configuration(suma_url=''):
    '''
    Verify if suma_api configuration is set otherwise not loading this module.
    '''
    if 'suma_api' in __opts__:    
        return True
    else:
        return False
    

def _decrypt_password(password_encrypted):
    
    encrypted_pwd = ""
    if not os.path.exists("/srv/pillar/sumakey.sls"):
        print("No /srv/pillar/sumakey.sls found")
        if os.environ.get('SUMAKEY') == None: 
            log.fatal("You don't have ENV SUMAKEY set. Use unencrypted pwd.")
            return str(password_encrypted)
        else:
            
            encrypted_pwd = os.environ.get('SUMAKEY')
    else:
        
        with open("/srv/pillar/sumakey.sls", 'r') as file:
            # Load the YAML data into a dictionary
            sumakey_dict = yaml.safe_load(file)
            encrypted_pwd = sumakey_dict["SUMAKEY"]

    if not encrypted_pwd == "":
        saltkey = bytes(str(encrypted_pwd), encoding='utf-8')
        fernet = Fernet(saltkey)
        encmessage = bytes(str(password_encrypted), encoding='utf-8')
        pwd = fernet.decrypt(encmessage)
    else:
        log.fatal("encrypted_pwd is empty. Use unencrypted pwd.")
        return str(password_encrypted)        
    
    return pwd.decode()

def _get_suma_configuration(suma_url=''):
    '''
    Return the configuration read from the master configuration
    file or directory
    '''
    suma_config = __opts__['suma_api'] if 'suma_api' in __opts__ else None

    if suma_config:
        try:
            for suma_server, service_config in six.iteritems(suma_config):
                username = service_config.get('username', None)
                password_encrypted = service_config.get('password', None)
                password = _decrypt_password(password_encrypted)
                protocol = service_config.get('protocol', 'https')

                if not username or not password:
                    log.error(
                        'Username or Password has not been specified in the master '
                        'configuration for %s', suma_server
                    )
                    return False

                ret = {
                    'api_url': '{0}://{1}/rpc/api'.format(protocol, suma_server),
                    'username': username,
                    'password': password,
                    'servername': suma_server
                }

                if (not suma_url) or (suma_url == suma_server):
                    return ret
        except Exception as exc:  # pylint: disable=broad-except
            log.error('Exception encountered: %s', exc)
            return False

        if suma_url:
            log.error(
                'Configuration for %s has not been specified in the master '
                'configuration', suma_url
            )
            return False

    return False


def _get_client_and_key(url, user, password, verbose=0):
    '''
    Return the client object and session key for the client
    '''
    session = {}
    session['client'] = six.moves.xmlrpc_client.Server(url, verbose=verbose, use_datetime=True)
    session['key'] = session['client'].auth.login(user, password)

    return session


def _disconnect_session(session):
    '''
    Disconnect API connection
    '''
    session['client'].auth.logout(session['key'])


def _get_session(server):
    '''
    Get session and key
    '''
    if server in _sessions:
        return _sessions[server]

    config = _get_suma_configuration(server)
    if not config:
        raise Exception('No config for \'{0}\' found on master'.format(server))

    session = _get_client_and_key(config['api_url'], config['username'], config['password'])
    atexit.register(_disconnect_session, session)

    client = session['client']
    key = session['key']
    _sessions[server] = (client, key)

    return client, key

def prep_patching(minion_list):
    grains_info = []
    minion_list_without_poor_size = []
    minion_list_with_poor_size = []
    local = salt.client.LocalClient()
    #print("minion_list: {}".format(list(minion_list)))
    ret_sync = []
    print("sync grains files to minions.")
    ret1 = local.cmd_batch(list(minion_list), 'saltutil.sync_grains', tgt_type="list", batch='10%')
    for result in ret1:
        ret_sync.append(result)
        ret_sync.remove(result)
    #print("ret_sync {}".format(ret_sync))

    ret_refresh = []
    print("refresh grains on minions.")
    ret2 = local.cmd_batch(list(minion_list), 'saltutil.refresh_grains', tgt_type="list", batch='10%')
    for result in ret2:
        ret_refresh.append(result)
        ret_refresh.remove(result)
    #print("ret_refresh {}".format(ret_refresh))

    print("get btrfs grains on minions.")
    ret = local.cmd_batch(list(minion_list), 'grains.get', ["btrfs:for_patching"], tgt_type="list", batch='10%')
    for result in ret:
        grains_info.append(result)
        if isinstance(result, dict):
            for a, b in result.items():
                if b != "" or b == "ok":
                    minion_list_without_poor_size.append(a)
                if b == "no":
                    minion_list_with_poor_size.append(a)

    print("rebuild rpm DB.")
    ret_rpm = []
    ret_rpm_rebuild = local.cmd_iter_no_block(list(minion_list), 'cmd.run', ["rpm --rebuilddb"], tgt_type="list")
    for i in ret_rpm_rebuild:
        #print(i)
        ret_rpm.append(i)
        ret_rpm.remove(i)
    
    print("stop ds_agent.service")
    ret_stop_svc = []
    ret_stop_service = local.cmd_iter_no_block(list(minion_list), 'service.stop', ["postfix.service", "no_block=True"], tgt_type="list")
    for i in ret_stop_service:
        #print(i)
        ret_stop_svc.append(i)
        ret_stop_svc.remove(i)
    
    print("entire minion_list_without_poor_size {}".format(minion_list_without_poor_size))
    print("entire minion_list_with_poor_size {}".format(minion_list_with_poor_size))
    return minion_list_without_poor_size, minion_list_with_poor_size

def _get_grains_info(minion_list):
    grains_info = []
    local = salt.client.LocalClient()
    #print("minion_list: {}".format(list(minion_list)))
    #_ = local.cmd_batch(list(minion_list), 'saltutil.refresh_grains', tgt_type="list", batch='10%')
    minion_list, _ = prep_patching(minion_list)
    ret = local.cmd_batch(list(minion_list), 'grains.get', ["srvinfo:INFO_MASTERPLAN"], tgt_type="list", batch='10%')
    for result in ret:
        grains_info.append(result)
        #print("MASTERPLAN: {}".format(grains_info))
    #print("entire dict grains_info {}".format(grains_info))
    return grains_info

def patch(target_system=None, groups=None, **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and schedule a apply_all_patches job for the given salt-minion name

    You could provide a delay in minutes or fixed schedule time for the job in format of: "15:30 20-04-1970"

    If no delay or schedule is provided then the job will be set to now.

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt-run sumapatch.patch minion_name delay=15

    Orchestrate state file example in salt://orch/patch.sls:
       
        salt-run state.orch orch.patch

    .. code-block:: yaml
        
        run_patching:
          salt.runner:
            - name: sumapatch.patch 
            - groups:
              - P-Basis-suma
              - testgrp
            - kwargs:
                delay: 60
                logfile: /var/log/patching/sumapatch.log
                t7user: t7udp
                grains: 
                  no_patch: False
                timeout: 2
                gather_job_timeout: 15
                jobchecker_timeout: 20
                jobchecker_emails:
                  - abc@example.com
                  - xyz@example.com
                
    '''

    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["Patching"] = []
    all_systems_in_groups = []
    all_to_patch_minions = {}
    offline_minions = []

    result = subprocess.check_output(["logname"])
    #print("logname output: {}".format(result.decode('utf-8').replace('\n', '')))
    log.info("logname output: {}".format(result.decode('utf-8').replace('\n', '')))
    ret["user"] = result.decode('utf-8').replace('\n', '')

    if kwargs.get("jobchecker_emails"):
        ret["jobchecker_emails"] = []
        ret["jobchecker_emails"] = kwargs.get("jobchecker_emails")
        print("jobchecker emails: {}".format(ret["jobchecker_emails"]))
        
    if kwargs.get("jobchecker_timeout"):
        if kwargs.get('delay'):
            ret["jobchecker_timeout"] = kwargs["delay"] + kwargs["jobchecker_timeout"]
            ret["jobstart_delay"] = kwargs["delay"]
        else:
            ret["jobchecker_timeout"] = kwargs["jobchecker_timeout"]
            ret["jobstart_delay"] = 0
    else:
        ret["jobchecker_timeout"] = 30
        if kwargs.get('delay'):
            ret["jobstart_delay"] = kwargs["delay"]
        else:
            ret["jobstart_delay"] = 0
    
    if kwargs.get("t7user"):
        ret["t7user"] = kwargs.get("t7user")
    else:
        ret["t7user"] = kwargs.get("unknown")

    if 'logfile' in kwargs:
        #mylog = logging.getLogger()  # root logger - Good to get it only once.
        for hdlr in log.handlers[:]:  # remove the existing file handlers
            if isinstance(hdlr,logging.FileHandler): #fixed two typos here
                log.removeHandler(hdlr)

        file_handler_custom = logging.FileHandler(kwargs['logfile'])
        file_handler_custom.setLevel(logging.DEBUG)
        file_handler_custom.setFormatter(formatter)
        log.addHandler(file_handler_custom) 


    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    # here we ensure the minions are really online
    
    if kwargs.get("timeout") and kwargs.get("gather_job_timeout"):
        present_minions = _minion_presence_check(timeout=kwargs['timeout'],
                                                 gather_job_timeout=kwargs['gather_job_timeout'])
    else:
        present_minions = _minion_presence_check()

    if target_system:
        try:
            #minion_names = client.saltkey.acceptedList(key)
            if target_system in list(present_minions):
                masterplan_list = _get_grains_info([target_system])
                kwargs["masterplan_list"] = masterplan_list
                target_system_id = _get_systemid(client, key, target_system)
                ret1 = _patch_single(client, key, target_system_id, target_system, kwargs)
                ret["Patching"].append(ret1)
                present_minions.remove(target_system)
                print("present minions {}".format(present_minions))
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_system, exc)
            log.error(err_msg)
            ret[target_system] = {'Error': err_msg}
    
    if groups:
        for g in groups:
            try:
                systems_in_groups = client.systemgroup.listSystemsMinimal(key, g)
                all_systems_in_groups += systems_in_groups              
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to get active minion list from group ({0}): {1}'.format(g, exc)
                log.error(err_msg)

    if len(all_systems_in_groups) > 0:
        for s in list(all_systems_in_groups):
            if target_system == s["name"]:
                all_systems_in_groups.remove(s)
                continue
            if not s["name"] in present_minions:
                offline_minions.append(s["name"])
                all_systems_in_groups.remove(s)
                log.warning("salt-run manage.up query says {} is not online.".format(s["name"]))
                continue
            else:
                all_to_patch_minions[s["name"]] = s['id']
    else:
        ret["comment"] = "No minion in SUMA groups found. Exit."
        return ret
    
    ret.update({"offline_minions": offline_minions})

    if len(all_to_patch_minions.keys()) > 0:
        masterplan_list = _get_grains_info(all_to_patch_minions.keys())
        kwargs["masterplan_list"] = masterplan_list
        #print("masterplans: {}".format(kwargs["masterplan_list"]))

    if 'grains' in kwargs:
        for x, y in kwargs['grains'].items():
            for p in list(all_to_patch_minions.keys()):
                print("all_to_patch_minions.keys {}".format(p))
                output_grains = __salt__['salt.execute'](p, 'grains.get', [x])
                if not output_grains.get(p, None):
                    print("skip {}".format(p))
                    continue
                if not y == output_grains.get(p, None):
                    print("grains {}: {} for <{}>".format(x, y, p))
                    del all_to_patch_minions[p]
                    log.info("Remove {} from all_to_patch_minions list due to grains query result: \
                             {}: {}".format(p, x, y))
                    
    log.info("final all_to_patch_minions {}".format(all_to_patch_minions))
    """ for minion_name, systemid in all_to_patch_minions.items():
            ret1 = _patch_single(client, key, systemid, minion_name, kwargs)
            ret["Patching"].append(ret1) """

    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)
    
    #print("ret[Patching]: {}".format(ret["Patching"]))
    # below we remove all elements from list if val not dict
    if len(ret["Patching"]) > 0:
        for system in list(ret["Patching"]):
            if isinstance(system, dict):
                for key, val in system.items():
                    if not isinstance(val, dict):
                        ret["Patching"].remove(system)
                    if not "Patch Job ID is" in val.keys():
                        ret["Patching"].remove(system)
            else:
                ret["Patching"].remove(system)

    # only call jobchecker if list is greater than 0
    if len(ret["Patching"]) > 0:
        _send_to_jobcheck(ret)
    else:
        log.warning("No patch jobs scheduled at all, not calling jobchecker. Exit")
    return ret

def _send_to_jobcheck(results):
    uri = 'http://127.0.0.1:12345/jobchecker'
    body = results
    headers = {}
    method = 'POST'
    timeout = 120.0

    pool = urllib3.PoolManager(timeout=timeout, retries=urllib3.util.retry.Retry(15))
    headers.update({'Content-Type': 'application/json', 'Connection': 'close', \
                    'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 \
                        (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17'})

    if body is not None and not isinstance(body, str):
        body = json.dumps(body).encode('utf-8')

    #print('[Request]: %s url=%s, headers=%s, body=%s' % (method, uri, headers, body))
    if body:
        headers['Content-Length'] = len(body)
        try:
            rsp = pool.request(method, uri, body=body, headers=headers)
            print('status: {}, {}'.format(rsp.status, rsp.data.decode('utf-8')))
            return
        except Exception as e:
            log.error("Connecting to jobchecker failed: {}".format(e))
            print(e)
            return
    
    return True

def _minion_presence_check(timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout], print_event=False)
    return online_minions
    

def _write_logs(input, logfile="/var/log/patching/patching.log"):
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    with open(logfile, 'a+') as f:
        f.write("sumapatch.patch executed --- {}\n".format(dt_string))
        for key, value in input.items(): 
            f.write("{}:\n".format(key))
            if type(value) == list:
                for i in value:
                    if type(i) == dict:
                        for s, x in i.items():
                            f.write('%s:\n' % (s))
                            if type(x) == dict:
                                for d, h in x.items():
                                    f.write('\t%s: %s\n' % (d, h))
                    else:
                        f.write("\t{}\n".format(i))
            else:
                f.write("{}\n".format(value))
    return

def _get_systemid(client, key, target_system):
    if target_system != "":
        try:
            getid_ret = client.system.getId(key, target_system)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} system ID: {0}'.format(exc, target_system)
            log.error(err_msg)

        if getid_ret:
            id = getid_ret[0]['id']
            return id
    return 

def _patch_single(client, key, target_system_id, target_system_name, kwargs):
    errata_id_list = []
    error_ret = dict()
    ret = dict()
    ret[target_system_name] = dict()
    if "masterplan_list" in kwargs.keys():
        if len(kwargs["masterplan_list"]) > 0:
            for l in kwargs["masterplan_list"]:
                if isinstance(l, dict):
                    for name, masterplan in l.items():
                        if name == target_system_name:
                            ret[target_system_name].update({"masterplan": masterplan})

    if target_system_id:
        try:
            errata_list = client.system.getRelevantErrata(key, target_system_id)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} all patch ID: {0}'.format(exc, target_system_id)
            log.error(err_msg)
            ret[target_system_name].update({"error_message": err_msg})
            return ret

        if errata_list and len(errata_list) > 0:
            for x in errata_list:
                errata_id_list.append(x['id'])
        else:
            info_msg = '{}: It looks like the system is fully patched.'.format(target_system_name)
            log.info(info_msg)
            ret[target_system_name].update({"info_message": info_msg})
            return ret

        
        if "delay" in kwargs.keys():
            delay = kwargs['delay']
            if int(delay) >= 0:
                nowlater = datetime.now() + timedelta(minutes=int(delay))
        
        if "schedule" in kwargs.keys():
            schedule = kwargs['schedule']
            nowlater = datetime.strptime(schedule, "%H:%M %d-%m-%Y")
        
        if not "delay" in kwargs.keys() and not "schedule" in kwargs.keys():
            nowlater = datetime.now()

        earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
        try:
            patch_job = client.system.scheduleApplyErrata(key, target_system_id, errata_id_list, earliest_occurrence, True)
            if patch_job:
                local = salt.client.LocalClient()
                local.cmd(target_system_name, 'event.send', ['suma/patch/job/id', \
                            {"node": target_system_name, "jobid": patch_job[0]}])
                log.info("SUMA Patch job {} created for {}".format(patch_job, target_system_name))     
                ret[target_system_name].update({"Patch Job ID is": patch_job[0], "event send": True})
                return ret
            
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when schedule patch job: {0}. \
                Please double check if there is not already a job scheduled: {1}.'.format(exc, target_system_name)
            log.debug(err_msg)
            ret[target_system_name].update({"error_message": err_msg})
            return ret
 
    return ret

def reboot(reboot_list=None, **kwargs):
    status = ""
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    reboot_dict = dict()
    ret = dict()
    ret["reboot_jobs"] = {}
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    if kwargs.get("delay"):
        if int(kwargs['delay']) > 0:
            delay = kwargs['delay']
            nowlater = datetime.now() + timedelta(minutes=int(delay))
        else:
            nowlater = datetime.now() + timedelta(minutes=2)
    
    if not reboot_list == None:
        # Open the YAML file
        reboot_file = reboot_list
        with open(reboot_file, 'r') as file:
            # Load the YAML data into a dictionary
            reboot_dict = yaml.safe_load(file)

    already_reboot_pending = _check_existing_reboot_jobs(client, key)
    reboot_required_list = _reboot_required(client, key)

    for reboot_required in list(reboot_required_list):
        if reboot_required["id"] in already_reboot_pending:
            reboot_required_list.remove(reboot_required)

    earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    if len(reboot_dict.keys()) > 0:
        for i in reboot_dict.keys():
            if isinstance(reboot_dict[i], list):
                for system in reboot_dict[i]:
                    if any(system in d.values() for d in reboot_required_list):
                        for reboot_required in reboot_required_list: 
                            if reboot_required["name"] == system:
                                ret["reboot_jobs"][system] = _reboot_single(client, key, reboot_required["id"], earliest_occurrence)
                    else:
                        ret["reboot_jobs"][system] = {"comment": "No reboot needed or another reboot job is pending."}
    return ret

def _reboot_required(client, key):
    
    try:
        result_reboot_required = client.system.listSuggestedReboot(key)
        #print("result_systemid {}".format(result_systemid))
        print("reboot list: {}".format(result_reboot_required))
        return result_reboot_required
    except Exception as exc:
        err_msg = 'Exception raised while trying to get reboot required list: ({0})'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}

def _check_existing_reboot_jobs(client, key):
    pending_reboot_systems = []
    try:
        result_inProgressActions = client.schedule.listInProgressActions(key) 
    except Exception as exc:
        err_msg = 'Exception raised while trying to get pending job list: ({0})'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}

    for action in list(result_inProgressActions):
        #print("action: {} {}".format(action["name"], action["type"]))
        if not "System reboot" in action["name"]:
            result_inProgressActions.remove(action)
    
    for inprogress in result_inProgressActions:
        try:
            result_inProgressSystems = client.schedule.listInProgressSystems(key, inprogress["id"])
            for result in result_inProgressSystems:
                pending_reboot_systems.append(result["server_id"])
        except Exception as exc:
            err_msg = 'Exception raised while trying to get pending jobs in progress systems: ({0})'.format(exc)
            log.error(err_msg)
            return {'Error': err_msg}

    return pending_reboot_systems

def _reboot_single(client, key, server_id, earliest_occurrence):
    try:
        result_reboot_job = client.system.scheduleReboot(key, server_id, earliest_occurrence)
    except Exception as exc:
        log.error("schedule reboot failed. {} {}".format(server_id, exc))
        return {'Error': exc}

    if int(result_reboot_job) > 0:
            log.info("SUMA Reboot job {} created for {}".format(result_reboot_job, server_id))
            #print("SUMA Reboot job {} created for {}".format(result_reboot_job, target_system))
            return {"Reboot Job ID is": result_reboot_job}
    
