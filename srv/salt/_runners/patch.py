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
import copy
import subprocess
import salt.client
import six
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

def _write_post_patching_list(minion_list, t7user):
        now = datetime.now()
        date_time = now.strftime("%Y%m%d%H%M%S")
        post_patching_list = {}
        post_patching_list["post_patching_minions"] = []
        post_patching_list["post_patching_minions"] = minion_list
        file_path = "/srv/pillar/sumapatch/post_patching_minions_{}_{}.sls".format(t7user, date_time)
        
        # convert the dictionary to YAML
        if len(post_patching_list["post_patching_minions"]) > 0:
            yaml_data = yaml.dump(post_patching_list)
            # write the YAML data to a file
            with open(file_path, 'w+') as file:
                file.write(yaml_data)
                log.info("Post Patching system list has been written to: {}".format(file_path))
                print("Post Patching system list has been written to: {}".format(file_path))

        return file_path

def _pre_patching_tasks(minion_list, t7user, state_name="", timeout=2, gather_job_timeout=10):
    print("Execut salt runner module - prep_patching.run")
    runner = salt.runner.RunnerClient(__opts__)
    prep_patching_list = runner.cmd('prep_patching.run', [minion_list, state_name, timeout, gather_job_timeout], print_event=False)
    # write out the minion list for post patching tasks.
    post_patching_output = _write_post_patching_list(list(prep_patching_list["qualified_minions"]), t7user)

    return prep_patching_list, post_patching_output

def _set_patch_job_grains(minion_name, job):
    local = salt.client.LocalClient()
    print("set grains for {}: {} type: {}".format(minion_name, job, type(job)))
    jobid = job[0]["JobID"]
    jobstatus = job[1]["Status"]
    #local.cmd_async(minion_name, 'grains.set', ["suma_job:JobID", "{}".format(job[0]["JobID"])], force=True, destructive=True)
    local.cmd(minion_name, 'grains.delkey', ["suma_job"], force=True, destructive=True)
    local.cmd_async(minion_name, 'grains.set', ["suma_job:JobID", "val={}".format(jobid)], force=True, destructive=True)
    local.cmd_async(minion_name, 'grains.set', ["suma_job:Status", "val={}".format(jobstatus)], force=True, destructive=True)
    return

def _set_patch_job_sdb(minion_name, job):
    local = salt.client.LocalClient()
    print("set sdb for {}: {} type: {}".format(minion_name, job, type(job)))
    jobid = job[0]["JobID"]
    jobstatus = job[1]["Status"]
    sdb_uri = "sdb://patching_info/bo"
    sdb_val = 'JobID: {}\nStatus: {}'.format(jobid, jobstatus)
    #local.cmd_async(minion_name, 'grains.set', ["suma_job:JobID", "{}".format(job[0]["JobID"])], force=True, destructive=True)
    local.cmd(minion_name, 'sdb.set', [sdb_uri, sdb_val])
    
    return

def patch(target_systems=[], **kwargs):
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
            - target_systems:
              - minion1
              - minion2
              - minion3
            - kwargs:
                delay: 60
                logfile: /var/log/patching/sumapatch.log
        
        cmd:
        salt-run patch.patch target_systems='["pxesap02.bo2go.home", "pxesap01.bo2go.home"]' delay=5
                
    '''
    log.debug("----------------------------args: {} kwargs: {}".format(target_systems, kwargs))
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["Patching"] = []
    

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


    if target_systems:
        if isinstance(target_systems, list):
            for target_system in list(set(target_systems)):
                try:
                    target_system_id = _get_systemid(client, key, target_system)
                    ret1 = _patch_single(client, key, target_system_id, target_system, kwargs)
                    if isinstance(ret1, int) and ret1:
                        job_obj = [{"JobID": ret1}, {"Status": "scheduled"}]
                        _set_patch_job_sdb(target_system, job_obj)
                        ret["Patching"].append({target_system: job_obj})

                    else:
                        job_obj = [{"JobID": 0}, {"Status": "scheduling failed"}]
                        _set_patch_job_sdb(target_system, job_obj)
                        ret["Patching"].append({target_system: job_obj})
                    
                except Exception as exc:
                    err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_system, exc)
                    log.error(err_msg)
                    ret[target_system] = {'Error': err_msg}
        else:
            try:
                target_system_id = _get_systemid(client, key, target_systems)
                ret1 = _patch_single(client, key, target_system_id, target_systems, kwargs)
                print("instance of ret1: {}: {}".format(type(ret1), ret1))
                if isinstance(ret1, int) and ret1:
                    job_obj = [{"JobID": ret1}, {"Status": "scheduled"}]
                    _set_patch_job_sdb(target_systems, job_obj)
                    ret["Patching"].append({target_systems: job_obj})
                else:
                    job_obj = [{"JobID": 0}, {"Status": "scheduling failed"}]
                    _set_patch_job_sdb(target_systems, job_obj)
                    ret["Patching"].append({target_systems: job_obj})
                
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_systems, exc)
                log.error(err_msg)
                ret[target_systems] = {'Error': err_msg}
    

    suma_minion_list = []
    
    #print("Start patch job scheduling.")
    
    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)

    return ret

def _send_to_jobcheck(results):
    print("see ret {}".format(results))
    uri = 'http://192.168.122.1:12345/jobchecker'
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
    ret_single_system = dict()
    ret = dict()
    ret["Full_Update_Job_ID"] = {}
    ret["Patching"] = []

    minion_sid_list = [target_system_id]
    
    print("kwargs: {}".format(kwargs))
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
    patch_job = 0
    try:
        patch_job = client.system.schedulePackageUpdate(key, minion_sid_list, earliest_occurrence)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when schedule patch job: {0}. \
            Please double check if there is not already a job scheduled: {1}.'.format(exc, target_system_name)
        log.debug(err_msg)
        
    if int(patch_job) > 0:
        return patch_job
    else:
        log.warning("something went wrong while system.schedulePackageUpdate for {}".format(target_system_name))
        return 0

 
    return ret

def reboot(target_systems=[], **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and schedule reboot job for a given salt-minions

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt-run patch.reboot target_systems=mytest.example.com

    Orchestrate state file example in salt://orch/patch.sls:
       
        salt-run state.orch patch.reboot

    .. code-block:: yaml
        
        run_patching_reboot:
            salt.runner:
                - name: patch.reboot 
                - target_systems: 
                  - minion 1
                  - minion 2
                  - minion 3
    
    Or from salt-master command line:
    .. code-block:: bash
        salt-run patch.reboot target_systems="[pxesap01.bo2go.home, pxesap02.bo2go.home, pxesap03.bo2go.home]"
    
    '''
    
    status = ""
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    reboot_dict = dict()
    ret = dict()
    ret["reboot_job"] = []
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
    else:
        nowlater = datetime.now() + timedelta(minutes=2)
    

    earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    
    if isinstance(target_systems, list):
        for target_system in list(set(target_systems)):
            try:
                target_system_id = _get_systemid(client, key, target_system)
            except Exception as exc:
                err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_system, exc)
                log.error(err_msg)
                ret[target_system] = {'Error': err_msg}
            
            if target_system_id != 0:
                ret1 = _reboot_single(client, key, target_system_id, earliest_occurrence)
                ret["reboot_job"].append({target_system: ret1})
    else:
        try:
            target_system_id = _get_systemid(client, key, target_systems)
        except Exception as exc:
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_systems, exc)
            log.error(err_msg)
            ret[target_systems] = {'Error': err_msg}
        
        if target_system_id != 0:
            ret1 = _reboot_single(client, key, target_system_id, earliest_occurrence)
            ret["reboot_job"].append({target_systems: ret1})

    return ret

def _reboot_required(client, key):
    
    try:
        result_reboot_required = client.system.listSuggestedReboot(key)
        #print("result_systemid {}".format(result_systemid))
        #print("reboot list: {}".format(result_reboot_required))
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
            return {"JobID": result_reboot_job}
    else:
        log.error("SUMA Reboot job creation failed for {}".format(server_id))
        return {"JobID": 0}

def _schedule_pkg_refresh_job(client, key, target_system_id, target_system, kwargs):
    ret = dict()
    ret[target_system] = {}
    nowlater = datetime.now()
    if kwargs.get("delay"):
        if int(kwargs['delay']) > 0:
            delay = kwargs['delay']
            nowlater = datetime.now() + timedelta(minutes=int(delay))
        else:
            nowlater = datetime.now() + timedelta(minutes=2)
    
    earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    if target_system_id:
        
        try:
            refresh_job_id = client.system.schedulePackageRefresh(key, target_system_id, earliest_occurrence)
            ret[target_system].update({"Pkg refresh Job ID": refresh_job_id})
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} schedule pkg refresh job: {0}'.format(exc, target_system)
            log.error(err_msg)
            ret[target_system].update({"error_message": err_msg})
            return ret
        
    return ret

def _minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    
    minion_status_list = runner.cmd('manage.status', ["tgt={}".format(minion_list), "tgt_type=list", timeout, gather_job_timeout], print_event=False)

    return minion_status_list

def refresh_package_list(target_system=None, groups=None, **kwargs):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["refresh_package_list"] = []
    all_systems_in_groups = []
    all_to_refresh_minions = {}

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
    
    if target_system:
        
        if target_system != "":
            try:
                target_system_id = _get_systemid(client, key, target_system)
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to find minion id ({0}): {1}'.format(target_system, exc)
                log.error(err_msg)
                ret[target_system] = {'Error': err_msg}
            
            ret1 = _schedule_pkg_refresh_job(client, key, target_system_id, target_system, kwargs)
            ret["refresh_package_list"].append(ret1)            
    
    if groups:
        print("Query systems in the SUMA groups.")
        for g in groups:
            try:
                systems_in_groups = client.systemgroup.listSystemsMinimal(key, g)
                all_systems_in_groups += systems_in_groups              
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to get active minion list from group ({0}): {1}'.format(g, exc)
                log.error(err_msg)

    suma_minion_list = []
    if len(all_systems_in_groups) == 0:
        ret["comment"] = "No minion in SUMA groups found. Exit."
        return ret
        
    for s in list(all_systems_in_groups):
        if target_system == s["name"]:
            all_systems_in_groups.remove(s)
            continue
        else:
            suma_minion_list.append(s["name"])
    
    if len(all_systems_in_groups) > 0:
        if kwargs.get("timeout") and kwargs.get("gather_job_timeout"):
            online_minion_list = _minion_presence_check(suma_minion_list, timeout=kwargs['timeout'], 
                                                 gather_job_timeout=kwargs['gather_job_timeout'])
        else:
            online_minion_list = _minion_presence_check(suma_minion_list)

    for s in list(all_systems_in_groups):
        for minion in online_minion_list["up"]:
            if s["name"] == minion:
                all_to_refresh_minions[s["name"]] = s['id']
    #print(all_to_refresh_minions)

    for minion_name, systemid in all_to_refresh_minions.items():
            ret1 = _schedule_pkg_refresh_job(client, key, systemid, minion_name, kwargs)
            ret["refresh_package_list"].append(ret1)

    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)
    
    #print("ret[Patching]: {}".format(ret["Patching"]))
    # below we remove all elements from list if val not dict
    if len(ret["refresh_package_list"]) > 0:
        for system in list(ret["refresh_package_list"]):
            if isinstance(system, dict):
                for key, val in system.items():
                    if not isinstance(val, dict):
                        ret["refresh_package_list"].remove(system)
                    if not "Pkg refresh Job ID" in val.keys():
                        ret["refresh_package_list"].remove(system)
            else:
                ret["refresh_package_list"].remove(system)

    return ret
