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
                prep_patching: orch.prep_state
                post_patching: orch.post_state
                patch_level: 2023-Q2
                
    '''

    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["Patching"] = []
    all_systems_in_groups = []
    all_to_patch_minions = {}

    ret["btrfs_disqualified"] = []
    ret["no_patch_execptions"] = []
    ret["offline_minions"] = []


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
        ret["t7user"] = "unknown"
    
    if kwargs.get("prep_patching"):
        ret["prep_patching"] = kwargs.get("prep_patching")
    else:
        ret["prep_patching"] = ""
    
    if kwargs.get("post_patching"):
        ret["post_patching"] = kwargs.get("post_patching")
    else:
        ret["post_patching"] = ""
    
    if kwargs.get("patch_level"):
        ret["patch_level"] = kwargs.get("patch_level")
    else:
        ret["patch_level"] = ""

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
        try:
            pre_patching_list, post_patching_file = _pre_patching_tasks([target_system], ret["t7user"], state_name=ret["prep_patching"])
            kwargs["masterplan_list"] = pre_patching_list["masterplan_list"]
            target_system_id = _get_systemid(client, key, target_system)
            ret1 = _patch_single(client, key, target_system_id, target_system, kwargs)
            ret["Patching"].append(ret1)
            ret["post_patching_file"] = post_patching_file
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_system, exc)
            log.error(err_msg)
            ret[target_system] = {'Error': err_msg}
    
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
            pre_patching_list, post_patching_file = _pre_patching_tasks(suma_minion_list, ret["t7user"], state_name=ret["prep_patching"],
                                                 timeout=kwargs['timeout'], gather_job_timeout=kwargs['gather_job_timeout'])
            ret["post_patching_file"] = post_patching_file
        else:
            pre_patching_list, post_patching_file = _pre_patching_tasks(suma_minion_list, ret["t7user"], state_name=ret["prep_patching"])
            ret["post_patching_file"] = post_patching_file

    
    if len(pre_patching_list["qualified_minions"]) == 0:
        ret["comment"] = "No qualified minions found. Exit."
        ret["No_qualified_minions"] = pre_patching_list
        return ret
    
    for s in list(all_systems_in_groups):
        for minion in pre_patching_list["qualified_minions"]:
            if s["name"] == minion:
                all_to_patch_minions[s["name"]] = s['id']

    ret.update({"offline_minions": pre_patching_list["offline_minions"]})
    ret.update({"no_patch_execptions": pre_patching_list["no_patch_execptions"]})
    ret.update({"btrfs_disqualified": pre_patching_list["btrfs_disqualified"]})
    kwargs["masterplan_list"] = pre_patching_list["masterplan_list"]
    #print("masterplans: {}".format(kwargs["masterplan_list"]))
                    
    log.info("final qualified minions: {}".format(all_to_patch_minions))
    print("Start patch job scheduling.")
    ret1 = _patch_single(client, key, all_to_patch_minions, kwargs)
    ret["Patching"] += ret1["Patching"]

    ret["Full_Update_Job_ID"] = []
    ret["Full_Update_Job_ID"] = ret1["Full_Update_Job_ID"]
    """ for minion_name, systemid in all_to_patch_minions.items():
            ret1 = _patch_single(client, key, systemid, minion_name, kwargs) """
            
    #print("Type of ret[Full_Update_Job_ID] is {}".format(type(ret["Full_Update_Job_ID"])))
    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)

    # only call jobchecker if list is greater than 0
    if len(ret["Patching"]) > 0:
        _send_to_jobcheck(ret)
    else:
        log.warning("No patch jobs scheduled at all, not calling jobchecker. Exit")
    return ret

def _send_to_jobcheck(results):
    print("see ret {}".format(results))
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

def _patch_single(client, key, allminions, kwargs):
    ret_single_system = dict()
    ret = dict()
    ret["Full_Update_Job_ID"] = {}
    ret["Patching"] = []

    all_scheduled_minions = []

    minion_sid_list = []

    for target_system_name, target_system_id in allminions.items():
        ret_single_system[target_system_name] = dict()
        if "masterplan_list" in kwargs.keys():
            if len(kwargs["masterplan_list"]) > 0:
                for l in kwargs["masterplan_list"]:
                    if isinstance(l, dict):
                        for name, masterplan in l.items():
                            if name == target_system_name:
                                ret_single_system[target_system_name].update({"masterplan": masterplan})

        minion_sid_list.append(target_system_id)
    
    if len(minion_sid_list) > 0:
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
            patch_job = client.system.schedulePackageUpdate(key, minion_sid_list, earliest_occurrence)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when schedule patch job: {0}. \
                Please double check if there is not already a job scheduled: {1}.'.format(exc, target_system_name)
            log.debug(err_msg)
        
        if int(patch_job) > 0:
            #print("job id {}".format(patch_job))
            for target_system_name, target_system_id in allminions.items():
                
                ret_single_system[target_system_name].update({"Patch Job ID is": patch_job, "event send": True})
                ret["Patching"].append({target_system_name: ret_single_system[target_system_name]})
                all_scheduled_minions.append(target_system_name)
                
            ret["Full_Update_Job_ID"] = []
            ret["Full_Update_Job_ID"].append({patch_job: all_scheduled_minions})
            #print("ret_single_system {}".format(ret_single_system))
            

            print("ret is: {}".format(ret))
        else:
            """ for target_system_name, target_system_id in allminions.items():
                ret[target_system_name].update({"error_message": err_msg}) """
            ret["Error Message"] = err_msg

 
    return ret

def reboot(reboot_list=None, **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and schedule reboot job for the given salt-minions

    You could provide a delay in minutes or fixed schedule time for the job in format of: "15:30 20-04-1970"

    If no delay or schedule is provided then the job will be set to run now.

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt-run sumapatch.reboot reboot_list=/srv/pillar/sumapatch/reboot_list.yaml delay=2

    Orchestrate state file example in salt://orch/patch.sls:
       
        salt-run state.orch sumapatch.reboot_t7udp_20230721213318

    .. code-block:: yaml
        
        run_patching_completed_t7udp_20230721213308:
            salt.runner:
                - name: sumapatch.reboot 
                - reboot_list: /srv/pillar/sumapatch/completed_t7udp_20230721213308
                - kwargs:
                delay: 3
                jobchecker_timeout: 20
                jobchecker_emails:
                    - max.mustermann@mydom.eu
                t7user: t7udp
                
    '''
    status = ""
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    reboot_dict = dict()
    ret = dict()
    ret["reboot_jobs"] = []
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
        ret["t7user"] = "unknown"
    
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
                                reboot_out = _reboot_single(client, key, reboot_required["id"], earliest_occurrence)
                                ret["reboot_jobs"].append({system: reboot_out})
                    else:
                        ret["reboot_jobs"].append({system :{"comment": "No reboot needed or another reboot job is pending."}})
    

    if len(ret["reboot_jobs"]) > 0:
        for system in list(ret["reboot_jobs"]):
            if isinstance(system, dict):
                for key, val in system.items():
                    if not isinstance(val, dict):
                        ret["reboot_jobs"].remove(system)
                    if not "Reboot Job ID is" in val.keys():
                        ret["reboot_jobs"].remove(system)
            else:
                ret["reboot_jobs"].remove(system)
    
    # only call jobchecker if list is greater than 0
    if len(ret["reboot_jobs"]) > 0:
        result_to_jobchecker = copy.deepcopy(ret)
        result_to_jobchecker["Patching"] = copy.deepcopy(ret["reboot_jobs"])
        print(result_to_jobchecker)
        _send_to_jobcheck(result_to_jobchecker)
    else:
        log.warning("No reboot jobs scheduled at all, not calling jobchecker. Exit")

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
            return {"Reboot Job ID is": result_reboot_job}

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
