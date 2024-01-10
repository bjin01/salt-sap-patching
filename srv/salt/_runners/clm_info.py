# -*- coding: utf-8 -*-
'''
SUMA Channels - salt runner module
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

import yaml
import re
import salt.client
import six
from datetime import datetime,  timedelta

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
    __context__: Any = None


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

def _write_to_file(file, data):
    with open(file, 'w') as f:
        yaml.dump(data, f)
    return

def _all_minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence from all systems...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    """ timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout) """
    minion_status_list = runner.cmd('manage.status', ["tgt={}".format(minion_list), "tgt_type=list", timeout, gather_job_timeout], print_event=False)

    return minion_status_list


def _list_clm():
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    
    clm = dict()
    
    try:
        clm_projects = client.contentmanagement.listProjects(key)
        #print(all_systems_in_groups)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised trying to get clm projects: {}'.format(exc)
        log.error(err_msg)

    if clm_projects and len(clm_projects) > 0:
        for project in clm_projects:
            #print(project)
            try:
                clm_project_environments = client.contentmanagement.listProjectEnvironments(key, project["label"])
                #print(clm_project_environments)
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to get clm project environments: {}'.format(exc)
                log.error(err_msg)
            
            if clm_project_environments and len(clm_project_environments) > 0:
                clm[project["label"]] = []
                for environment in clm_project_environments:
                    clm[project["label"]].append(environment["label"])
    else:
        print("No clm project found.")
        return
    
    return clm
   
               
def _get_systemid(host):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    result_sid = []
    try:
        result_sid = client.system.getId(key, host)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to get system id: {}'.format(exc)
        log.error(err_msg)
    
    if len(result_sid) == 1:
        return result_sid[0]['id']
    else:
        print("No system id found for {}".format(host))
        return None
    
def _get_systems_in_groups(group_list):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    all_systems_in_groups = []
    for group in group_list:
        try:
            all_systems_in_groups.extend(client.systemgroup.listSystems(key, group))
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get systems in group {}: {}'.format(group, exc)
            log.error(err_msg)
    
    return all_systems_in_groups

def _get_system_base_channel(system_id):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        system_base_channel = client.system.getSubscribedBaseChannel(key, system_id)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to get base channel for system {}: {}'.format(system_id, exc)
        log.error(err_msg)
        return None
    
    #print(system_base_channel)
    if system_base_channel:
        system_base_channel = system_base_channel.get("label")
    else:
        system_base_channel = None

    return system_base_channel

def find_clm_stage(groups=[], input_file=""):

    clm = _list_clm()
    if len(clm) == 0:
        return "clm not found"
    
    if len(groups) > 0:
        all_systems_in_groups = _get_systems_in_groups(groups)
        if len(all_systems_in_groups) == 0:
            return "no systems in groups"
    else:
        all_systems_in_groups = []
    
    if input_file != "":
        if os.path.isfile(input_file):
            with open(input_file, 'r') as file:
                # The FullLoader parameter handles the conversion from YAML
                # scalar values to Python the dictionary format
                minion_dict = yaml.load(file, Loader=yaml.FullLoader)
        else:
            print("File {} not found".format(input_file))
    else:
        print("You could also use input_file='/tmp/minion_list.yaml' to provide a list of minions in yaml")

    systems_list = []

    for _, minions_list in  minion_dict.items():
        if isinstance(minions_list, list):
            for minion in minions_list:
                minion_id = _get_systemid(minion)
                if minion_id == None:
                    continue
                minion_dict = dict()
                minion_dict['minion_id'] = minion
                minion_dict['id'] = minion_id
                all_systems_in_groups.append(minion_dict)

    
    #only unique by system['minion_id'] should be in the all_systems_in_groups list
    unique_systems = []
    for system in all_systems_in_groups:
        system_dict = dict()
        system_dict["minion_id"] = system["minion_id"]
        system_dict["id"] = system["id"]
        if system_dict not in unique_systems:
            unique_systems.append(system_dict)

    for system in unique_systems:
        system_dict = dict()
        system_dict[system["minion_id"]] = {}
        system_base_channel = _get_system_base_channel(system["id"])
        #print(system['minion_id'], system_base_channel)
        if system_base_channel == None:
            continue
        clm_found = False
        for project, environments in clm.items():
            for environment in environments:
                search_string = "^{}-{}-".format(project, environment)
                if re.search(search_string, system_base_channel):
                    system_dict[system["minion_id"]]["clm_project"] = project
                    system_dict[system["minion_id"]]["clm_stage"] = environment 
                    systems_list.append(system_dict)
                    clm_found = True
                    break
        if not clm_found:
            system_dict[system["minion_id"]]["clm_project"] = ""
            system_dict[system["minion_id"]]["clm_stage"] = ""
            systems_list.append(system_dict)


    return systems_list