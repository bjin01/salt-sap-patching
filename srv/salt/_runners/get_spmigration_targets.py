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
import re
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
        else:
            print("System ID not found.")
    return 

def _get_ident_info(client, key, sid):
    try:
        ident_return = client.system.listMigrationTargets(key, sid)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to get {1} system spmigration ident: {0}'.format(exc, sid)
        log.error(err_msg)
    
    if len(ident_return) > 0:
        """ for i in ident_return:
            for k, v in i.items():
                print("{}: {}".format(k, v))
                print() """
        return ident_return

    return


def list_targets(target_system=None, groups=None, **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api to list service pack migration targets for the given salt-minion name

    Use cae:
    The information listed can be used for automated service pack migration in conjunction with jobchecker.
    
    CLI Example:

    .. code-block:: bash

        salt-run get_spmigration_targets.list_targets target_system=minion_name
        salt-run get_spmigration_targets.list_targets groups="a_group1 testgrp"

    '''

    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret[target_system] = []
    ret["targets from groups"] = {}
    ret["final_unique_targets"] = []

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to SUSE Manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    all_systems_in_groups = []
    if groups:
        groups_list = groups.split()
        for g in groups_list:
            print("Query systems in the SUMA groups. {}".format(groups))
            try:
                print("group name: {}".format(g))
                systems_in_groups = client.systemgroup.listSystemsMinimal(key, g)
                all_systems_in_groups += systems_in_groups              
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to get system list from group ({0}): {1}'.format(g, exc)
                log.error(err_msg)
    
    for b in all_systems_in_groups:
        if b['id']:
            ret[b['name']] = _get_ident_info(client, key, b['id'])
            #print("output {}".format(ret[b['name']]))
            ret["targets from groups"][b['name']] = []
            ret["targets from groups"][b['name']] = ret[b['name']]
        
    if target_system:
        try:
            target_system_id = _get_systemid(client, key, target_system)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_system, exc)
            log.error(err_msg)
            ret[target_system] = {'Error': err_msg}


        if target_system_id:
            ret[target_system] = _get_ident_info(client, key, target_system_id)

    ident_list = []
    final_unique_list = []
    for a, b in ret["targets from groups"].items():
        #print("system: {}".format(a))
        #print("\tident: {}".format(b))
        if b:
            for s in b:
                #print("s is {}".format(s))
                entire_value = "ident: {}, friendly: {}".format(s['ident'], s['friendly'])
                ident_list.append(entire_value)

        
        final_unique_list = list(set(ident_list))
        
    ret['final_unique_targets'] = final_unique_list



    return ret['final_unique_targets']

    

def delete_groups():
    '''
    Call suse manager / uyuni xmlrpc api to delete "spmigration_t7" groups.

    Use cae:
    Use this salt-run function to delete all existing spmigration_t7* groups that were automatically created by spmigration.
    
    CLI Example:

    .. code-block:: bash

        salt-run get_spmigration_targets.list_targets target_system=minion_name
        salt-run get_spmigration_targets.list_targets groups="a_group1 testgrp"

    '''
    group_name = "spmigration_t7"
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to SUSE Manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    allgroups = []
    try:
        allgroups = client.systemgroup.listAllGroups(key)          
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised trying to get list of groups: {1}'.format(exc)
        log.error(err_msg)

    
    if len(allgroups) > 0:
        found_matching_group = False    
        for s in allgroups:
            result = re.findall(r"^{}".format(group_name), s['name'])
            if len(result) > 0:
                found_matching_group = True
                print("delete group {}".format(s['name']))
                try:
                    _ = client.systemgroup.delete(key, s['name'])    
                except Exception as exc:  # pylint: disable=broad-except
                    err_msg = 'Exception raised when deleting group {0}: {1}'.format(s['name'], exc)
                    log.error(err_msg)
                    return {'Error': err_msg}
        
        if not found_matching_group:
            print("No matching group found.")

        return 
    else:
        print("No group found. Exit")


    return
