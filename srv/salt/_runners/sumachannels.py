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
import urllib3
import yaml
import sys
import copy
import subprocess
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

def get_child_channels(parent_channel, output=False, file=None):
    result = []
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    if parent_channel:
        print("Calling SUSE Manager API...to get child channels from {}".format(parent_channel))
    else:
        print("No parent_channel given. Exit")
        return "Error"
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        result_allchannels = client.channel.listSoftwareChannels(key)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to list all channels: {}'.format(exc)
        log.error(err_msg)

    result = dict()
    result['channel_tree'] = {}
    if isinstance(result_allchannels, list):
        if len(result_allchannels) > 0:
            result['channel_tree'][parent_channel] = []
            print("{}:".format(parent_channel))
            for c in result_allchannels:
                for a, b in c.items():
                    if a == "parent_label" and b == str(parent_channel):
                        #print("  - {}".format(c['label']))
                        result['channel_tree'][parent_channel].append(c['label'])
                        if file:
                            print("Write data to {}".format(file))
                            _write_to_file(file, result['channel_tree'])
                            result['comment'] = "data written to {}".format(file)
        else:
            print("No channels found.")
    else:
        print("No channels found.")
    
    return result

def change_channels_by_group(file, groups=None, timeout=2, gather_job_timeout=10):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    if not groups:
        print("No SUSE Manager group provided. Exit.")
        return False

    if not isinstance(groups, list):
        print("SUSE Manager groups must be provided as a list. groups='[group1, group2]'")
        return False
    
    print("Query systems in the SUMA groups.")
    all_systems_in_groups = []
    for g in groups:
        try:
            systems_in_groups = client.systemgroup.listSystemsMinimal(key, g)
            all_systems_in_groups += systems_in_groups
            #print(all_systems_in_groups)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised trying to get active minion list from group ({0}): {1}'.format(g, exc)
            log.error(err_msg)

    minion_list = []
    #print(set(all_systems_in_groups))
    #print(all_systems_in_groups)
    if len(all_systems_in_groups) > 0:

        for a in all_systems_in_groups:
            minion_list.append(a['name'])
    
    minion_list = list(set(minion_list))
    result_minion_presence_check = _all_minion_presence_check(minion_list, timeout=2, gather_job_timeout=10)
    print(result_minion_presence_check['up'])
        
        
               

def get_parents():
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        result_allchannels = client.channel.listSoftwareChannels(key)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to list all channels: {}'.format(exc)
        log.error(err_msg)
    

    if isinstance(result_allchannels, list):
        if len(result_allchannels) > 0:
            print("Parent channel labels:")
            for c in result_allchannels:
                for a, b in c.items():
                    if a == "parent_label" and b == "":
                        print("  * {}".format(c['label']))
        else:
            print("No channels found.")
    else:
        print("No channels found.")
    
    return "Done"

def change_channels(file, host):
    if not os.path.exists(file):
        print("{} does not exist.".format(file))
        return
    else:
        data = _load_yaml(file)
        if data == None:
            # Use the loaded data dictionary
            return "No yaml data found in {}".format(file)
        result_sid = _get_systemid(host)
        if result_sid:
            print("system id: {}".format(result_sid))
            return_change_channels = _schedule_change_channels(result_sid, data)
            print("Channel assignment scheduled. Job ID: {}".format(return_change_channels))
    return

def _schedule_change_channels(sid, data):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        if isinstance(data, dict):
            """ basechannel = data.keys()
            childchannels = data[list(basechannel)[0]] """
            basechannel = ""
            childchannels = []
            for parent, childrens in data.items():
                basechannel = parent
                if isinstance(childrens, list):
                    for i in childrens:
                        childchannels.append(i)

            earliest_occurrence = six.moves.xmlrpc_client.DateTime(datetime.now())
            result_actionid = client.system.scheduleChangeChannels(key, sid, basechannel, childchannels, earliest_occurrence)
            return result_actionid
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to set basechannel: {}'.format(exc)
        log.error(err_msg)
        return False

def _load_yaml(file_path):
    with open(file_path, 'r') as file:
        try:
            yaml_data = yaml.load(file, Loader=yaml.FullLoader)
            return yaml_data
        except yaml.YAMLError as e:
            print(f"Error loading YAML file: {e}")
            return None

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
        return None
    