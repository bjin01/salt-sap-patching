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
        password: 'verybadpass'

.. note::

    Optionally, ``protocol`` can be specified if the SUMA server is
    not using the defaults. Default is ``protocol: https``.

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
from cryptography.fernet import Fernet
import atexit
import logging
import os
import salt.client
import six
import yaml

from datetime import datetime,  timedelta

# Below part is to supress undefinedvariable warnings in IDE for dunder dicts e.g. __salt__
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
log = logging.getLogger(__name__)

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

def add():
    """
    add minion to SUSE Manager group, if group does not exist then create the group.
    The minion group information is taken from grains srvinfo:INFO_MASTERPLAN

    CLI Example::

        salt-run add_minion_to_group.add
    """
    # get grains from minion
    ret_grains = _get_grains()
    # print("result: {}".format(ret_grains))

    ret_with_hostnames, ret_ids = _normalize_data(ret_grains)
    
    # then join minion to group but also create group if group does not exist
    feedback = _join(ret_ids)
    if feedback: 
        return ret_with_hostnames
    else:
        return feedback
    return ret_ids

def _normalize_data(result):
    ret = dict()

    groups = []
    for system in result:
        if isinstance(system, dict):
            for a, b in system.items():
                if b != "":
                    groups.append(b)
                    ret[b] = []
                else:
                    groups.append("P-MP-missing")
                    ret["P-MP-missing"] = []
                

    for system in result:
        if isinstance(system, dict):
            for a, b in system.items():
                if b != "":
                    ret[b].append(a)
                else:
                    ret["P-MP-missing"].append(a)

    
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    print("Calling SUSE Manager API...to get all system IDs.")
    
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        allsystems = client.system.listSystems(key)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to call system.listSystems ({0}): {1}'.format(server, exc)
        log.error(err_msg)

    ret_with_id = dict()
    if len(ret.keys()) > 0:
        for key in ret.keys():
            ret_with_id[key] = []

    if len(allsystems) > 0:
        for i in allsystems:
            # print(i['id'], i['name'])
            for groupname, system_list in ret.items():
                if len(system_list) > 0:
                    for s in system_list:
                        if s == i['name']:
                            ret_with_id[groupname].append(i['id'])
                else:
                    ret_with_id[groupname] = []
                
    return ret, ret_with_id

def _get_grains():
    grains_info = []
    runner = salt.runner.RunnerClient(__opts__)
    minion_status_list = runner.cmd('manage.status', ['timeout=2', 'gather_job_timeout=10'])
    online_minions = minion_status_list["up"]
    offline_minions = minion_status_list["down"]
    local = salt.client.LocalClient()
    #print("minion_list: {}".format(list(online_minions)))
    _ = local.cmd_batch(list(online_minions), 'saltutil.refresh_grains', tgt_type="list", batch='10%')
    ret = local.cmd_batch(list(online_minions), 'grains.get', ["srvinfo:INFO_MASTERPLAN"], tgt_type="list", batch='10%')
    for result in ret:
        grains_info.append(result)
    
    for offline_minion in offline_minions:
        offline_result = dict()
        offline_result[offline_minion] = "P-MP-offline"
        grains_info.append(offline_result)
        #print("MASTERPLAN: {}".format(grains_info))
    #print("entire dict grains_info {}".format(grains_info))
    return grains_info


def _join(systems):
    ret = dict()
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    print("Calling SUSE Manager API...join systems to groups")
    if len(systems.keys()) != 0:
        try:
            client, key = _get_session(server)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
    
        try:
            allgroups = client.systemgroup.listAllGroups(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to list all groups: {}'.format(exc)
            log.error(err_msg)

        all_admins = []
        
        for existing_group in allgroups:
            if "created by add_minion_to_group" in existing_group['description']:
                try:
                    admins_in_group = client.systemgroup.listAdministrators(key, existing_group['name'])
                except Exception as exc:  # pylint: disable=broad-except
                    err_msg = 'Exception raised when trying to get admins from group ({0}): {1}'.format(existing_group['name'], exc)
                    log.error(err_msg)


                if len(admins_in_group) > 0:
                    #print("admins {} in {}".format(admins_in_group, existing_group['name']))
                    for admin in admins_in_group:
                        if admin['login'] != "":
                            try:
                                user_roles = client.user.listRoles(key, admin['login'])
                            except Exception as exc:  # pylint: disable=broad-except
                                err_msg = 'Exception raised when trying to get user roles ({0}): {1}'.format(admin['login'], exc)
                                log.error(err_msg)

                            if len(user_roles) > 0:
                                #print("{} roles {}".format(admin['login'], user_roles))
                                if "org_admin" not in user_roles:
                                    admins_groups = dict()
                                    admins_groups[existing_group['name']] = admin['login']
                                    all_admins.append(admins_groups)
                            else:
                                admins_groups = dict()
                                admins_groups[existing_group['name']] = admin['login']
                                all_admins.append(admins_groups)

                try:
                    _ = client.systemgroup.delete(key, existing_group['name'])
                    print("Delete group {}, no worries we will create it again.".format(existing_group['name']))
                except Exception as exc:  # pylint: disable=broad-except
                    err_msg = 'Exception raised when trying to delete group ({0}): {1}'.format(existing_group['name'], exc)
                    log.error(err_msg)
        
        for group in systems.keys():
            allowed_admins = []
            now = datetime.now()
            description = "created by add_minion_to_group salt runner module. {}".format(now.strftime("%d/%m/%Y, %H:%M:%S"))
            try:
                _ = client.systemgroup.create(key, group, description)
                print("Create group {}.".format(group))
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised when trying to creating group ({0}): {1}'.format(group, exc)
                log.error(err_msg)

            for a in all_admins:
                for a_group, admin in a.items():
                    if admin != "":
                        if a_group == group:
                            print("Allow {} to access {}".format(admin, group))
                            allowed_admins.append(admin)

            if len(allowed_admins) > 0:
                try:
                    add_admins = client.systemgroup.addOrRemoveAdmins(key, group, allowed_admins, 1)
                except Exception as exc:  # pylint: disable=broad-except
                    err_msg = 'Exception raised when trying to add admins to group ({0}): {1}'.format(group, exc)
                    log.error(err_msg)
            
        for group in systems.keys():
            print("Will add {} to group {}".format(systems[group], group))
            if len(systems[group]) > 0:
                try:
                    _ = client.systemgroup.addOrRemoveSystems(key, group, systems[group], True)
                except Exception as exc:  # pylint: disable=broad-except
                    err_msg = 'Exception raised when trying to join the group ({0}): {1}'.format(group, exc)
                    log.error(err_msg)
                    return False
        
    return True