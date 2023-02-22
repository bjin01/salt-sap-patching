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
import re
import salt.client

# Import third party libs
from salt.ext import six

from datetime import datetime,  timedelta

log = logging.getLogger(__name__)

_sessions = {}


def __virtual__():
    '''
    Check for suse manager configuration in master config file
    or directory and load runner only if it is specified
    '''
    if not _get_suma_configuration():
        return False, 'No suma_api configuration found'
    return True

def _decrypt_password(password_encrypted):
    
    saltkey = bytes(os.environ.get('SUMAKEY'), encoding='utf-8')
    
    fernet = Fernet(saltkey)
    encmessage = bytes(password_encrypted, encoding='utf-8')
    pwd = fernet.decrypt(encmessage)
    
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

def create_groups(file):
    ret = []
    templist = []
    if os.path.isfile(file):
        with open(file, 'r') as f:
            file_content = f.readlines()
        for i in file_content:
            group_name = re.sub(r"[\n\t\s]*", "", i)
            templist.append(group_name)
        set_res = set(templist) 
        list_res = list(set_res)
        for i in range(len(list_res)):
            output = _create_group(list_res[i])
            ret.append(output)
   
    return ret

def _create_group(group):
    group = re.sub(r"[\n\t\s]*", "", group)
    spacewalk_config = _get_suma_configuration()
    server = spacewalk_config["servername"]
    if server != "":
        try:
            client, key = _get_session(server)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        try:
            groups = client.systemgroup.listAllGroups(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get system ID ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        # check if the "test" group exists
        
        if group not in [g['name'] for g in groups]:
            
            # create a new system group called "test"
            group_id = client.systemgroup.create(key, str(group), group)
            return {"{} created".format(group): group_id['id']}
        else:
            return {"{} already exist".format(group): group}
                
    return

def delete_groups(file):
    ret = [] 
    templist = []
    if os.path.isfile(file):
        with open(file, 'r') as f:
            file_content = f.readlines()
        for i in file_content:
            group_name = re.sub(r"[\n\t\s]*", "", i)
            templist.append(group_name)
        set_res = set(templist) 
        list_res = list(set_res)
        
        for i in range(len(list_res)):
            output = _delete_groups(list_res[i])
            ret.append(output)
   
    return ret

def _delete_groups(group):

    group = re.sub(r"[\n\t\s]*", "", group)
    spacewalk_config = _get_suma_configuration()
    server = spacewalk_config["servername"]
    if server != "":
        try:
            client, key = _get_session(server)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        try:
            groups = client.systemgroup.listAllGroups(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get system ID ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        
        if group in [g['name'] for g in groups]:
            
            # create a new system group
            group_id = client.systemgroup.delete(key, str(group))
            return {"{} deleted".format(group): group_id}
        else:
            return {"{} does not exist".format(group): group}
    return