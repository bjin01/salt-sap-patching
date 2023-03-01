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
from salt.ext import six

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
    if os.environ.get('SUMAKEY') == None: 
        log.fatal("You don't have ENV SUMAKEY set. Use unencrypted pwd.")
        return str(password_encrypted)
    else:    
        saltkey = bytes(str(os.environ.get('SUMAKEY')), encoding='utf-8')
        fernet = Fernet(saltkey)
        encmessage = bytes(str(password_encrypted), encoding='utf-8')
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

def add():
    """
    add minion to SUSE Manager group, if group does not exist then create the group.
    The minion group information is taken from grains srvinfo:INFO_MASTERPLAN

    CLI Example::

        salt-run add_minion_to_group.add
    """
    # get grains from minion
    ret = _get_grains()

    # then join minion to group but also create group if group does not exist
    ret = _join(ret)
    return ret

def _get_grains():
    result = []
    print("Checking online minions and build a list.")

    # First get a list of minions which are online
    runner = salt.runner.RunnerClient(__opts__)
    online_minions = runner.cmd('manage.up', ['timeout=2', 'gather_job_timeout=10'])
    print("Get grains srvinfo:INFO_MASTERPLAN from each minion")
    for x in online_minions:
        output = __salt__['salt.execute'](x, 'grains.get', ['srvinfo:INFO_MASTERPLAN'])
        #print("grains out: ", output.get(x, None))
        if output.get(x, None) == "":
            print("No masterplan found for: ", x)
        else:
            result.append(output)

    return result


def _join(systems):
    ret = dict()
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    print("Calling SUSE Manager API...")
    if len(systems) != 0:
        try:
            client, key = _get_session(server)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        
        # loop through the list of online minions
        for s in systems:
            # found var is used to identify if minion is already in the group
            found = False

            # group_exist to be used if group is not found
            group_exist = False
            for a, b in s.items():
                try:
                    systemid = client.system.getId(key, a)
                except Exception as exc:  # pylint: disable=broad-except
                    err_msg = 'Exception raised when trying to get system ID ({0}): {1}'.format(server, exc)
                    log.error(err_msg)

                if systemid:
                    try:
                        systemgroups = client.system.listGroups(key, systemid[0]['id'])
                    except Exception as exc:  # pylint: disable=broad-except
                        err_msg = 'Exception raised when trying to get system groups ({0}): {1}'.format(server, exc)
                        log.error(err_msg)
                
                if len(systemgroups) != 0:
                    for s in systemgroups:
                        if s["system_group_name"] == b:
                            group_exist = True
                        if s["system_group_name"] == b and s["subscribed"] == 1:
                            found = True
                            ret[a] = "Already in group {}".format(b)

                    # create group if it does not exist
                    if not group_exist:
                        if b != "":
                            try:
                                _ = client.systemgroup.create(key, b, b)
                                print("Created group {} for system {}".format(b, a))
                            except Exception as exc:  # pylint: disable=broad-except
                                err_msg = 'Exception raised when trying to create group ({0}): {1}'.format(b, exc)
                                log.error(err_msg)
                        else:
                            print("No srvinfo:MASTERPLAN found for {}".format(a))

                if systemid[0]['id'] and not found:
                    #print("Joining group for: \t{} into {}".format(a, b))
                    if b == "":
                        continue
                    try:
                        _ = client.systemgroup.addOrRemoveSystems(key, b, systemid[0]['id'], True)
                    except Exception as exc:  # pylint: disable=broad-except
                        err_msg = 'Exception raised when trying to join the group ({0}): {1}'.format(server, exc)
                        log.error(err_msg)
                    ret[a] = "Joined into {}".format(b)
        
    return ret