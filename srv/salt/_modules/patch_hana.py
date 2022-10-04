# -*- coding: utf-8 -*-
'''
Spacewalk Runner
================

.. versionadded:: 2016.3.0

Runner to interact with Spacewalk using Spacewalk API

:codeauthor: Nitin Madhok <nmadhok@clemson.edu>, Joachim Werner <joe@suse.com>, Benedikt Werner <1benediktwerner@gmail.com>
:maintainer: Benedikt Werner <1benediktwerner@gmail.com>

To use this runner, set up the Spacewalk URL, username and password in the
master configuration at ``/etc/salt/master`` or ``/etc/salt/master.d/spacewalk.conf``:

.. code-block:: yaml

    spacewalk:
      spacewalk01.domain.com:
        username: 'testuser'
        password: 'verybadpass'
      spacewalk02.domain.com:
        username: 'testuser'
        password: 'verybadpass'

.. note::

    Optionally, ``protocol`` can be specified if the spacewalk server is
    not using the defaults. Default is ``protocol: https``.

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import atexit
import logging



# Import third party libs
from salt.ext import six

from datetime import datetime,  timedelta

log = logging.getLogger(__name__)

_sessions = {}


def __virtual__():
    '''
    Check for spacewalk configuration in master config file
    or directory and load runner only if it is specified
    '''
    if not _get_spacewalk_configuration():
        return False, 'No spacewalk configuration found'
    return True


def _get_spacewalk_configuration(spacewalk_url=''):
    '''
    Return the configuration read from the master configuration
    file or directory
    '''
    spacewalk_config = __opts__['spacewalk'] if 'spacewalk' in __opts__ else None

    if spacewalk_config:
        try:
            for spacewalk_server, service_config in six.iteritems(spacewalk_config):
                username = service_config.get('username', None)
                password = service_config.get('password', None)
                protocol = service_config.get('protocol', 'https')

                if not username or not password:
                    log.error(
                        'Username or Password has not been specified in the master '
                        'configuration for %s', spacewalk_server
                    )
                    return False

                ret = {
                    'api_url': '{0}://{1}/rpc/api'.format(protocol, spacewalk_server),
                    'username': username,
                    'password': password
                }

                if (not spacewalk_url) or (spacewalk_url == spacewalk_server):
                    return ret
        except Exception as exc:  # pylint: disable=broad-except
            log.error('Exception encountered: %s', exc)
            return False

        if spacewalk_url:
            log.error(
                'Configuration for %s has not been specified in the master '
                'configuration', spacewalk_url
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

    config = _get_spacewalk_configuration(server)
    if not config:
        raise Exception('No config for \'{0}\' found on master'.format(server))

    session = _get_client_and_key(config['api_url'], config['username'], config['password'])
    atexit.register(_disconnect_session, session)

    client = session['client']
    key = session['key']
    _sessions[server] = (client, key)

    return client, key


def api(server, command, *args, **kwargs):
    '''
    Call the Spacewalk xmlrpc api.

    CLI Example:

    .. code-block:: bash

        salt-run spacewalk.api spacewalk01.domain.com systemgroup.create MyGroup Description
        salt-run spacewalk.api spacewalk01.domain.com systemgroup.create arguments='["MyGroup", "Description"]'

    State Example:

    .. code-block:: yaml

        create_group:
          salt.runner:
            - name: spacewalk.api
            - server: spacewalk01.domain.com
            - command: systemgroup.create
            - arguments:
              - MyGroup
              - Description
    '''
    if 'arguments' in kwargs:
        arguments = kwargs['arguments']
    else:
        arguments = args

    call = '{0} {1}'.format(command, arguments)
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {call: err_msg}

    namespace, _, method = command.rpartition(".")
    if not namespace:
        return {
            call: "Error: command must use the following format: 'namespace.method'"
        }
    endpoint = getattr(getattr(client, namespace), method)
    #log.warning("endpoint is: %s", endpoint)

    try:
        output = endpoint(key, *arguments)
        #log.warning("suma job output is: %s", output)
    except Exception as e:  # pylint: disable=broad-except
        output = 'API call failed: {0}'.format(e)

    return {call: output}


def addGroupsToKey(server, activation_key, groups):
    '''
    Add server groups to a activation key

    CLI Example:

    .. code-block:: bash

        salt-run spacewalk.addGroupsToKey spacewalk01.domain.com 1-my-key '[group1, group2]'
    '''

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    all_groups = client.systemgroup.listAllGroups(key)
    groupIds = []
    for group in all_groups:
        if group['name'] in groups:
            groupIds.append(group['id'])

    if client.activationkey.addServerGroups(key, activation_key, groupIds) == 1:
        return {activation_key: groups}
    else:
        return {activation_key: 'Failed to add groups to activation key'}


def deleteAllGroups(server):
    '''
    Delete all server groups from Spacewalk
    '''

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    groups = client.systemgroup.listAllGroups(key)

    deleted_groups = []
    failed_groups = []

    for group in groups:
        if client.systemgroup.delete(key, group['name']) == 1:
            deleted_groups.append(group['name'])
        else:
            failed_groups.append(group['name'])

    ret = {'deleted': deleted_groups}
    if failed_groups:
        ret['failed'] = failed_groups
    return ret


def deleteAllSystems(server):
    '''
    Delete all systems from Spacewalk

    CLI Example:

    .. code-block:: bash

        salt-run spacewalk.deleteAllSystems spacewalk01.domain.com
    '''

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    systems = client.system.listSystems(key)

    ids = []
    names = []
    for system in systems:
        ids.append(system['id'])
        names.append(system['name'])

    if client.system.deleteSystems(key, ids) == 1:
        return {'deleted': names}
    else:
        return {'Error': 'Failed to delete all systems'}


def deleteAllActivationKeys(server):
    '''
    Delete all activation keys from Spacewalk

    CLI Example:

    .. code-block:: bash

        salt-run spacewalk.deleteAllActivationKeys spacewalk01.domain.com
    '''

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    activation_keys = client.activationkey.listActivationKeys(key)

    deleted_keys = []
    failed_keys = []

    for aKey in activation_keys:
        if client.activationkey.delete(key, aKey['key']) == 1:
            deleted_keys.append(aKey['key'])
        else:
            failed_keys.append(aKey['key'])

    ret = {'deleted': deleted_keys}
    if failed_keys:
        ret['failed'] = failed_keys
    return ret


def patch(target_system, **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and schedule a apply_all_patches job for given salt-minion name

    You could provide a delay in minutes or fixed schedule time for the job in format of: 15:30 20-04-1970

    If no delay or schedule is provided then the job will be set to now.

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt "mysystem*" patch_hana.patch your-minion.something.domain delay=15

    State Example in sls:

    .. code-block:: yaml

        applypatches:
          patch_hana.patch:
            - name: "anything"
    '''
    errata_id_list = []

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    try:
        systemid = client.system.getId(key, target_system)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to get system ID ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        errata_list = client.system.getRelevantErrata(key, systemid[0]['id'])
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to get all patch ID ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    if errata_list and len(errata_list) > 0:
        for x in errata_list:
            errata_id_list.append(x['id'])
    else:
        info_msg = 'It looks like the system is fully patched: {0}'.format(server)
        log.info(info_msg)
        return {'Info': info_msg}

    if 'delay' in kwargs:
        delay = kwargs['delay']
        nowlater = datetime.now() + timedelta(minutes=int(delay))
    
    if 'schedule' in kwargs:
        schedule = kwargs['schedule']
        nowlater = datetime.strptime(schedule, "%H:%M %d-%m-%Y")
    
    if not kwargs:
        nowlater = datetime.now()

    earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    try:
        patch_job = client.system.scheduleApplyErrata(key, systemid[0]['id'], errata_id_list, earliest_occurrence)    
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when schedule patch job ({0}): {1}. Please double check if there is not already a job scheduled.'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    

    return {"Patch Job ID is": patch_job}
    
def unregister(name, server_url):
    '''
    Unregister specified server from Spacewalk

    CLI Example:

    .. code-block:: bash

        salt-run spacewalk.unregister my-test-vm spacewalk01.domain.com
    '''

    try:
        client, key = _get_session(server_url)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server_url, exc)
        log.error(err_msg)
        return {name: err_msg}

    systems_list = client.system.getId(key, name)

    if systems_list:
        for system in systems_list:
            out = client.system.deleteSystem(key, system['id'])
            if out == 1:
                return {name: 'Successfully unregistered from {0}'.format(server_url)}
            else:
                return {name: 'Failed to unregister from {0}'.format(server_url)}
    else:
        return {name: 'System does not exist in spacewalk server ({0})'.format(server_url)}
