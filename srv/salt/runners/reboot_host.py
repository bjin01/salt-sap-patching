# -*- coding: utf-8 -*-
'''
SUMA Uyuni - salt runner module
================

.. versionadded:: 2022.7.0

Runner to interact with SUSE Manager/Uyuni using xmlrpc API

:codeauthor: Nitin Madhok <nmadhok@clemson.edu>, Joachim Werner <joe@suse.com>, Benedikt Werner <1benediktwerner@gmail.com>, Bo Jin <bo.jin@suse.com>
:maintainer: Benedikt Werner <1benediktwerner@gmail.com>

To use this runner, set up the SUSE Manager URL, username and password in the
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

    Optionally, ``protocol`` can be specified if the SUSE Manager server is
    not using the defaults. Default is ``protocol: https``.

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import atexit
import logging
import socket
import salt.client
import time

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


def reboot(target_system, **kwargs):
    status = ""
    server = socket.getfqdn(socket.gethostname())
    local = salt.client.LocalClient()
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

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
        result_systemid = client.system.getId(key, target_system)
    except Exception as exc:
        err_msg = 'Exception raised while trying to get systemid ({0}): {1}'.format(target_system, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    try:
        systemid = result_systemid[0]['id']
        result_reboot_job = client.system.scheduleReboot(key, systemid, earliest_occurrence)
        if result_reboot_job and result_reboot_job > 0:
            
            local.cmd(target_system, 'event.send', ['suma/reboot/job/id', {"node": target_system, "jobid": result_reboot_job}])
            log.debug("SUMA Reboot job {} created for {}".format(result_reboot_job, target_system))
            return {"Reboot Job ID is": result_reboot_job, "event send": True}

    except Exception as exc:
        log.error("schedule reboot failed. {} {}".format(target_system, exc))
        return {'Error': exc}

    return {"reboot_jobid": "", "comment": "Schedule reboot job failed."}