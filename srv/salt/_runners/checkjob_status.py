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


def jobstatus(jobid, target_system, interval=60, timeout=15):
    status = ""
    server = socket.getfqdn(socket.gethostname())

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        minion_names = client.saltkey.acceptedList(key)
        if len(minion_names) != 0:
            for m in minion_names:
                if target_system in m:
                    target_system = m
                    log.info("------------------ job running on host: {}".format(target_system))
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}


    if int(timeout) >= 1:
        timeout = int(timeout) * 60
    else:
        timeout = 15 * 60
    timeout_start = time.time()

    if int(interval) <= 0:
        interval = 60

    nowlater = datetime.now()
    #earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    local = salt.client.LocalClient()

    while time.time() < timeout_start + timeout:
        try:
            result_inprogress_actions = client.schedule.listInProgressActions(key)
        except Exception as e:
            log.error("get inProgress Actions failed. %s" %(e))
            
        try:
            result_failed_actions = client.schedule.listFailedActions(key)
        except Exception as e:
            log.error("get result_failed_actions Actions failed. %s" %(e))
            
        try:
            result_completed_actions = client.schedule.listAllCompletedActions(key)
        except Exception as e:
            log.error("get result_completed_actions Actions failed. %s" %(e))


        log.info("SUMA Job status is being examinated.")

        jobid_exist = False    
        if result_inprogress_actions:
            if len(result_inprogress_actions) > 0:
                
                for p in result_inprogress_actions:
                    if p['id'] == int(jobid):
                        jobid_exist = True
                        log.info("Job %d is in-progress, Job Name: %s" %(int(jobid), p['name']))
                    

        if result_failed_actions:
            if len(result_failed_actions) > 0:
                
                for p in result_failed_actions:
                    if p['id'] == int(jobid):
                        jobid_exist = True
                        log.info("Job %d is failed, Job Name: %s" %(int(jobid), p['name']))
                        return {"{}".format(jobid): "failed"}
                    

        if result_completed_actions:
            if len(result_completed_actions) > 0:
                
                for p in result_completed_actions:
                    if p['id'] == int(jobid):
                        jobid_exist = True
                        log.info("-------------Job %d is completed, Job Name: %s" %(int(jobid), p['name']))
                        if "Update" in p['name']:
                            local.cmd(target_system, 'event.send', ['suma/patch/job/finished', {"node": target_system, "reboot": True}])
                        
                        if "System reboot" in p['name']:
                            role = get_node_role(target_system)
                            message = "suma/{}/reboot/job/finished".format(role)
                            local.cmd(target_system, 'event.send', [message, {"node": target_system, "reboot": True}])
                        return {"{}".format(jobid): "completed", "Job name": p['name']}
        
        if not jobid_exist:
            log.info("Job ID does not exist: %s" % int(jobid))
            return {"{}".format(jobid): "not found or job has been cancelled by user."}

        time.sleep(int(interval))

    return {"{}".format(jobid): "Job is still running"}

def get_node_role(tgt):
    
    pub_data = __salt__['salt.execute'](tgt, 'grains.get', arg=["hana_info"])
    if len(pub_data) > 0:
        for a, b in pub_data[tgt].items():
            
            if "diskless_node" in a and b[0] in tgt:
                print("a: {}, b: {}".format(a,b))
                return "diskless_node"
            if "hana_primary" in a and b[0] in tgt:
                return "hana_primary"
            if "hana_secondary" in a and b[0] in tgt:
                return "hana_secondary"
    
    
    return "Unknown host"