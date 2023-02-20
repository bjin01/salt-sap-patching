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
        password: 'verybadpass'

.. note::

    Optionally, ``protocol`` can be specified if the SUMA server is
    not using the defaults. Default is ``protocol: https``.

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
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
                password = service_config.get('password', None)
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
            - target_system: pxesap01.bo2go.home
            - kwarg:
                delay: 60
        
        run_patching:
          salt.runner:
            - name: sumapatch.patch 
            - groups:
              - P-Basis-suma
              - testgrp
            - kwarg:
                delay: 60
    '''

    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["Patching"] = []
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    if target_system:
        try:
            minion_names = client.saltkey.acceptedList(key)
            if len(minion_names) != 0 and target_system in minion_names:
                print("patch host: {}".format(target_system))
                target_system_id = _get_systemid(client, key, target_system)
                ret1 = _patch_single(client, key, target_system_id, kwargs)
                ret["Patching"].append(ret1)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            ret = {'Error': err_msg}
    
    if groups:
        all_active_minions = []
        for g in groups:
            try:
                active_minions = client.systemgroup.listActiveSystemsInGroup(key, g)
                all_active_minions += active_minions                
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to get active minion list from group ({0}): {1}'.format(g, exc)
                log.error(err_msg)

        # print("all act minions: {}".format(all_active_minions))
        set_res = set(all_active_minions) 
        all_active_minions = (list(set_res))
        # print("final active minions unique: {}".format(all_active_minions))
        for l in all_active_minions:
            ret1 = _patch_single(client, key, l, kwargs)
            ret["Patching"].append(ret1)
    return ret

def _get_systemid(client, key, target_system):
    if target_system != "":
        try:
            getid_ret = client.system.getId(key, target_system)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} all patch ID: {0}'.format(exc, target_system)
            log.error(err_msg)

        if getid_ret:
            id = getid_ret[0]['id']
            return id
    return 

def _patch_single(client, key, target_system_id, kwargs):
    errata_id_list = []
    if target_system_id:
        try:
            target_system = client.system.getName(key, target_system_id)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get minion name {0}'.format(exc, target_system_id)
            log.error(err_msg)

        try:
            errata_list = client.system.getRelevantErrata(key, target_system_id)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} all patch ID: {0}'.format(exc, target_system_id)
            log.error(err_msg)

        if errata_list and len(errata_list) > 0:
            for x in errata_list:
                errata_id_list.append(x['id'])
        else:
            info_msg = 'It looks like the system is fully patched.'
            log.info(info_msg)
            return {'Info': info_msg}

        
        if "delay" in kwargs.keys():
            delay = kwargs['delay']
            if int(delay) >= 0:
                nowlater = datetime.now() + timedelta(minutes=int(delay))
        
        if "schedule" in kwargs.keys():
            schedule = kwargs['schedule']
            nowlater = datetime.strptime(schedule, "%H:%M %d-%m-%Y")
        
        if len(kwargs) == 0:
            nowlater = datetime.now()

        earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
        try:
            patch_job = client.system.scheduleApplyErrata(key, target_system_id, errata_id_list, earliest_occurrence, True)
            if patch_job:
                ret = dict()
                local = salt.client.LocalClient()
                local.cmd(target_system['name'], 'event.send', ['suma/patch/job/id', \
                            {"node": target_system['name'], "jobid": patch_job[0]}])
                log.debug("SUMA Patch job {} created for {}".format(patch_job, target_system['name']))
                ret[target_system['name']] = {"Patch Job ID is": patch_job[0], "event send": True}
                return ret
            
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when schedule patch job: {0}. \
                Please double check if there is not already a job scheduled: {1}.'.format(exc, target_system['name'])
            log.error(err_msg)
            return {'Error': err_msg}
 
    return