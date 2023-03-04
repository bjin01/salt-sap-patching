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
import salt.client
from salt.ext import six
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
                logfile: /var/log/patching/sumapatch.log
        
        run_patching:
          salt.runner:
            - name: sumapatch.patch 
            - groups:
              - P-Basis-suma
              - testgrp
            - kwargs:
                delay: 60
                logfile: /var/log/patching/sumapatch.log
                grains: 
                  no_patch: False
                timeout: 2
                gather_job_timeout: 15
                
    '''

    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["Patching"] = []
    all_active_minions = []
    all_to_patch_minions = {}

    if 'logfile' in kwargs:
        #mylog = logging.getLogger()  # root logger - Good to get it only once.
        for hdlr in log.handlers[:]:  # remove the existing file handlers
            if isinstance(hdlr,logging.FileHandler): #fixed two typos here
                log.removeHandler(hdlr)

        file_handler_custom = logging.FileHandler(kwargs['logfile'])
        file_handler_custom.setLevel(logging.DEBUG)
        file_handler_custom.setFormatter(formatter)
        log.addHandler(file_handler_custom) 


    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    # here we ensure the minions are really online
    
    if kwargs.get("timeout") and kwargs.get("gather_job_timeout"):
        present_minions = _minion_presence_check(timeout=kwargs['timeout'],
                                                 gather_job_timeout=kwargs['gather_job_timeout'])
    else:
        present_minions = _minion_presence_check()

    if target_system:
        try:
            #minion_names = client.saltkey.acceptedList(key)
            if target_system in present_minions:
                target_system_id = _get_systemid(client, key, target_system)
                ret1 = _patch_single(client, key, target_system_id, target_system, kwargs)
                ret["Patching"].append(ret1)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            ret[target_system] = {'Error': err_msg}
    
    if groups:
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
        target_system = client.system.getName(key, l)
        all_to_patch_minions[target_system['name']] = target_system['id']

    

    # drop minions from list which are not online according to presence check
    for minion in list(all_to_patch_minions.keys()):
        if minion not in present_minions:
            log.warning("salt-run manage.up query says {} is not online.".format(minion))
            del all_to_patch_minions[minion]

    if 'grains' in kwargs:
        for x, y in kwargs['grains'].items():
            for p in list(all_to_patch_minions.keys()):
                output_grains = __salt__['salt.execute'](p, 'grains.get', [x])
                if not output_grains.get(p, None):
                    continue
                if not y == output_grains.get(p, None):
                    print("grains {}: {} for <{}>".format(x, y, p))
                    del all_to_patch_minions[p]
                    log.info("Remove {} from all_to_patch_minions list due to grains query result: \
                             {}: {}".format(p, x, y))
                    
    log.info("final all_to_patch_minions {}".format(all_to_patch_minions))
    for minion_name, systemid in all_to_patch_minions.items():
            ret1 = _patch_single(client, key, systemid, minion_name, kwargs)
            ret["Patching"].append(ret1)

    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)
    return ret

def _minion_presence_check(timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout])
    #print("Online minions: \n{}".format(online_minions))
    return online_minions
    

def _write_logs(input, logfile="/var/log/patching/patching.log"):
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    with open(logfile, 'a+') as f:
        f.write("sumapatch.patch executed --- {}\n".format(dt_string))
        for key, value in input.items(): 
            f.write("{}:\n".format(key))
            if type(value) == list:
                for i in value:
                    if type(i) == dict:
                        for s, x in i.items():
                            f.write('%s:\n' % (s))
                            if type(x) == dict:
                                for d, h in x.items():
                                    f.write('\t%s: %s\n' % (d, h))
                    else:
                        f.write("\t{}\n".format(i))
            else:
                f.write("{}\n".format(value))
    return

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

def _patch_single(client, key, target_system_id, target_system_name, kwargs):
    errata_id_list = []
    error_ret = dict()
    ret = dict()
    if target_system_id:

        try:
            errata_list = client.system.getRelevantErrata(key, target_system_id)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} all patch ID: {0}'.format(exc, target_system_id)
            log.error(err_msg)
            error_ret[target_system_name] = err_msg
            return error_ret

        if errata_list and len(errata_list) > 0:
            for x in errata_list:
                errata_id_list.append(x['id'])
        else:
            info_msg = 'It looks like the system is fully patched.'
            log.info(info_msg)
            ret[target_system_name] = info_msg
            return ret

        
        if "delay" in kwargs.keys():
            delay = kwargs['delay']
            if int(delay) >= 0:
                nowlater = datetime.now() + timedelta(minutes=int(delay))
        
        if "schedule" in kwargs.keys():
            schedule = kwargs['schedule']
            nowlater = datetime.strptime(schedule, "%H:%M %d-%m-%Y")
        
        if not "delay" in kwargs.keys() and not "schedule" in kwargs.keys():
            nowlater = datetime.now()

        earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
        try:
            patch_job = client.system.scheduleApplyErrata(key, target_system_id, errata_id_list, earliest_occurrence, True)
            if patch_job:
                local = salt.client.LocalClient()
                local.cmd(target_system_name, 'event.send', ['suma/patch/job/id', \
                            {"node": target_system_name, "jobid": patch_job[0]}])
                log.info("SUMA Patch job {} created for {}".format(patch_job, target_system_name))
                ret[target_system_name] = {"Patch Job ID is": patch_job[0], "event send": True}
                return ret
            
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when schedule patch job: {0}. \
                Please double check if there is not already a job scheduled: {1}.'.format(exc, target_system_name)
            log.debug(err_msg)
            error_ret[target_system_name] = err_msg
            return error_ret
 
    return