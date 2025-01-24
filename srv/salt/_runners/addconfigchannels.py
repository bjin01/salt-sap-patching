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
import string
from cryptography.fernet import Fernet
# Import python libs
import atexit
import logging
import os
import json
import yaml
#import salt.client
import six
from datetime import datetime, time,  timedelta
from contextlib import contextmanager
import time

try:
    import psycopg2 
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None



log = logging.getLogger("sumajobs")
log.propagate = False
formatter = logging.Formatter('%(asctime)s | %(module)s | %(levelname)s | %(message)s') 

if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    log.addHandler(streamhandler)

""" if not any(isinstance(h, logging.FileHandler) for h in log.handlers):
    file_handler = logging.FileHandler('/var/log/patching/patching.log')
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler) """

_sessions = {}

def set_log_level(log_level):
    """Set the log level globally for the logger."""
    if log_level.upper() == "DEBUG":
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)


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



def run(sid, **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and postgres to get action chain job status.

    Use case:
    After action chain jobs have been scheduled it is neccessary to loop check job status and report it to users. 
    
    CLI Example:

    .. code-block:: bash

        salt-run sumajobs.actionchain_jobs jobs_file=/var/cache/salt/master/actionchain_jobs_26_07_2024_112227 interval=2 timeout=10 email_to="abc@example.cc,xyz@example.cc"

    Orchestrate state file example in salt://orch/patch.sls:
       
        salt-run state.orch orch.patch

    .. code-block:: yaml
        
        run_patching:
          salt.runner:
            - name: sumajobs.actionchain_jobs 
            - jobs_file: /var/cache/salt/master/actionchain_jobs_26_07_2024_112227
            - interval: 2
            - timeout: 10
            - kwargs:
                logfile: /var/log/patching/sumapatch.log
                email_to: "abc@example.cc,xyz@example.cc"
        
        cmd:
        salt-run addconfigchannels.run 1000010546 chainLabel=myapi channelLabel=user_bojin filePath="/init.sls" revision=2"
                
    '''
    #log.debug("----------------------------args: {} kwargs: {}".format(groups, kwargs))
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    email_content = ""

    if 'log_level' in kwargs:
        set_log_level(kwargs["log_level"])
    else:
        log.setLevel(logging.INFO)

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        configchannel = []
        configchannel.append({"channelLabel": kwargs["channelLabel"], "filePath": kwargs["filePath"], "revision": kwargs["revision"]})
        result = client.actionchain.addConfigurationDeployment(key, kwargs["chainLabel"], sid, configchannel)
        ret[sid] = result
    except Exception as exc:
        err_msg = 'Exception raised trying to add configuration channel to action chain ({0}): {1}'.format(kwargs["chainLabel"], exc)
        log.error(err_msg)
        ret[sid] = {'Error': err_msg}
       
    return ret
