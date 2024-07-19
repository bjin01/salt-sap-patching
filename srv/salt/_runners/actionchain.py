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
import urllib3
import yaml
import json
import copy
import subprocess
import salt.client
import six
from datetime import datetime,  timedelta
from contextlib import contextmanager

try:
    import psycopg2 
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

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

def _get_sumadb_configuration(postgres=''):
    '''
    Return the configuration read from the master configuration
    file or directory
    '''
    postgres_config = __opts__['postgres'] if 'postgres' in __opts__ else None
    ret = dict()

    if postgres_config:
        #print("{}".format(type(postgres_config)))
        try:
            if "host" in postgres_config.keys() and postgres_config['host'] is not None:
                ret['host'] = postgres_config['host']
            else:
                log.debug('No host found in configuration')
                return False

            if "port" in postgres_config and postgres_config['port'] is not None:
                ret['port'] = postgres_config['port']
            else:
                log.debug('No port found in configuration')
                return False
            
            if "db" in postgres_config and postgres_config['db'] is not None:
                ret['db'] = postgres_config['db']
            else:
                log.debug('No db found in configuration')
                return False
            

            if "user" in postgres_config and postgres_config['user'] is not None:
                ret['user'] = postgres_config['user']
            else:
                log.debug('No user found in configuration')
                return False
            
            if "pass" in postgres_config and postgres_config['pass'] is not None:
                ret['pass'] = postgres_config['pass']
            else:
                log.debug('No password found in configuration')
                return False
            return ret
        except:  # pylint: disable=broad-except
            return False
                

    return False

@contextmanager
def _get_cursor():
    """
    Yield a POSTGRES cursor
    """
    _options = _get_sumadb_configuration()
    
    conn = psycopg2.connect(
        host=_options["host"],
        user=_options["user"],
        password=_options["pass"],
        dbname=_options["db"],
        port=_options["port"],
    )
    conn.set_session(autocommit=True)
    cursor = conn.cursor()
    try:
        yield cursor
        log.debug("Connected to POSTGRES DB {} on {}".format(_options["db"], _options["host"]))
        #print("Connected to POSTGRES DB {} on {}".format(_options["db"], _options["host"]))
    except psycopg2.DatabaseError as err:
        log.exception("Error while connecting to POSTGRES: %s", err.args)
    finally:
        conn.close()

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



def run(groups=[], **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and create action chain for patching a given group of salt-minions

    You could provide a delay in minutes or fixed schedule time for the job in format of: "15:30 20-04-1970"

    If no delay or schedule is provided then the job will be set to now.

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt-run actionchain.run groups=[] delay=15

    Orchestrate state file example in salt://orch/patch.sls:
       
        salt-run state.orch orch.patch

    .. code-block:: yaml
        
        run_patching:
          salt.runner:
            - name: actionchain.run 
            - groups:
              - group1
              - group2
              - group3
            - kwargs:
                delay: 60
                reboot: True
                logfile: /var/log/patching/sumapatch.log
        
        cmd:
        salt-run actionchain.run groups='["group1", "group2"]' delay=5
                
    '''
    #log.debug("----------------------------args: {} kwargs: {}".format(groups, kwargs))
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["Patching"] = []
    

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

    all_data = []
    systemid_list_all_groups = []
    if len(groups) > 0:
        if isinstance(groups, list):
            for grp in list(set(groups)):
                try:
                    active_systems_ids = _get_listActiveSystemsInGroup(client, key, grp)
                    if active_systems_ids:
                        log.debug("following active systems in group: {} \t{}".format(grp, active_systems_ids))
                        systemid_list_all_groups += active_systems_ids
                    else:
                        log.debug("No active systems in group: {}".format(grp))
                        continue
                    
                except Exception as exc:
                    err_msg = 'Exception raised trying to get active systems IDs from group ({0}): {1}'.format(grp, exc)
                    log.error(err_msg)
                    
        else:
            if isinstance(groups, str) and groups != "":
                try:
                    active_systems_ids = _get_listActiveSystemsInGroup(client, key, groups)
                    if active_systems_ids:
                        log.debug("following active systems in group: {} \t{}".format(groups, active_systems_ids))
                        systemid_list_all_groups += active_systems_ids
                    else:
                        log.debug("No active systems in group: {}".format(groups))
                    
                except Exception as exc:
                    err_msg = 'Exception raised trying to get active systems IDs from single group ({0}): {1}'.format(groups, exc)
                    log.error(err_msg)
            else:    
                log.debug("No groups provided. Exit.")
                return {"Error": "No groups provided."}
    
    if len(systemid_list_all_groups) > 0:
        #print("All systems in groups: {}".format(systemid_list_all_groups))
        # create a list of all systems but unique id
        systemid_list_all_groups = list(set(systemid_list_all_groups))

        for id in systemid_list_all_groups:
            systemname = _get_systemname(client, key, id)
            if systemname and systemname != "":
                #print("{}: {}".format(systemname, id))
                all_data.append({"name": systemname, "id": id})
        
        if len(all_data) > 0:
            minionlist = []
            for data in all_data:
                minionlist.append(data["name"])
                print("{}".format(data))

            online_minions = _minion_presence_check(minionlist)
            print("online_minions: {}".format(online_minions))
        
        online_systems = []
        for system in all_data:
            if system["name"] in online_minions:
                online_systems.append(system)
            else:
                log.debug("{} is offline.".format(system["name"])) 

        systemlist_with_pkgids = []
        for system in online_systems:
            sid = system["id"]
            sname = system["name"]
            pkg_ids = []
            if "no_update" in kwargs and kwargs["no_update"]:
                log.debug("No update for {}".format(sname))
                systemlist_with_pkgids.append({"name": sname, "id": sid, "pkg_ids": []})
                continue
            try:
                result_upg_pkgs = client.system.listLatestUpgradablePackages(key, sid)
                if len(result_upg_pkgs) > 0:
                    for pkg in result_upg_pkgs:
                        pkg_ids.append(pkg['to_package_id'])
                if len(pkg_ids) > 0:
                    systemlist_with_pkgids.append({"name": sname, "id": sid, "pkg_ids": pkg_ids})
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised when trying to get latest relevant packages: {0}'.format(exc)
                log.error(err_msg)
                continue
        
        if len(systemlist_with_pkgids) > 0:
            now = datetime.now()
            date_time = now.strftime("%d-%m-%Y-%H%M%S")
            label = "ac_{}".format(date_time)
            chain_actionID = _create_actionchain(client, key, label)
            if chain_actionID == 0:
                log.error("Failed to create action chain. Exit.")
                return
            #print("all systemlist_with_pkgids {}".format(systemlist_with_pkgids))
            for system in systemlist_with_pkgids:
                if len(system["pkg_ids"]) == 0:
                    continue
                log.debug("{}: {}".format(system["name"], len(system["pkg_ids"])))
                pkg_action_id = _addPackageUpgrade(client, key, label, system["id"], system["pkg_ids"])
                #log.debug("pkg_action_id: {}".format(pkg_action_id))
                if pkg_action_id == 0:
                    log.error("Failed to add package upgrade to action chain for {}. Exit.".format(system["name"]))
                    break
            
            if "reboot" in kwargs and kwargs["reboot"]:
                for system in systemlist_with_pkgids:
                    log.debug("Add reboot job for {}".format(system["name"]))
                    reboot_jobid = _addSystemReboot(client, key, system["id"], label)

            if "states" in kwargs and isinstance(kwargs["states"], list):
                
                log.debug("Add state job: {}".format(kwargs["states"]))
                for system in systemlist_with_pkgids:
                    state_action_id = _addState(client, key, system["id"], label, chain_actionID, kwargs["states"])
                    if state_action_id == 0:
                        log.error("Failed to add state job to action chain for {}. Exit.".format(kwargs["states"]))
                        break
            
            earliest_occurrence = six.moves.xmlrpc_client.DateTime(datetime.now() + timedelta(minutes=10))
            jobID = _scheduleChain(client, key, label, earliest_occurrence)
            if jobID == 0:
                log.error("Failed to schedule action chain. Exit.")
                return
            else:
                ret["Action Chain"] = "{} created successfully".format(label)
                return ret
            

    
    #print("Start patch job scheduling.")
    
    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)

    return ret

def _addState(client, key, sid, label, chain_id, states):
    actionID = 0
    states_string = ""
    for s in states:
        states_string += s + ","
   
    # strip the last comma in states_string
    if states_string != "":
        states_string = states_string.rstrip(',')
    else:
        return action_id

    
    create_rhnaction = """INSERT INTO rhnaction (id, org_id, action_type, name, scheduler, earliest_action, version)
        VALUES((SELECT MAX(id)+1 FROM rhnaction), 1, 503, %s, 1, now(), 2) RETURNING id;"""
    
    create_rhnactionapplystates = """INSERT INTO rhnactionapplystates 
        (id, action_id, states, test) VALUES((SELECT MAX(id)+1 FROM rhnactionapplystates), 
        %s, %s, 'N') RETURNING id;"""
    
    add_to_actionchain = """INSERT INTO rhnactionchainentry (actionchain_id, action_id, server_id, sort_order) 
        VALUES(%s, %s, %s, (SELECT COALESCE(MAX(sort_order)+1, 0) FROM rhnactionchainentry));"""
    try:
        with _get_cursor() as curs:
            
            curs.execute(create_rhnaction, (states_string,))
            rows = curs.fetchone()
            if rows:
                action_id = rows[0]
            # Commit into the database
            #curs.connection.commit()
            print("rhnaction id: %s" % action_id)

            curs.execute(create_rhnactionapplystates, (action_id, states_string,))
            rows = curs.fetchone()
            if rows:
                state_action_id = rows[0]
            # Commit into the database
            #curs.connection.commit()
            print("rhnactionapplystates id: %s" % state_action_id)

            curs.execute(add_to_actionchain, (chain_id, action_id, sid,))
            #curs.connection.commit()
            print("action id: %s added to action chain %s" % (action_id, label))

            return action_id
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0

    """ if len(states) > 0:
        #config_specifier = [{"channelLabel": label, "filePath": "/init.sls", "revision": 0}]
        '''
        actionProps:
            entity_type: minion
            entity_id: 1000010047
            name: "test state apply"
            cron_expr: "0 1/12 * * *"
            states:
                - certs
                - mypkgs
        '''
        actionProps = dict()
        actionProps["entity_type"] = "minion"
        actionProps["entity_id"] = sid
        actionProps["name"] = "api - state apply"
        actionProps["cron_expr"] = "0 0 12 * * ?"

        sid_list = []
        sid_list.append(sid)
        try:
            #actionID = client.actionchain.addConfigurationDeployment(key, actionProps)
            #actionID = client.recurring.custom.create(key, actionProps) 
            earliest_occurrence = six.moves.xmlrpc_client.DateTime(datetime.now())
            actionID = client.system.scheduleApplyStates(key, sid, states, earliest_occurrence, False)
            return actionID
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to schedule state apply job for {1} {0}'.format(sid, exc)
            log.error(err_msg)
            return actionID
    else:
        log.error("state is empty.")
        return actionID """
    
def _addSystemReboot(client, key, sid, label):
    try:
        reboot_jobid = client.actionchain.addSystemReboot(key, sid, label)
        return reboot_jobid
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to add reboot job to action chain for {} {0}'.format(sid, exc)
        log.error(err_msg)
        return 0
    return 0

def _addPackageUpgrade(client, key, action_label, system_id, pkg_ids):
    actionID = 0
    
    if len(pkg_ids) == 0:
        log.warning("No package IDs provided for {}. Exit.".format(system_id))
        return 0

    if action_label == "":
        log.error("action chain label is empty.")
        return 0
    
    try:
        actionID = client.actionchain.addPackageUpgrade(key, system_id, pkg_ids, action_label)
        return actionID
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to add package upgrade to action chain for {1} {0}'.format(system_id, exc)
        log.error(err_msg)
        return 0
    return actionID

def _scheduleChain(client, key, action_label, earliest_occurrence):
    jobID = 0
    try:
        jobID = client.actionchain.scheduleChain(key, action_label, earliest_occurrence)
        print("action chain jobID: {}".format(jobID))
        return jobID
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when trying to schedule action chain {1}: {0}'.format(exc, action_label)
        log.error(err_msg)
        print(err_msg)
        return jobID
    return jobID

def _create_actionchain(client, key, label):
    actionID = 0
    if label != "":
        try:
            actionID = client.actionchain.createChain(key, label)
            return actionID
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to create an action chain {1}: {0}'.format(exc, label)
            log.error(err_msg)
            return actionID
    else:
        log.error("action chain label is empty.")

    return actionID

def _send_to_jobcheck(results):
    print("see ret {}".format(results))
    uri = 'http://192.168.122.1:12345/jobchecker'
    body = results
    headers = {}
    method = 'POST'
    timeout = 120.0

    pool = urllib3.PoolManager(timeout=timeout, retries=urllib3.util.retry.Retry(15))
    headers.update({'Content-Type': 'application/json', 'Connection': 'close', \
                    'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 \
                        (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17'})

    if body is not None and not isinstance(body, str):
        body = json.dumps(body).encode('utf-8')

    #print('[Request]: %s url=%s, headers=%s, body=%s' % (method, uri, headers, body))
    if body:
        headers['Content-Length'] = len(body)
        try:
            rsp = pool.request(method, uri, body=body, headers=headers)
            print('status: {}, {}'.format(rsp.status, rsp.data.decode('utf-8')))
            return
        except Exception as e:
            log.error("Connecting to jobchecker failed: {}".format(e))
            print(e)
            return
    
    return True    

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

def _get_listActiveSystemsInGroup(client, key, groupname):
    if groupname != "":
        try:
            systemid_list = client.systemgroup.listActiveSystemsInGroup(key, groupname)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get system IDs from group {1}: {0}'.format(exc, groupname)
            log.error(err_msg)
            return

        if systemid_list != 0:
            return systemid_list
        else:
            return None
    return 

def _get_systemname(client, key, sid):
    if sid != "":
        try:
            systemname_obj = client.system.getName(key, sid)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get system name from ID: {1} {0}'.format(exc, sid)
            log.error(err_msg)

        if systemname_obj:
            return systemname_obj['name']
        else:
            return None
    return 

def _get_systemid(client, key, target_system):
    if target_system != "":
        try:
            getid_ret = client.system.getId(key, target_system)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} system ID: {0}'.format(exc, target_system)
            log.error(err_msg)

        if getid_ret:
            id = getid_ret[0]['id']
            return id
    return 

def _patch_single(client, key, target_system_id, target_system_name, kwargs):
    ret_single_system = dict()
    ret = dict()
    ret["Full_Update_Job_ID"] = {}
    ret["Patching"] = []

    minion_sid_list = [target_system_id]
    
    print("kwargs: {}".format(kwargs))
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
    patch_job = 0
    try:
        patch_job = client.system.schedulePackageUpdate(key, minion_sid_list, earliest_occurrence)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when schedule patch job: {0}. \
            Please double check if there is not already a job scheduled: {1}.'.format(exc, target_system_name)
        log.debug(err_msg)
        
    if int(patch_job) > 0:
        return patch_job
    else:
        log.warning("something went wrong while system.schedulePackageUpdate for {}".format(target_system_name))
        return 0

 
    return ret

def reboot(target_systems=[], **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and schedule reboot job for a given salt-minions

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt-run patch.reboot target_systems=mytest.example.com

    Orchestrate state file example in salt://orch/patch.sls:
       
        salt-run state.orch patch.reboot

    .. code-block:: yaml
        
        run_patching_reboot:
            salt.runner:
                - name: patch.reboot 
                - target_systems: 
                  - minion 1
                  - minion 2
                  - minion 3
    
    Or from salt-master command line:
    .. code-block:: bash
        salt-run patch.reboot target_systems="[pxesap01.bo2go.home, pxesap02.bo2go.home, pxesap03.bo2go.home]"
    
    '''
    
    status = ""
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    reboot_dict = dict()
    ret = dict()
    ret["reboot_job"] = []
    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    if kwargs.get("delay"):
        if int(kwargs['delay']) > 0:
            delay = kwargs['delay']
            nowlater = datetime.now() + timedelta(minutes=int(delay))
        else:
            nowlater = datetime.now() + timedelta(minutes=2)
    else:
        nowlater = datetime.now() + timedelta(minutes=2)
    

    earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    
    if isinstance(target_systems, list):
        for target_system in list(set(target_systems)):
            try:
                target_system_id = _get_systemid(client, key, target_system)
            except Exception as exc:
                err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_system, exc)
                log.error(err_msg)
                ret[target_system] = {'Error': err_msg}
            
            if target_system_id != 0:
                ret1 = _reboot_single(client, key, target_system_id, earliest_occurrence)
                ret["reboot_job"].append({target_system: ret1})
    else:
        try:
            target_system_id = _get_systemid(client, key, target_systems)
        except Exception as exc:
            err_msg = 'Exception raised trying to find host minion id ({0}): {1}'.format(target_systems, exc)
            log.error(err_msg)
            ret[target_systems] = {'Error': err_msg}
        
        if target_system_id != 0:
            ret1 = _reboot_single(client, key, target_system_id, earliest_occurrence)
            ret["reboot_job"].append({target_systems: ret1})

    return ret

def _reboot_required(client, key):
    
    try:
        result_reboot_required = client.system.listSuggestedReboot(key)
        #print("result_systemid {}".format(result_systemid))
        #print("reboot list: {}".format(result_reboot_required))
        return result_reboot_required
    except Exception as exc:
        err_msg = 'Exception raised while trying to get reboot required list: ({0})'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}

def _check_existing_reboot_jobs(client, key):
    pending_reboot_systems = []
    try:
        result_inProgressActions = client.schedule.listInProgressActions(key) 
    except Exception as exc:
        err_msg = 'Exception raised while trying to get pending job list: ({0})'.format(exc)
        log.error(err_msg)
        return {'Error': err_msg}

    for action in list(result_inProgressActions):
        #print("action: {} {}".format(action["name"], action["type"]))
        if not "System reboot" in action["name"]:
            result_inProgressActions.remove(action)
    
    for inprogress in result_inProgressActions:
        try:
            result_inProgressSystems = client.schedule.listInProgressSystems(key, inprogress["id"])
            for result in result_inProgressSystems:
                pending_reboot_systems.append(result["server_id"])
        except Exception as exc:
            err_msg = 'Exception raised while trying to get pending jobs in progress systems: ({0})'.format(exc)
            log.error(err_msg)
            return {'Error': err_msg}

    return pending_reboot_systems

def _reboot_single(client, key, server_id, earliest_occurrence):
    try:
        result_reboot_job = client.system.scheduleReboot(key, server_id, earliest_occurrence)
    except Exception as exc:
        log.error("schedule reboot failed. {} {}".format(server_id, exc))
        return {'Error': exc}

    if int(result_reboot_job) > 0:
            log.info("SUMA Reboot job {} created for {}".format(result_reboot_job, server_id))
            #print("SUMA Reboot job {} created for {}".format(result_reboot_job, target_system))
            return {"JobID": result_reboot_job}
    else:
        log.error("SUMA Reboot job creation failed for {}".format(server_id))
        return {"JobID": 0}

def _schedule_pkg_refresh_job(client, key, target_system_id, target_system, kwargs):
    ret = dict()
    ret[target_system] = {}
    nowlater = datetime.now()
    if kwargs.get("delay"):
        if int(kwargs['delay']) > 0:
            delay = kwargs['delay']
            nowlater = datetime.now() + timedelta(minutes=int(delay))
        else:
            nowlater = datetime.now() + timedelta(minutes=2)
    
    earliest_occurrence = six.moves.xmlrpc_client.DateTime(nowlater)
    if target_system_id:
        
        try:
            refresh_job_id = client.system.schedulePackageRefresh(key, target_system_id, earliest_occurrence)
            ret[target_system].update({"Pkg refresh Job ID": refresh_job_id})
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get {1} schedule pkg refresh job: {0}'.format(exc, target_system)
            log.error(err_msg)
            ret[target_system].update({"error_message": err_msg})
            return ret
        
    return ret

def _minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    
    minion_status_list = runner.cmd('manage.status', ["tgt={}".format(minion_list), "tgt_type=list", timeout, gather_job_timeout], print_event=False)

    return minion_status_list

def refresh_package_list(target_system=None, groups=None, **kwargs):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["refresh_package_list"] = []
    all_systems_in_groups = []
    all_to_refresh_minions = {}

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
    
    if target_system:
        
        if target_system != "":
            try:
                target_system_id = _get_systemid(client, key, target_system)
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to find minion id ({0}): {1}'.format(target_system, exc)
                log.error(err_msg)
                ret[target_system] = {'Error': err_msg}
            
            ret1 = _schedule_pkg_refresh_job(client, key, target_system_id, target_system, kwargs)
            ret["refresh_package_list"].append(ret1)            
    
    if groups:
        print("Query systems in the SUMA groups.")
        for g in groups:
            try:
                systems_in_groups = client.systemgroup.listSystemsMinimal(key, g)
                all_systems_in_groups += systems_in_groups              
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised trying to get active minion list from group ({0}): {1}'.format(g, exc)
                log.error(err_msg)

    suma_minion_list = []
    if len(all_systems_in_groups) == 0:
        ret["comment"] = "No minion in SUMA groups found. Exit."
        return ret
        
    for s in list(all_systems_in_groups):
        if target_system == s["name"]:
            all_systems_in_groups.remove(s)
            continue
        else:
            suma_minion_list.append(s["name"])
    
    if len(all_systems_in_groups) > 0:
        if kwargs.get("timeout") and kwargs.get("gather_job_timeout"):
            online_minion_list = _minion_presence_check(suma_minion_list, timeout=kwargs['timeout'], 
                                                 gather_job_timeout=kwargs['gather_job_timeout'])
        else:
            online_minion_list = _minion_presence_check(suma_minion_list)

    for s in list(all_systems_in_groups):
        for minion in online_minion_list["up"]:
            if s["name"] == minion:
                all_to_refresh_minions[s["name"]] = s['id']
    #print(all_to_refresh_minions)

    for minion_name, systemid in all_to_refresh_minions.items():
            ret1 = _schedule_pkg_refresh_job(client, key, systemid, minion_name, kwargs)
            ret["refresh_package_list"].append(ret1)

    if 'logfile' in kwargs:
        _write_logs(ret, logfile=kwargs['logfile'])
    else:
        _write_logs(ret)
    
    #print("ret[Patching]: {}".format(ret["Patching"]))
    # below we remove all elements from list if val not dict
    if len(ret["refresh_package_list"]) > 0:
        for system in list(ret["refresh_package_list"]):
            if isinstance(system, dict):
                for key, val in system.items():
                    if not isinstance(val, dict):
                        ret["refresh_package_list"].remove(system)
                    if not "Pkg refresh Job ID" in val.keys():
                        ret["refresh_package_list"].remove(system)
            else:
                ret["refresh_package_list"].remove(system)

    return ret

def _minion_presence_check(minion_list, timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [minion_list, "tgt_type=list", timeout, gather_job_timeout], print_event=False)
    log.debug("online minions are: {}".format(online_minions))
    return online_minions