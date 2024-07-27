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
import yaml
import json
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



#log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler = logging.FileHandler('/var/log/patching/patching.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
log = logging.getLogger("action_chain")
#log.setLevel(logging.DEBUG)
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
    conn.set_session()
    cursor = conn.cursor()
    try:
        yield cursor
        log.debug("Connected to POSTGRES DB {} on {}".format(_options["db"], _options["host"]))
        #print("Connected to POSTGRES DB {} on {}".format(_options["db"], _options["host"]))
    except psycopg2.DatabaseError as err:
        log.exception("Error while connecting to POSTGRES: %s", err.args)
    finally:
        log.debug("Disconnected from Postgres DB.")
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
    Call suse manager / uyuni xmlrpc api and create action chain to patch a given group of salt-minions

    There are four jobs will be created if all are enabled by kwargs:
        - pre-sates: salt states that should be executed prior patching.
        - patching: patching job
        - reboot: reboot job
        - post-states: salt states that should be executed after patching.
    

    If delay keyword argument is not provided then the job will start by default with one minute delay.

    Use case:
    It can be helpful to create a reactor that catches certain event sent by minion by 
    e.g. highstate or minion registration and trigger to patch the minion 
    with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt-run actionchain.run groups="[a_group1, b_group2]" \
            job_check_state=my_jobcheck_sls \
            reboot=True no_update=False \
            pre_states="[asdfmanager_org_1.bo_state_test, mypkgs]" post_states="[pause]" delay=5

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
            - pre_states:
                - manager_org_1.bo_state_test
                - mypkgs
            - post_states:
                - pause
            - delay: 5
            - reboot: True
            - no_update: True
            - logfile: /var/log/patching/sumapatch.log
            - job_check_state: my_jobcheck_sls
        
        cmd:
        salt-run actionchain.run groups="[a_group1, b_group2]" \
            reboot=True no_update=True \
            job_check_state=my_jobcheck_sls \
            pre_states="[manager_org_1.bo_state_test, mypkgs]" post_states="[pause]" delay=5
        
        or execute sls with orchestrate runner:
        salt-run state.orchestrate actionchain.patching
                
    '''
    #log.debug("----------------------------args: {} kwargs: {}".format(groups, kwargs))
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    ret = dict()
    ret["job_IDs"] = []
    
    

    if 'logfile' in kwargs:
        #mylog = logging.getLogger()  # root logger - Good to get it only once.
        for hdlr in log.handlers[:]:  # remove the existing file handlers
            if isinstance(hdlr,logging.FileHandler): #fixed two typos here
                log.removeHandler(hdlr)

        file_handler_custom = logging.FileHandler(kwargs['logfile'])
        file_handler_custom.setLevel(logging.DEBUG)
        file_handler_custom.setFormatter(formatter)
        log.addHandler(file_handler_custom)
    

    if 'output_file' in kwargs and kwargs['output_file'] != "":
        output_file = kwargs['output_file']
    else:
        now = datetime.now()
        
        today_date = now.strftime("%d_%m_%Y_%H%M%S")
        output_file = f"/var/cache/salt/master/actionchain_jobs_{today_date}"
        with open(output_file, 'w') as fp:
            pass

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}

    all_data = []
    systemid_list_all_groups = []
    if len(groups) > 0:
        log.info("Following groups will be patched: {}".format(groups))
        if isinstance(groups, list):
            for grp in list(set(groups)):
                try:
                    result_systemsInGroup = _get_listSystemsInGroup(client, key, grp)
                    if result_systemsInGroup:
                        #log.debug("following active systems in group: {} \t{}".format(grp, result_systemsInGroup))
                        for r in result_systemsInGroup:
                            systemid_list_all_groups.append(r)
                    else:
                        log.debug("No systems in group: {}".format(grp))
                        continue
                    
                except Exception as exc:
                    err_msg = 'Exception raised trying to get systems IDs from group ({0}): {1}'.format(grp, exc)
                    log.error(err_msg)
                    
        else:
            if isinstance(groups, str) and groups != "":
                try:
                    result_systemsInGroup = _get_listSystemsInGroup(client, key, groups)
                    if result_systemsInGroup:
                        #log.debug("following systems in group: {} \t{}".format(groups, result_systemsInGroup))
                        for r in result_systemsInGroup:
                            systemid_list_all_groups.append(r)
                        
                    else:
                        log.debug("No systems in group: {}".format(groups))
                    
                except Exception as exc:
                    err_msg = 'Exception raised trying to get systems IDs from single group ({0}): {1}'.format(groups, exc)
                    log.error(err_msg)
            else:    
                log.debug("No groups provided. Exit.")
                return {"Error": "No groups provided."}
    
    unique_systemid_list_all_groups = []
    if len(systemid_list_all_groups) > 0:
        log.debug("systemid_list_all_groups: {}".format(systemid_list_all_groups))
        ids = []
        for s in systemid_list_all_groups:
            ids.append(s['id'])

        unique_ids = list(set(ids))
        print("unique_ids: {}".format(unique_ids))
        
        # need to add unique element from systemid_list_all_groups into unique_systemid_list_all_groups
        for u in unique_ids:
            exist = 0
            for s in systemid_list_all_groups:
                if u == s['id'] and exist == 0:
                    exist = 1
                    unique_systemid_list_all_groups.append(s)

        minionlist = []
        for server in unique_systemid_list_all_groups:
            #systemname = _get_systemname(client, key, id)
            if server['name'] and server['name'] != "":
                #print("{}: {}".format(systemname, id))
                all_data.append({"name": server['name'], "id": server['id']})
                minionlist.append(server["name"])

        if len(minionlist) > 0:
            online_minions = _minion_presence_check(minionlist)

            if len(log.handlers) > 1:
                log.removeHandler(log.handlers[1])
            log.info("online_minions: {}".format(online_minions))
            
        else:
            print("No active minions in list. Exit.")
            return
        
        online_systems = []
        if not online_minions:
            print("Failed to get online minions. Exit")
            return
        
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
                    # prevent duplicate pkg ids
                    for pkg in result_upg_pkgs:
                        if pkg['to_package_id'] not in pkg_ids:
                            pkg_ids.append(pkg['to_package_id'])
                        else:
                            print("Not adding duplicate pkg id: {} {}".format(pkg['to_package_id'], pkg['name']))
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
            else:
                ret['action_chain_id'] = chain_actionID
                ret['action_chain_label'] = label
                
            #print("all systemlist_with_pkgids {}".format(systemlist_with_pkgids))
            
            
            if "pre_states" in kwargs and isinstance(kwargs["pre_states"], list):
                log.debug("Add pre state job: {}".format(kwargs["pre_states"]))
                for system in systemlist_with_pkgids:
                    sort_num = _get_rhnactionchainentry_sortorder(client, key, chain_actionID)
                    state_action_id = _addState(client, key, system["id"], label, chain_actionID, kwargs["pre_states"], sort_num)
                    if state_action_id == 0:
                        log.error("Failed to add pre state job to action chain for {}. Exit.".format(kwargs["pre_states"]))
                        return
                    else:
                        ret["job_IDs"].append({"system_name": system["name"], "sid": system["id"], "jobid": int(state_action_id)})
                
            
            
            for system in systemlist_with_pkgids:
                if len(system["pkg_ids"]) == 0:
                    continue
                
                log.debug("{}: {}".format(system["name"], len(system["pkg_ids"])))
                pkg_action_id = _addPackageUpgrade(client, key, label, system["id"], system["pkg_ids"])
                #log.debug("pkg_action_id: {}".format(pkg_action_id))
                if pkg_action_id == 0:
                    log.error("Failed to add package upgrade to action chain for {}. Exit.".format(system["name"]))
                    break
                else:
                    ret["job_IDs"].append({"system_name": system["name"], "sid": system["id"], "jobid": pkg_action_id})
            
            #time.sleep(3)
            if "reboot" in kwargs and kwargs["reboot"]:
                
                for system in systemlist_with_pkgids:
                    log.debug("Add reboot job for {}".format(system["name"]))
                    reboot_jobid = _addSystemReboot(client, key, system["id"], label)
                    ret["job_IDs"].append({"system_name": system["name"], "sid": system["id"], "jobid": reboot_jobid})
                    
            
            #time.sleep(3)
            if "post_states" in kwargs and isinstance(kwargs["post_states"], list):
                log.debug("Add post state job: {}".format(kwargs["post_states"]))
                for system in systemlist_with_pkgids:
                    sort_num = _get_rhnactionchainentry_sortorder(client, key, chain_actionID)
                    state_action_id = _addState(client, key, system["id"], label, chain_actionID, kwargs["post_states"], sort_num)
                    if state_action_id == 0:
                        log.error("Failed to add post state job to action chain for {}. Exit.".format(kwargs["post_states"]))
                        break
                    else:
                        ret["job_IDs"].append({"system_name": system["name"], "sid": system["id"], "jobid": int(state_action_id)})
            
            if "delay" in kwargs and kwargs["delay"] != "":
                delay = int(kwargs["delay"])
            else:
                delay = 1
            earliest_occurrence = six.moves.xmlrpc_client.DateTime(datetime.now() + timedelta(minutes=delay))
            jobID = _scheduleChain(client, key, label, earliest_occurrence)
            if jobID == 0:
                log.error("Failed to schedule action chain. Exit.")
                return
            else:
                ret["comment"] = "{} created successfully".format(label)
                try:
                    with open(output_file, "w") as outfile: 
                        json.dump(ret, outfile)
                except Exception as exc:  # pylint: disable=broad-except
                    log.error("Failed to write output to file: {}".format(exc))
                    return
                
                if "job_check_state" in kwargs and kwargs["job_check_state"] != "":
                    pillar_data = f"pillar={{ ac_job_file: {output_file} }}"
                    runner = salt.runner.RunnerClient(__opts__)
                    #runner_args = f"[{jobs_file}, interval=2, timeout=10,
                    pillar_data = f"pillar={{ ac_job_file: {output_file} }}"
                    runner = salt.runner.RunnerClient(__opts__)
                    #runner_args = f"[{jobs_file}, interval=2, timeout=10, email_to='bo.jin@jinbo01.com']"
                    out = runner.cmd('state.orchestrate', [kwargs["job_check_state"], pillar_data], print_event=False)
                    #print("actionchain.run runner output: {}".format(out))
                return ret
    return ret

def _get_rhnactionchainentry_sortorder(client, key, chain_id):
    sort_num = 0
    try:
        select_rhnactionchainentry = """SELECT MAX(cast((sort_order) as int)) FROM rhnactionchainentry WHERE actionchain_id = %s"""
        with _get_cursor() as curs:
            curs.execute(select_rhnactionchainentry, (chain_id,))
            select_rhnactionchainentry_result = curs.fetchone()
            if select_rhnactionchainentry_result:
                #log.debug("select_rhnactionchainentry_result[0]: {} is instance {}".format(select_rhnactionchainentry_result[0], type(select_rhnactionchainentry_result[0])))
                if isinstance(select_rhnactionchainentry_result[0], int):
                    sort_num = select_rhnactionchainentry_result[0]
                    sort_num += 1
                
            else:
                sort_num = 0
        return sort_num
    except Exception as e:
        print(f"An error occurred _get_cursor: {e}")
        return 0
    

def _addState(client, key, sid, label, chain_id, states, sort_num):
    actionID = 0
    states_string = ""
    for s in states:
        states_string += s + ","
    #print("states_string before rstrip {}".format(states_string))
   
    # strip the last comma in states_string
    if states_string != "":
        states_string = states_string.rstrip(',')
        #print("states_string after rstrip {}".format(states_string))
        states_string_jobname = f'"custom states - {states_string}"'
    else:
        return action_id

    select_rhnaction = """SELECT MAX(id) FROM rhnaction"""
    
    create_rhnaction = """INSERT INTO rhnaction (id, org_id, action_type, name, scheduler, earliest_action, version)
        VALUES(nextval('rhn_event_id_seq'), 1, 503, %s, 1, now(), 2) RETURNING id;"""
    
    create_rhnactionapplystates = """INSERT INTO rhnactionapplystates (id, action_id, states, test) VALUES(nextval('rhn_act_apply_states_id_seq'), %s, %s, 'N') RETURNING id;"""
    
    add_to_actionchain = """INSERT INTO rhnactionchainentry (actionchain_id, action_id, server_id, sort_order) 
        VALUES(%s, %s, %s, %s);"""
    try:
        with _get_cursor() as curs:
            #curs.execute("SELECT setval('rhnaction_id_seq', (SELECT COALESCE(MAX(id), 1) FROM rhnaction)::bigint)")
            #curs.connection.commit()
            curs.execute(select_rhnaction)
            select_rhnaction_result = curs.fetchone()
            curs.connection.commit()
            #print("last rhnaction id is {} and next rhnaction id would be {}".format(select_rhnaction_result[0], select_rhnaction_result[0] +1 ))
            

            curs.execute(create_rhnaction, (states_string_jobname,))
            rows = curs.fetchone()
            if rows:
                action_id = rows[0]
            # Commit into the database
            curs.connection.commit()
            #print("rhnaction id: %s" % action_id)

            curs.execute(create_rhnactionapplystates, (action_id, states_string,))
            rows = curs.fetchone()
            if rows:
                state_action_id = rows[0]
            # Commit into the database
            curs.connection.commit()
            #print("rhnactionapplystates id: %s" % state_action_id)

            curs.execute(add_to_actionchain, (chain_id, action_id, sid, sort_num,))
            curs.connection.commit()
            #print("action id: %s added to action chain %s" % (action_id, label))

            return action_id
    except Exception as e:
        print(f"An error occurred _addState: {e}")
        return 0

    
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

def _get_listSystemsInGroup(client, key, groupname):
    if groupname != "":
        try:
            systemid_list = client.systemgroup.listSystemsMinimal(key, groupname)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get system IDs from group {1}: {0}'.format(exc, groupname)
            log.error(err_msg)
            return

        if systemid_list != 0:
            return systemid_list
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
    try:
        import salt.client
    except ImportError:
        log.error("salt client not found")
        return False
    
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [minion_list, "tgt_type=list", timeout, gather_job_timeout], print_event=False)
    #log.debug("online minions are: {}".format(online_minions))
    return online_minions