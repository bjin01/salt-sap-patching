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

if not any(isinstance(h, logging.FileHandler) for h in log.handlers):
    file_handler = logging.FileHandler('/var/log/patching/patching.log')
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)

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



def actionchain_jobs(jobs_file="", interval=5, timeout=10, **kwargs):
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
        salt-run sumajobs.actionchain_jobs jobs_file=/var/cache/salt/master/actionchain_jobs_26_07_2024_112227 interval=2 timeout=10 email_to="abc@example.cc,xyz@example.cc"
                
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

    jobs_data = dict()

    
    if jobs_file != "":
        log.info("Received action chain job file: {}".format(jobs_file))
        if  os.path.isfile(jobs_file):
            with open(jobs_file, 'r') as f:
                jobs_data = json.load(f)
            if isinstance(jobs_data, dict):
                #print("job_IDs: {}".format(len(jobs_data['job_IDs'])))
                if int(timeout) <= 1:
                    timeout = 2
                time_now = datetime.now()
                time_end = time_now + timedelta(minutes=timeout)
                
                while datetime.now() < time_end:
                    failed_email_content = f"Job status from file: {jobs_file}\n\n"
                    email_content = f"Job status from file: {jobs_file}\n\n"
                    loop_continue = False
                    send_failed_email = False
                    if len(jobs_data['job_IDs']) > 0:
                        for ac_jobid in jobs_data['job_IDs']:
                            #start_time = timer()
                            status = _get_ac_jobstatus(client, key, ac_jobid['jobid'])
                            #end_time = timer()
                            #print("SQL Time taken: {}".format(end_time - start_time))

                            ret[ac_jobid['jobid']] = {"system": ac_jobid["system_name"], "job status": status}
                            email_content += f"Job ID: {ac_jobid['jobid']} for {ac_jobid['system_name']} - {status}\n"
                            
                            if "Failed" in status:    
                                failed_message = _failed_job_getDetails(ac_jobid)
                                print("Job ID failed: {} for {} - {} - {}".format(ac_jobid['jobid'], 
                                    ac_jobid['system_name'], status, failed_message))
                                ret[ac_jobid['jobid']] = {"system": ac_jobid["system_name"], "job status": status, "failed msg": failed_message}
                                failed_email_content += f"Job ID failed: {ac_jobid['jobid']} for {ac_jobid['system_name']} - {failed_message}\n"
                                send_failed_email = True
                            if "Queued" in status or "Picked Up" in status:
                                loop_continue = True    
                        # send email if failed jobs found
                        if 'email_to' in kwargs and failed_email_content != "" and send_failed_email:
                            _email_to(kwargs, "Action Chain Jobs Failed", failed_email_content)

                    if loop_continue:
                        if int(interval) <= 1:
                            interval = 2
                        next_check_time = datetime.now() + timedelta(minutes=interval)
                        interval_internal = int(interval) * 60
                        log.info("Next loop check in {} seconds at {}".format(interval_internal, next_check_time.strftime("%d-%m-%Y, %H:%M:%S")))
                        log.info("Job check ends once all jobs finished before timeout at {}".format(time_end.strftime("%d-%m-%Y, %H:%M:%S")))
                        time.sleep(interval_internal)
                    else:
                        print("All jobs done. Exit.")
                        log.debug("All jobs done. Exit.")
                        if 'email_to' in kwargs and email_content != "":
                            _email_to(kwargs, "Action Chain Jobs Done", email_content)
                        return ret
                
                if 'email_to' in kwargs and email_content != "":
                    email_content += "\nNot all jobs done. Timeout reached\n."
                    _email_to(kwargs, "Action Chain Jobs loop check timed out", email_content)
        else:
            print("jobs_file does not exist. Exit. {}".format(jobs_file))
            return ret
    else:
        return "No jobs_file provided. Exist"
    
       
    return ret

def _email_to(kwargs, email_subject, email_content):
    if 'email_to' in kwargs and kwargs['email_to'] != "":
        emails_addresses = kwargs['email_to'].split(",")
        email_to = emails_addresses
        print("email_to: {}".format(email_to))
        _send_email(email_to, email_subject, email_content)
    return

    
def _send_email(email_to, email_subject, email_content):
    '''
    Send email using local smtp server

    '''
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    email_from = "root@susemanager.host"
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = ", ".join(email_to)
    msg['Subject'] = email_subject
    msg.attach(MIMEText(email_content, 'plain'))

    try:
        server = smtplib.SMTP('localhost')
        text = msg.as_string()
        server.sendmail(email_from, email_to, text)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print("Error sending email: {}".format(e))
        return False
    return True


def _failed_job_getDetails(ac_jobid):
    failed_msg = ""
    failed_rhnserveraction = """SELECT result_msg FROM rhnserveraction WHERE action_id = %s AND server_id = %s;"""
    try:
        with _get_cursor() as curs:
            curs.execute(failed_rhnserveraction, (int(ac_jobid['jobid']), ac_jobid['sid']))
            failed_rhnserveraction_result = curs.fetchall()
            curs.connection.commit()
            if len(failed_rhnserveraction_result) == 0:
                print("No job result message found for: {}".format(ac_jobid['jobid']))
                return failed_msg
            else:
                for f in failed_rhnserveraction_result:
                    return f[0]
    except Exception as e:
        print(f"An error occurred _failed_job_getDetails: {e}")
        return failed_msg
    return failed_msg

def _get_ac_jobstatus(client, key, jobid):

    select_rhnserveraction = """SELECT sa.status AS status, s.name AS status_name 
        FROM rhnserveraction sa, rhnactionstatus s WHERE sa.action_id = %s AND sa.status = s.id;"""
    
    
    try:
        with _get_cursor() as curs:
            curs.execute(select_rhnserveraction, (int(jobid),))
            select_rhnserveraction_result = curs.fetchall()
            curs.connection.commit()
            if len(select_rhnserveraction_result) == 0:
                print("No action found with id: {}".format(jobid))
                return "Job not found"
            else:
                for e in select_rhnserveraction_result:
                    #print("Job ID: {} - {}".format(jobid,e[1]))
                    return e[1]
                        
        return
    except Exception as e:
        print(f"An error occurred _get_ac_jobstatus: {e}")
        return 0

    
