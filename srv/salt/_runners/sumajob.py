'''
SUMA api runner
================

.. versionadded:: 3004-150400.8.17.7

Runner to query SUSE Manager job status from postgresql

To use this runner, the postgresql username and password should be stored under salt master config
master configuration at ``/etc/salt/master.d/susemanager_db.conf``:

.. code-block:: yaml

    postgres:
        db: susemanager
        host: localhost
        pass: 12345
        port: 5432
        user: susemanager

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import atexit
import logging
from contextlib import contextmanager

import yaml
import json
import copy
import subprocess
import salt.client
import six
from datetime import datetime,  timedelta

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

def __virtual__():
    '''
    Check for spacewalk configuration in master config file
    or directory and load runner only if it is specified
    '''
    if not _get_sumadb_configuration():
        return False, 'No sum db configuration found'
    if not HAS_POSTGRES:
        return False, 'No postgresql python module found'
    return True



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
    cursor = conn.cursor()
    try:
        yield cursor
        log.debug("Connected to POSTGRES DB {} on {}".format(_options["db"], _options["host"]))
        #print("Connected to POSTGRES DB {} on {}".format(_options["db"], _options["host"]))
    except psycopg2.DatabaseError as err:
        log.exception("Error while connecting to POSTGRES: %s", err.args)
    finally:
        conn.close()

def status(minion_id='', job_id=0):

    """ minion = "pxesap01.bo2go.home"
    job_id = 28475 """

    if minion_id.__contains__(","):
        temp = minion_id.split(",")
        minion_id = temp[0]
        job_id = int(temp[1].strip())

    #print("----------------------------------minion_id {} job_id {}".format(minion_id, job_id))

    if minion_id != "" and job_id != 0:
        query = f'''select b.name from rhnserveraction a, rhnactionstatus b, 
                    rhnserveroverview c where a.action_id = {job_id} 
                    AND c.server_name = '{minion_id}' AND b.id = a.status;'''
        try:
            with _get_cursor() as c:
                c.execute(query)
                res = c.fetchall()
                #print("Fetched records: %s" % res)
                #print("type of res is {}".format(type(res)))
                if len(res) == 0:
                    #print("No Job records found")
                    return f"Status: No Job records found for {minion_id} with job_id {job_id}"
                else:
                    if len(res) == 1:
                        for i in res:
                            #print("Status: {}".format(i[0]))
                            return f"Status: {i[0]}"
                    else:
                        return f"Status: No Job records found for {minion_id} with job_id {job_id}"
        except Exception as e:
            print(f"An error occurred: {e}")
        
    return True
