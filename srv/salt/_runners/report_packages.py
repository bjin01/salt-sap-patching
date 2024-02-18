"""
Search software packages using suse manager API.

.. versionadded:: 2024.02.01

"""
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
from cryptography.fernet import Fernet
import logging
import atexit
import json
import re
import os
import salt.client
import six
import yaml

from datetime import datetime,  timedelta

# Below part is to supress undefinedvariable warnings in IDE for dunder dicts e.g. __salt__
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
log = logging.getLogger(__name__)

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

def _get_package_details(client, key, pid):
    package_details = dict()
    try:
        package_details = client.packages.getDetails(key, pid)
        
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised trying to get package details: {}'.format(exc)
        log.error(err_msg)


    return package_details

def _write_json(file, obj):
    with open(file, 'w') as j_file:
        json.dump(obj, j_file, indent=4,  sort_keys=True, default=str)
    return

def list_packages(search_pattern='kernel-default', json_file=""):
    """
    Search SUSE software packages using suse manager API.
    Only software from vendor SUSE will be seeked.

    CLI Example:

    .. code-block:: shell

        salt-run report_packages.list_packages search_pattern="kernel-default"

        The result will be written into a json file for further usage.
    """
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]

    try:
        client, key = _get_session(server)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised when connecting to suse manager server ({0}): {1}'.format(server, exc)
        log.error(err_msg)
        return {'Error': err_msg}
    
    try:
        search_result = client.packages.search.name(key, search_pattern)
        #print(all_systems_in_groups)
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = 'Exception raised trying to run package.search: {}'.format(exc)
        log.error(err_msg)

    found_packages = []

    if search_result:
        if len(search_result) == 0:
            search_result = {'Error': 'No packages found'}
        else:
            for i in range(len(search_result)):
                if isinstance(search_result[i], dict):
                    if re.search("^{}.*".format(search_pattern), search_result[i]['name']) and search_result[i]['provider'] == 'SUSE LLC':
                        package_details = _get_package_details(client, key, search_result[i]['id'])
                        if not re.search("^.*SUSE.*", package_details['vendor']):
                            continue
                        package_data = dict()
                        package_data['name'] = "{}-{}-{}.{}".format(search_result[i]['name'], search_result[i]['version'], search_result[i]['release'], search_result[i]['arch'])
                        if 'build_date' in package_details.keys():
                            package_data['build_date'] = package_details['build_date']
                        else:
                            package_data['build_date'] = "n/a"
                        
                        package_data['suse-channels'] = []
                        if len(package_details['providing_channels']) > 0:
                            for p in package_details['providing_channels']:
                                if re.search("^sle-module-.*", p):
                                    package_data['suse-channels'].append(p)

                        """ package_data['id'] = search_result[i]['id']
                        package_data['version'] = search_result[i]['version']
                        package_data['release'] = search_result[i]['release']
                        package_data['arch'] = search_result[i]['arch']
                        package_data['summary'] = search_result[i]['summary'] """
                        found_packages.append(package_data)

                        """ for key, value in search_result[i].items():
                            print(key, value) """
    else:
        search_result = {'Error': 'No packages found'}


    """ if len(found_packages) > 0:
        for package in found_packages:
            print()
            if isinstance(package, dict):
                for key, value in package.items():
                    print(key, value) """

    result = dict()
    result['packages'] = found_packages
    result["total_packages"] = len(found_packages)

    #write found_packages into a json file
    if json_file != "":
        _write_json(json_file, found_packages)
        result["z_comment"] = "Result written into file: {}".format(json_file)
    else:
        result["z_comment"] = "No json_file provided. Result not written into file."
    return result