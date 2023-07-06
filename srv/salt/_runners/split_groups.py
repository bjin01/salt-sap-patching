'''
Patching Preparation module
================

.. versionadded:: 3004-150400.8.17.7

Salt Runner module - split given suma groups into new suma groups  

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs

import atexit
import logging
import os
import time
import yaml
from salt.ext import six
from cryptography.fernet import Fernet
import random

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

_sessions = {}

def __virtual__():
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

def get_all_minions(existing_groups):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    print("Calling SUSE Manager API...join systems to groups")
    minion_list = []
    if len(existing_groups) != 0:
        try:
            client, key = _get_session(server)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        
        for g in existing_groups:
            try:
                allgroups = client.systemgroup.listSystemsMinimal(key, g)
                
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised when trying to list all groups: {}'.format(exc)
                log.error(err_msg)
            
            for a in allgroups:
                minion_list.append(a['id'])

        unique_minion_list = (list(set(minion_list)))
        
    return unique_minion_list

def split_list_randomly(lst, num_lists):
    random.shuffle(lst)  # Shuffling the original list randomly
    
    split_size = len(lst) // num_lists  # Calculating the size of each split
    remainder = len(lst) % num_lists  # Calculating the remainder (if any)

    splits = []
    start = 0

    for i in range(num_lists):
        split = lst[start:start + split_size]  # Creating a split of the desired size
        start += split_size
        #print("split {}".format(split))
        if remainder:  # If there is a remainder, add one element to the split
            split.append(lst[start])
            start += 1
            remainder -= 1
            
        splits.append(split)

    return splits

def create_new_groups(uniq_minion_list, new_groups):
    suma_config = _get_suma_configuration()
    server = suma_config["servername"]
    print("Calling SUSE Manager API...join systems to groups")
    minion_list = []
    if len(new_groups) != 0:
        try:
            client, key = _get_session(server)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when connecting to spacewalk server ({0}): {1}'.format(server, exc)
            log.error(err_msg)
            return {'Error': err_msg}
        
        try:
            allgroups = client.systemgroup.listAllGroups(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to list all groups: {}'.format(exc)
            log.error(err_msg)
    
        for group in allgroups:
            for new_group_name in new_groups:
                if group['name'] in new_group_name.keys():
                    try:
                        _ = client.systemgroup.delete(key, group['name'])
                        print("Delete group {}, no worries we will create it again.".format(group['name']))
                    except Exception as exc:  # pylint: disable=broad-except
                        err_msg = 'Exception raised when trying to delete group ({0}): {1}'.format(group['name'], exc)
                        log.error(err_msg)

        total_number_groups = len(new_groups)
        #print("split into {} groups. {}".format(total_number_groups, uniq_minion_list))
        splitted_list = split_list_randomly(uniq_minion_list, total_number_groups)
        
        for new_group_name in new_groups:
            a_group = list(new_group_name.keys())
            
            description = "created by split_groups salt runner module. {}".format(a_group[0])
            try:
                _ = client.systemgroup.create(key, a_group[0], description)
                print("Create group {}.".format(a_group[0]))
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised when trying to creating group ({0}): {1}'.format(a_group[0], exc)
                log.error(err_msg)
        
        for num in range(len(new_groups)):
            
            a_group = list(new_groups[num].keys())
           
            try:
                result = client.systemgroup.addOrRemoveSystems(key, a_group[0], splitted_list[num], True)
                print("Added minions {} to {}. Result: {}".format(splitted_list[num], a_group[0], result))
            except Exception as exc:  # pylint: disable=broad-except
                err_msg = 'Exception raised when trying to join the group ({0}): {1}'.format(a_group[0], exc)
                log.error(err_msg)
                return False

    return

def create_sls_files(template, output_file):
    template_data = dict()
    #print("outfile: {}".format(list(output_file.keys())[0]))
    group = list(output_file.keys())[0]
    email = output_file[group]["email"]
    t7user = output_file[group]["t7user"]
    """ print("Email: {}".format(output_file[group]["email"]))
    print("t7user: {}".format(output_file[group]["t7user"])) """
    if os.path.exists(template):
        with open(template, 'r') as file:
            # Load the YAML data into a dictionary
            template_data = yaml.safe_load(file)
        
        
        """ print("template_data {}".format(template_data))
        print("instance: {}".format(type(template_data))) """
        # Iterate over the list and update t7user value
        for item in template_data['run_patching']['salt.runner']:
            if isinstance(item, dict) and 't7user' in item:
                item['t7user'] = t7user
            if isinstance(item, dict) and 'jobchecker_emails' in item:
                item['jobchecker_emails'].append(email)
        
        print("final: {}".format(template_data["run_patching"]["salt.runner"]))

        output_file = "{}_{}.sls".format(group, t7user)
        with open(output_file, 'w') as file:
            yaml.dump(template_data, file)
    return output_file

def split(input_file):
    ret = dict()
    split_group_info = dict()
    if os.path.exists(input_file):
        with open(input_file, 'r') as file:
            # Load the YAML data into a dictionary
            split_group_info = yaml.safe_load(file)
            print("{}".format(split_group_info["existing_suma_groups"]))
            print("{}".format(split_group_info["target_groups"]))
    else:
        ret["comment"] = "{} does not exist.".format(input_file)
    
    minion_list = get_all_minions(split_group_info["existing_suma_groups"])
    print("all minions but unique {}".format(minion_list))
    create_new_groups_result = create_new_groups(minion_list, split_group_info["target_groups"])
    if split_group_info["template_sls"]:
        for g in split_group_info["target_groups"]:
            group = list(g.keys())[0]
            
            print("split_group_info[template_sls][0] is: {}".format(split_group_info["template_sls"][0]))
            create_sls_result = create_sls_files(split_group_info["template_sls"][0], g)
            ret[group] = create_sls_result
    return ret