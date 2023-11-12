from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import logging
import requests
import json
import yaml

def __virtual__():
    return True

def _convert_yaml_to_json(yaml_file):
    try:
        # Read the YAML file
        with open(yaml_file, 'r') as file:
            yaml_data = yaml.load(file, Loader=yaml.FullLoader)

        # Convert YAML to JSON
        json_data = json.dumps(yaml_data, indent=4)

        return json_data
    except FileNotFoundError:
        return None


def run(config="", api_server="127.0.0.1", api_port="12345"):
    if config == "":
        print("No config file provided.\n")
        return 
    else:
        json_data = _convert_yaml_to_json(config)
    
    if json_data:
        #print(json_data)
        url = "http://{}:{}/pkg_update".format(api_server, api_port)
        headers = {
        'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=json_data)
        print(response.text)
        return "The workflow to update systems in SUSE Manager has started. \nYou will get email notifications. \nOr journalctl -u     suma-jobchecker.service -f to watch logs"
    else:
        print(f"Error: The file '{config}' was not found.")
        return "Error: The file '{config}' was not found."
    return

def add_minions(config="", api_server="127.0.0.1", api_port="12345"):
    if config == "":
        print("No config file provided.\n")
        return 
    else:
        json_data = _convert_yaml_to_json(config)
    
    if json_data:
        #print(json_data)
        url = "http://{}:{}/pkg_update_by_list".format(api_server, api_port)
        headers = {
        'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=json_data)
        print(response.text)
        return "The workflow to update systems in SUSE Manager has started. \nYou will get email notifications. \nOr journalctl -u     suma-jobchecker.service -f to watch logs"
    else:
        print(f"Error: The file '{config}' was not found.")
        return "Error: The file '{config}' was not found."
    return
