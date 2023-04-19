from __future__ import absolute_import, print_function, unicode_literals
# Import python libs
import logging
import os
import yaml
import salt.client
from salt.ext import six
from datetime import datetime,  timedelta

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None

__virtualname__ = 'allonline'
output_file = "/srv/pillar/allonline/minions"
output_yaml = "/srv/pillar/allonline/minions.yaml"

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
#log.setFormatter(formatter)

def __virtual__():
    return True

def detect(timeout=2, gather_job_timeout=10):
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__) 
    type = "tgt_type='glob'"
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions = runner.cmd('manage.up', [timeout, gather_job_timeout], print_event=False)
    csv_list = ",".join(online_minions)
    with open(output_file, 'w') as file:
    # Write the csv_list string into the file
        file.write(csv_list)

    return online_minions

def create_pillar(timeout=2, gather_job_timeout=10):
    ret = dict()
    online_minions = dict()
    online_minions["online_minions"] = []
    print("checking minion presence...")
    runner = salt.runner.RunnerClient(__opts__) 
    type = "tgt_type='glob'"
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    online_minions["online_minions"] = runner.cmd('manage.up', [timeout, gather_job_timeout], print_event=False)

    with open(output_yaml, 'w') as file:
        yaml.dump(online_minions, file)

    ret["message"] = 'Done. Use this file to target all online minions. \ne.g. salt-run post_patching.report {} csv_file="/srv/pillar/sumapatch/post_patching_report.csv"'.format(output_yaml)
    return ret