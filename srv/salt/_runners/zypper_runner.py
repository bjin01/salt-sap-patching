# -*- coding: utf-8 -*-
'''
Patching Preparation module
================

.. versionadded:: 3004-150400.8.17.7

Runner for running few pre-patching steps

'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import logging
import salt.client

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')


def __virtual__():
    return True

def _find_stdout(dictionary, mykey="retcode"):
    
    if isinstance(dictionary, dict):
        if mykey in dictionary:
            return dictionary[mykey]
        for value in dictionary.values():
            result = _find_stdout(value, mykey)
            if result is not None:
                return result
    return None


def run(state_name="", timeout=2, gather_job_timeout=10):
    """
    This function executes a state and returns failed state stdout and a list of systems which failed.
    The function will first detect online minions and then run the state on the currently online minions only.

    CLI Example::
      
        salt-run zypper_runner.run state_name="orch.check_zypper_ref" timeout=2 gather_job_timeout=10

    In the given sls file a state module function is used to run e.g. a script and returns output back.

    e.g. orch.check_zypper_ref.sls:
    
    check_zypper_refresh:
      cmd.script:
        - source: salt://orch/zypper/check_zypper_refresh.sh
        - cwd: /
        - stateful: True
        - success_stderr:
          - ERROR
          - error
        - success_stdout:
          - "All is good"

    """
    final_minion_list = dict()
    #minion_list = ["pxesap01.bo2go.home", "pxesap02.bo2go.home", "jupiter.bo2go.home", "saturn"]
    #minion_list = ["jupiter.bo2go.home", "saturn", "pxesap01.bo2go.home"]
    minion_list = _all_minion_presence_check(timeout, gather_job_timeout)
    """ offline_minions = []
    offline_minions = _get_diff(suma_minion_list, minion_list) """

    final_minion_list["offline_minions"] = minion_list["down"]
    #minion_list = []
    local = salt.client.LocalClient()
    #print("minion_list: {}".format(list(minion_list)))

    print("Executing state: {}".format(state_name))
    final_minion_list["zypper_erros"] = []
    final_minion_list["zypper_refresh_problem_systems"] = []

    zypper_refresh_check = local.cmd_batch(list(minion_list['up']), 'state.apply', [state_name], tgt_type="list", batch='10%')
    for w in zypper_refresh_check:
        if w:
            for a, b in w.items():
                stdout = _find_stdout(b, mykey="stdout")
                #print("host: {} - stdout {}".format(a, stdout))
                if b['retcode'] != 0:
                    final_minion_list["zypper_erros"].append({a: stdout})
                    final_minion_list["zypper_refresh_problem_systems"].append(a)

    if len(final_minion_list["zypper_refresh_problem_systems"]) > 0:
        final_minion_list["zypper_refresh_summary"] = "{} systems have problem to run zypper refresh.".format(len(final_minion_list["zypper_refresh_problem_systems"]))
    
    return final_minion_list

def _all_minion_presence_check(timeout=2, gather_job_timeout=10):
    print("checking minion presence from all systems...")
    runner = salt.runner.RunnerClient(__opts__)
    timeout = "timeout={}".format(timeout)
    gather_job_timeout = "gather_job_timeout={}".format(gather_job_timeout)
    print("the timeouts {} {}".format(timeout,gather_job_timeout))
    minion_status_list = runner.cmd('manage.status', ["tgt=*", "tgt_type=glob", timeout, gather_job_timeout], print_event=False)

    return minion_status_list