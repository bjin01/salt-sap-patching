# "Automated Patching" using action chains in Uyuni / SUSE Manager
1. Introduction
2. Prerequisites
3. Excuting the salt runner module to start the patching


## 1. Introduction
Automated patching is a feature that allows you to automatically patch your systems based on a schedule. This feature is available in Uyuni and SUSE Manager. The automated patching feature uses action chains to perform the patching. Action chains are a series of actions that are executed in a specific order. In this case, the action chain will perform the following actions:
* Run Highstate (to avoid missing gpg keys on some minions)
* Run salt pre-patch states
* Apply updates 
* Reboot the system
* Run salt post-patch states

## 2. Prerequisites
Before you can use the automated patching feature, you need to make sure that the following prerequisites are met:
* You have a Uyuni or SUSE Manager server installed and configured.
* You have a Uyuni or SUSE Manager client registered to the server.
* salt runner modules [actionchain](../_runners/actionchain.py) and [sumajobs](../_runners/sumajobs.py) are placed in runners_dirs
* The runner module actionchain is using SUSE Manager xmlrpc API to query and schedule the jobs. The API login credentials are stored in the salt-master config directory. The master config should contain the following information:
```
suma_api:
  <suma-host-name>:
    username: <username>
    password: <password>
```
* Additionally runner module __sumajobs__ and __actionchain__ make SELECT and INSERT queries to the database. The database credentials are stored in /etc/rhn/rhn.conf. Make sure the information is correct.



* Create an orchestrator sls file in which the input parameters for runner's module actionchain are provided, for example: [patching.sls](patching.sls)
```
run_patching:
  salt.runner:
    - name: actionchain.run 
    - groups:
      - a_group1
      - b_group2
    - pre_states:
      - manager_org_1.bo_state_test
      - mypkgs
    - post_states:
      - some_state
    - delay: 5
    - reboot: True
    - no_update: False
    - job_check_state: actionchain.check_jobs
    - log_level: info
```
groups: The groups of systems that will be patched
pre_states: The pre-patch states that will be executed
post_states: The post-patch states that will be executed
delay: The delay in minutes from current time to start job execution.
reboot: A boolean value that indicates whether the system should be rebooted after the updates are applied
no_update: A boolean value that indicates whether the system should be updated. If this parameter is set to False but reboot is True then systems will be rebooted without applying updates.
job_check_state: The name of the runner module that will be used to check the status of the scheduled jobs

**Note:** The job information will be stored in the file /var/cache/salt/master/actionchain_jobs_<date>_<time>. The file will be created when the job is scheduled. Old files should be deleted manually.


* To use the second runner's module sumajobs to loop check scheduled jobs create another orchestrator sls, for example: [check_jobs.sls](check_jobs.sls)
```
check_ac_jobs:
  salt.runner:
    - name: sumajobs.actionchain_jobs
    - jobs_file: {{ pillar['ac_job_file']  }}
    - interval: 2
    - timeout: 10
    - email_to: "abc@example.com,xyz@example.com"
```
interval: The interval in minutes between each check
timeout: The maximum time in minutes the runner will run
email_to: The email addresses to which the notification will be sent. No email will be sent if the parameter is not provided.



## 3. Excuting the salt runner module to start the patching
To start the automated patching process, you need to execute the salt runner module that is responsible for running the action chain. You can do this by running the following command on the Uyuni or SUSE Manager server:
```
salt-run state.orchestrate actionchain.patching
```

The job check runner module can be executed by running the following command:
```
salt-run state.orchestrate actionchain.check_jobs

```
```
salt-run state.orchestrate actionchain.check_jobs 'pillar={ ac_job_file: /var/cache/salt/master/actionchain_jobs_27_07_2024_070609 }'
```
```
salt-run actionchain.run groups="[Censhare-Test]" reboot=False no_update=False pre_states="[users.bojin]" post_states="[users.bojin]" delay=5
salt-run actionchain.run groups="[Censhare-Test]" reboot=False no_update=True pre_states="[manager_org_1.user_bojin]" post_states="[manager_org_1.user_bojin]" delay=1 no_presence_check=True
salt-run actionchain.run groups="[TEST]" reboot=True no_update=False pre_states="[disk.status]" post_states="[disk.status]" delay=2
```
