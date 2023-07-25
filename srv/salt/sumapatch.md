# __salt runner module - sumapatch__

sumapatch is a salt runner module that uses SUSE Manager / [Uyuni](https://www.uyuni-project.org/) API to schedule patch jobs. 

Tested on: SUSE Manager 4.3 x86 on SLES15SP4 with python v3.6

## Updates:
To reduce API load another SUSE Manager API Call replaces schedulePackageInstall.
New API Method being used is __schedulePackageUpdate__. This method simply schedules for every targeted system a "full package update job" and triggers salt minion to execute "pkg.uptodate" which equals to ```zypper update```

This new method does not need a list of to-be-updated packages and processing hundreds of minions using this salt runner module will be faster.

The scheduled job will be one Job ID with all targeted salt-minions. This information will be further passed to jobchecker for [job monitoring](https://github.com/bjin01/jobmonitor).

## __Features included within the module:__
* schedule patch jobs based on groups defined in SUSE Manager
* allows setting delay time for job start 
* online presence check - if the mininons are online via salt-run manage.up check
* writes logs to specified log files
* hand over scheduled job IDs to [jobchecking](../../jobchecker/jobchecker.md) for job status monitoring
* no_patch - grains key to be used as exceptional system lock to not patch it within groups
* Use encrypted SUMA API login password in configuration file
* reboot function - schedule reboot jobs via SUSE Manager API.
* Verify if system really require reboot 
* If system already has pending reboot jobs then no further reboot jobs will be created.

Here is a sample salt orchestrator sls file (salt://orch/test1.sls) to use sumapatch module:
<details><summary>test1.sls</summary>

```
run_patching:
  salt.runner:
    - name: sumapatch.patch 
    - target_system: pxesap01.bo2go.home
    - groups:
      - testgrp
    - kwargs:
      delay: 5
      timeout: 3
      gather_job_timeout: 15
      logfile: /var/log/patching/sumapatching.log
      jobchecker_timeout: 20
      jobchecker_emails:
        - bj@somedomain.dot
      grains: 
        no_patch: False
      t7user: t7777
      prep_patching: orch.disable_proxy
      post_patching: orch.enable_proxy
      patch_level: 2023-Q2
```

</details>

## Explain kwargs:
The supported kwargs are:
- delay: the number given is in minutes. The delay time will be added to the current time to scheduled patch jobs.
- logfile: if defined the logs will be written to the specified log file. But the logfile and directory must belong to user salt and created before using it
- timeout: given number in seconds. This is used for minion presence check for salt-run manage.up 
- gather_job_timeout: given number in seconds. [manage.up](https://docs.saltproject.io/en/latest/ref/runners/all/salt.runners.manage.html#salt.runners.manage.up)
- jobchecker_timeout: given number in minutes. It tells jobchecker how long to monitor the jobs
- jobchecker_emails: email addresses where the final job monitoring results will be sent to.
- no_patch: is the grains key name. If the value is True then the respective minion will be excluded from patching.

## Configuration and preparations:

The sumaptch module uses the a configuration file. (Example: [/etc/salt/master.d/spacewalk.conf](../etc/salt/master.d/spacewalk.conf))

### __Create configuration file for SUSE Manager API:__

**Password encryption**:
The module sumpatch supports using encrypted password in the configuration file.
Therefore use the [encrypt.py](../encrypt.py) to generat a encrypted password:
```
python3.6 encrypt.py <YOUR-SUMA-API-PASSWORD>
```
The output of encrypt.py gives the encrypted password and the key will be needed for decryption.
The encrypted password must be provided in the configuration file and stored in ```/etc/salt/master.d```
For example:
```
suma_api:
  suma1.bo2go.home:
    username: 'admin'
    password: gAAAAABj_xzeu23IpzKM-mYOYOS1HwV3leuntobtovVru5TvK0pdJVJjvStXPSO3IOOCTfBSoIQZHE_GhoCokaaj0tAOdyzcvQ==
```
Do not forget to restart salt-master after changing or adding configurations on salt master. \
```systemctl restart salt-master```

**Additionally you must set an OS environment variable SUMAKEY**
```
export SUMAKEY=R2bfp223Qsk-pX970Jw8tyJUChT4-e2J8anZ4G4n4IM=
```
The SUMAKEY will be needed by the salt-runner module which uses it for password decryption. \
**If the SUMAKEY is not found then the script will use the value of password in [sumaconfig](../etc/salt/master.d/spacewalk.conf) as clear text password.**

## __Installation steps (run as root or with sudo):__
```
git clone https://github.com/bjin01/salt-sap-patching.git
cd salt-sap-patching
mkdir /var/log/patching/
touch /var/log/patching/patching.log
chown salt. /var/log/patching/patching.log
cp srv/salt/_runners/sumapatch.py /usr/share/susemanager/modules/runners/
salt-run saltutil.sync_runners
```

## __Execute the patch orchestrator:__
```salt-run state.orch orch.test1```

## __Logs:__
Upon logfile defined in the sls file there is one default log file: \
```/var/log/patching/patching.log```
And the logfile specified in the sls of above example: \
```/var/log/patching/sumapatching.log``` 

Logfiles and directories must have ownership belonging to user salt. \
Use below commands to create directory and log files and set correct ownerships: \
Run as root user or with sudo (if not already done in installation steps):
```
mkdir -p /var/log/patching
touch /var/log/patching/patching.log
touch /var/log/patching/sumapatching.log
chown -R salt. /var/log/patching/
```

## __Reboot function__
The suma-jobchecker will write the completed jobs into a file \
e.g. ```/srv/pillar/sumapatch/completed_20230317095655```

This output file contains a list of systems that completed patch jobs successfully.
Now admins could use this file as input for ```sumapatch.reboot``` to trigger reboot jobs but via SUSE Manager API.

Another orchestrator sls file could be used to provide all needed parameters as shown below:

```
/srv/salt/orch # cat reboots.sls 
run_patching:
  salt.runner:
    - name: sumapatch.reboot 
    - reboot_list: /srv/pillar/sumapatch/completed_20230316141955
    - kwargs:
      delay: 15
```
* reboot_list - (argument required) file from which the reboot function should read from
* delay - (kwargs, optional) tells when the reboot job should start from now on with any given delay time in minutes. If not given then default 2 minutes delay will be added so that admins could still cancel the jobs if needed.

### __Reboot conditions:__
* The reboot function only schedule a reboot job for a system if a reboot is really required, according to SUSE Manager.
* The reboot function only schedule a reboot job for a system if the system not already have a pending reboot job in the pending job list. Avoid multiple reboot jobs.

## __execute the reboot orchestrator sls__ ##
If the sls file is called reboots and resides in orch directory:
```
salt-run state.orch orch.reboots
```
Sample output from sumapatch.patch
```
suma1.bo2go.home_master:
----------
          ID: run_patching
    Function: salt.runner
        Name: sumapatch.patch
      Result: True
     Comment: Runner function 'sumapatch.patch' executed.
     Started: 10:29:45.034921
    Duration: 32426.463 ms
     Changes:   
              ----------
              return:
                  ----------
                  Patching:
                      |_
                        ----------
                        pxesap01.bo2go.home:
                            ----------
                            Patch Job ID is:
                                1102
                            event send:
                                True
                            masterplan:
                                P-Basis-suma-aaa
                      |_
                        ----------
                        pxesap02.bo2go.home:
                            ----------
                            Patch Job ID is:
                                1103
                            event send:
                                True
                            masterplan:
                                P-Basis-suma
                  btrfs_disqualified:
                  jobchecker_emails:
                      - bj@somedomain.dot
                  jobchecker_timeout:
                      25
                  jobstart_delay:
                      5
                  no_patch_execptions:
                      - jupiter.bo2go.home
                  offline_minions:
                      - mars
                      - saturn
                  patch_level:
                      2023-Q2
                  post_patching:
                      orch.enable_proxy
                  post_patching_file:
                      /srv/pillar/sumapatch/post_patching_minions_t7777_20230424103016.sls
                  prep_patching:
                      orch.disable_proxy
                  t7user:
                      t7777
                  user:
                      root

Summary for suma1.bo2go.home_master
------------
Succeeded: 1 (changed=1)
Failed:    0
------------
Total states run:     1
Total run time:  32.426 s
```