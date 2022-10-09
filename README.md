# Automated OS Patching for SAP HANA Scale-Up clusters using SUSE Manager and salt states
This repository contains saltstack configurations, modules and states which have been created for a fully automated patching of SAP HANA Database Scale-up cluster.

## __Motivation__
Patching SAP HANA Scale-up cluster Linux OS can be challenging. Before patching the Linux (SLES-for-SAP) OS admins need to execute certain cluster commands and move resources from one node to another. The cluster maintenance steps (manually) could be found in [SAP HANA System Replication Scale-Up - Performance Optimized Scenario](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-PerfOpt-15/#id-maintenance).


__The saltstack states and modules you can find here are to help automating SAP HANA Cluster maintenance tasks by:__
* precheck cluster health and SAP HANA System Replication status (SOK)
* set SAP HANA msl_resource into maintenance mode
* schedule and deploy patch job in SUSE Manager to the cluster nodes 
* monitor SUSE Manager patch job status
* schedule OS reboot after patching
* start pacemaker, unset maintenance mode in pacemaker, clear location contraints(cli-ban)
* move msl_resource from primary SAP HANA System Replication site to the secondary site 

__Skills required:__
Knowledge about how to configure pacemaker cluster
Knowledgeabout SUSE SAP HANA SR Scale-up cluster setup
Knowledge about salt states and modules
Knowledge about how to use SUSE Manager

__Technical prerequisites:__
* SLES-for-SAP SLES15SP3
* Software pattern ha_sles, sap-hana installed
* salt-minion installed and registered to SUSE Manager 
* SAP HANA System Replication Scale-up 2 or 3 nodes cluster is up and running
* Linux hostname and host FQDN are configured properly and used in both pacemaker cluster and salt-minion minion_id (e.g. hostname=myhost, fqdn=myhost.mydomain.com)
* DNS name resolution to the hostnames must be working properly.
* pacemaker cluster resource rsc_SAPHana parameter AUTOMATED_REGISTER=true is set.

## __Tested scenario:__
- SLES-for-SAP 15SP3 x86_64
- SAP HANA SR Scale-up - 3 node cluster (diskless setup)
- SUSE Manager 4.2.8
- salt-minion-3004
- salt-master-3002.2
- python3.6

![Architecture](./saphana-patching-architecture)

__Review the [workflow readme](./workflow-README.md) steps.__

## Using this solution:

### Prepare the salt-master configuration:
Configure SUSE Manager API credentials in a config file in 

```/etc/salt/master.d/spacewalk.conf```
and add also runners_dir to this config file:
```
# cat spacewalk.conf 
spacewalk:
  suma1.bo2go.home:
    username: 'bjin'
    password: 'Suselinux01!'

runner_dirs:
  - /srv/salt/runners
  ```

> never modify susemanager.conf file as this will be overwritten by SUSE Manager upgrades. \
> after adding and modifying salt-master config files salt-master needs to be restarted. \
```systemctl restart salt-master```

### Download and place the salt states, modules, orchestrate files into salt file_roots e.g. /srv/salt

Below is the content in this repository. Feel free to use other directory and file names.
```
# tree /srv/salt
├── _modules
│   ├── crmhana.py
│   └── patch_hana.py
├── _states
│   ├── crmhana.py
│   └── patch_hana.py
├── myhana
│   ├── init.sls
│   ├── prep_primary_node_for_patching.sls
│   ├── reactor_job_check.sls
│   ├── reactor_patch_diskless_node.sls
│   ├── reactor_patch_master_node.sls
│   ├── reactor_patch_secondary.sls
│   ├── reactor_prep_primary_node_patching.sls
│   ├── reactor_reboot.sls
│   ├── reactor_set_cluster_nodeinfo_grains.sls
│   ├── reactor_set_off_maintenance.sls
│   ├── reactor_start_pacemaker.sls
│   ├── reactor_start_pacemaker_diskless_node.sls
│   ├── reactor_start_pacemaker_oldprimary.sls
│   ├── set_msl_maintenance_off.sls
│   ├── start_pacemaker.sls
│   ├── start_pacemaker_diskless_node.sls
│   └── start_pacemaker_oldprimary.sls
├── orchestrate
│   ├── prep_master_node_for_patching.sls
│   ├── set_maintenance_off.sls
│   ├── start_pacemaker_diskless_node.sls
│   ├── start_pacemaker_oldprimary_node.sls
│   └── start_pacemaker_secondary_node.sls
└── runners
    ├── checkjob_status.py
    ├── patch_hana.py
    └── reboot_host.py
```
__Create and define pillar data for the cluster nodes:__
```
# cat /srv/pillar/myhana/init.sls 
hana_cluster1:
  - hana-1.bo2go.home
  - hana-2.bo2go.home
  - hana-3.bo2go.home
```

> Synchronize the new modules out to the SAP HANA Cluster nodes: \
```# salt "hana-*" saltutil.sync_all``` \

### __Use reactor system:__
The usage of reactor allows great flexibility to define the patching steps in a highly granular manner.

```
# cat /etc/salt/master.d/patchhana.conf 
reactor:
  - 'suma/hana/secondary/patch/ready':
    - /srv/salt/myhana/reactor_patch_secondary.sls
  - 'suma/patch/job/id':
    - /srv/salt/myhana/reactor_job_check.sls
  - 'suma/patch/job/finished':
    - /srv/salt/myhana/reactor_reboot.sls
  - 'suma/reboot/job/id':
    - /srv/salt/myhana/reactor_job_check.sls
  - 'suma/hana_secondary/reboot/job/finished':
    - /srv/salt/myhana/reactor_start_pacemaker.sls
  - 'suma/cluster/secondary/started/ready_unset_maintenance_msl':
    - /srv/salt/myhana/reactor_set_off_maintenance.sls
  - 'suma/cluster/idle/after/maintenance/ready_to_patch_diskless_node':
    - /srv/salt/myhana/reactor_patch_diskless_node.sls
  - 'suma/diskless_node/reboot/job/finished':
    - /srv/salt/myhana/reactor_start_pacemaker_diskless_node.sls
  - 'suma/cluster/diskless_node/started/ready_to_patch_master_node':
    - /srv/salt/myhana/reactor_prep_primary_node_patching.sls
  - 'suma/hana/primary/patch/ready':
    - /srv/salt/myhana/reactor_patch_master_node.sls
  - 'suma/hana_primary/reboot/job/finished':
    - /srv/salt/myhana/reactor_start_pacemaker_oldprimary.sls
```
> After each reactor modification salt-master needs to be restarted. \

## Start the entire workflow:
Run the init.sls state to all SAP HANA Cluster nodes. \
```# salt "hana-*" state.apply myhana```

Once the init state has started all subsequent states will be triggered by defined reactor states.

#
#

## Important timeout and interval settings:

Loop check interval and timeout for runner module checkjob_status:

Below is an example showing that __*interval in seconds*__ and __*timeout in minutes*__ used within the runner module for repeadly checking patch job status.
```
# cat reactor_job_check.sls
patch_job_check_{{ data['data']['node'] }}_{{ data['data']['jobid'] }}:
  runner.checkjob_status.jobstatus:
    - jobid: {{ data['data']['jobid'] }}
    - target_system: {{ data['data']['node'] }}
    - interval: 60
    - timeout: 15
```

In salt execution module __*bocrm.wait_for_cluster_idle*__ function is loop checking for pacemaker cluster state if the state is idle or not. \
> Never touch pacemaker cluster if the cluster state is not idle! \

For this function there are input parameters interval in seconds and timeout in minutes required. \
Select the timeout in minutes in accordance to your cluster SAP HANA realistic start time duration. If SAP HANA primary start takes e.g. 10 minutes than you might need to set a timeout for 15 minutes. \
> The timeout must be set longer than the node reboot takes. If baremetal system takes 30 minutes for one reboot than the timeout must be set greater than 30 minutes.

> The same decision must be taken if using __*bocrm.wait_for_cluster_idle*__ right after unset maintenance and move msl resource states.
```
check_for_clusterstate_after_maintenance_off_{{ hostname }}:
  module.run:
    - name: bocrm.wait_for_cluster_idle
    - interval: 60
    - timeout: 10
    - require:
      - module: start_pacemaker_{{ hostname }}
```

## Important grains:
This patching automation is designed to patch cluster nodes one after the other. In order to identify the node roles as primary, secondary and diskless node the salt execution module __*bocrm.check_sr_status*__ will autot-detect the cluster nodes and current role based on __crm__ and __SAPHanaSR-showAttr__ outputs. \
The function will then auto-set grains key value pairs on each SAP HANA and diskless node.

> If the cluster does not have diskless node than you will only find two nodes.
> On diskless node SAPHanaSR-showAttr does not exist.

Grains output:
```
# salt "hana-*" bocrm.check_sr_status
hana-3.bo2go.home:
    ----------
    cluster_nodes:
        - hana-1
        - hana-2
        - hana-3
    diskless_node:
        - hana-3
    no_SAPHanaSR-showAttr:
        SAPHanaSR-showAttr output is empty. This host is not a SAP HANA host.
hana-2.bo2go.home:
    ----------
    SOK:
        True
    cluster_nodes:
        - hana-1
        - hana-2
        - hana-3
    diskless_node:
        - hana-3
    hana_primary:
        - hana-2
    hana_secondary:
        - hana-1
hana-1.bo2go.home:
    ----------
    SOK:
        True
    cluster_nodes:
        - hana-1
        - hana-2
        - hana-3
    diskless_node:
        - hana-3
    hana_primary:
        - hana-2
    hana_secondary:
        - hana-1
```

The grains ```hana_info``` will be set by the execution module function ```bocrm.check_sr_status```.\

In the state module function ```crmhana.precheck``` the ```hana_info``` grains will be deleted if it exists. \
It is crucial to use ```crmhana.precheck``` and ```bocrm.check_sr_status``` to first delete and then create grains values so that the node roles have been identified correctly. In SAP HANA Cluster the node role can be changed due to fail-over or resource move.

#
#

## Additional salt execution, state, runner modules
In order to capture pacemaker cluster runtime information additional salt __execution modules__ have been developed. \
[bocrm module](./srv/salt/_modules/crmhana.py)

```
# salt "hana*" sys.list_functions bocrm
hana-1.bo2go.home:
    - bocrm.check_if_maintenance
    - bocrm.check_if_nodes_online
    - bocrm.check_sr_status
    - bocrm.delete_cli_ban_rule
    - bocrm.find_cluster_nodes
    - bocrm.get_dc
    - bocrm.get_msl_resource_info
    - bocrm.if_cluster_state_idle
    - bocrm.is_cluster_idle
    - bocrm.is_quorum
    - bocrm.move_msl_resource
    - bocrm.off_msl_maintenance
    - bocrm.pacemaker
    - bocrm.patch_diskless_node
    - bocrm.set_msl_maintenance
    - bocrm.set_off_msl_maintenance
    - bocrm.set_on_msl_maintenance
    - bocrm.start_pacemaker
    - bocrm.stop_pacemaker
    - bocrm.sync_status
    - bocrm.wait_for_cluster_idle
```
> salt execution modules could be used in state file as well. Here an example:
```
check_for_clusterstate_after_maintenance_off_{{ hostname }}:
  module.run:
    - name: bocrm.wait_for_cluster_idle
    - interval: 60
    - timeout: 10
    - require:
      - module: start_pacemaker_{{ hostname }}
```


The __state module__ have been developed for states. \
[state modules](./srv/salt/_states/crmhana.py)
```
# salt "hana*" sys.list_state_functions crmhana
hana-1.bo2go.home:
    - crmhana.precheck
    - crmhana.set_msl_maintenance
```


The __runner modules__ have been developed for calling SUSE Manager API to create patch and reboot jobs.
3 runner modules or python scripts have been written to interact with SUSE Manager API. \
[checkjob_status.py](./srv/salt/runners/checkjob_status.py) \
[patch_hana.py](./srv/salt/runners/patch_hana.py) \
[reboot_host.py](./srv/salt/runners/reboot_host.py)

> In order to use the SUSE Manager API the login credentials must be provided in a salt-master config file. e.g [spacewalk.conf](./etc/salt/master.d/spacewalk.conf)

## Debug and Test:

Salt states and modules can be debugged quite well.
For debugging state execution on the minions use ```salt-minion -l debug``` to see more outputs.

For salt runner module debugging e.g. [patch_hana.py](./srv/salt/runners/patch_hana.py) start salt-master in debug mode. In the debug output the runner module script's output will be shown.

Of course ```salt-run state.event pretty=true``` will show the salt events between salt minion and salt master.

