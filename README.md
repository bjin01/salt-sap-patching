# Automated OS Patching for SAP HANA Scale-Up clusters using SUSE Manager and salt states
This repository contains saltstack configurations, modules and states which have been created for a fully automated patching of SAP HANA Database Scale-up cluster.

## __Motivation__
Patching SAP HANA Scale-up cluster Linux OS can be challenging. Before patching the Linux (SLES-for-SAP) OS administrators need to issue certain cluster actions and move resources from one node to another. The cluster maintenance steps (manually) could be found in [SAP HANA System Replication Scale-Up - Performance Optimized Scenario](https://documentation.suse.com/sbp/all/single-html/SLES4SAP-hana-sr-guide-PerfOpt-15/#id-maintenance). 

__The saltstack states and modules you can find here is to help automating SAP HANA Cluster maintenance tasks by:__
* precheck cluster health and SAP HANA System Replication status (SOK)
* set SAP HANA msl_resource into maintenance mode
* schedule and deploy patch job in SUSE Manager to the cluster nodes 
* monitor SUSE Manager patch job status
* schedule OS reboot after patching
* start pacemaker, unset maintenance mode in pacemaker, clear location contraints(cli-ban)
* move msl_resource from primary SAP HANA System Replication site to the secondary site 

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
  - 'suma/hana/cluster/nodeinfo/*':
    - /srv/salt/myhana/reactor_set_cluster_nodeinfo_grains.sls
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

