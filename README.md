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
SLES-for-SAP 15SP3 x86_64
SAP HANA SR Scale-up - 3 node cluster (diskless setup)
SUSE Manager 4.2.8
salt-minion-3004
salt-master-3002.2
python3.6

![Architecture](./saphana-patching-architecture)

