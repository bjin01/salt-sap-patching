{% set hostname = salt['grains.get']('fqdn') %}
{% if hostname|length %}
start_pacemaker_{{ hostname }}:
  module.run:
    - name: bocrm.start_pacemaker

check_for_clusterstate_idle_{{ hostname }}:
  module.run:
    - name: bocrm.wait_for_cluster_idle
    - interval: 60
    - timeout: 10
    - require:
      - module: start_pacemaker_{{ hostname }}
{% endif %}

precheck_myhana_test_{{ hostname }}:
  crmhana.precheck:
    - name: hana
    - require:
      - module: check_for_clusterstate_idle_{{ hostname }}

find_node_roles_from_crm_mon_{{ hostname }}:
  module.run:
    - name: hana_roles.find_node_roles_from_crm_mon
    - require:
      - crmhana: precheck_myhana_test_{{ hostname }}

send_event_diskless_node_finished_{{ hostname }}:
  event.send:
    - name: suma/cluster/diskless_node/started/ready_to_patch_master_node
    - data:
        message: "diskless node pacemaker started and cluster state is idle, ready to continue with master node"
    - require:
      - module: find_node_roles_from_crm_mon_{{ hostname }}
