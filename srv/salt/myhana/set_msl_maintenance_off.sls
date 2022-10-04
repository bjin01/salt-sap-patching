set_msl_maintenance_off:
  module.run:
    - name: bocrm.off_msl_maintenance
    - msl_resource_name: msl_SAPHana_BJK_HDB00

check_for_clusterstate_after_maintenance_off:
  module.run:
    - name: bocrm.wait_for_cluster_idle
    - interval: 60
    - timeout: 10
    - require:
      - module: set_msl_maintenance_off

{% set hana_info = salt['grains.get']('hana_info') %}
{% set node = salt['grains.get']('id') %}
check_sr_status_{{ node }}:
  module.run:
    - name: bocrm.check_sr_status
    - require:
      - module: check_for_clusterstate_after_maintenance_off

get_diskless_node_fqdn_{{ node }}:
  grains.exists:
    - name: "hana_info:diskless_node"
    - require:
      - module: check_sr_status_{{ node }}

{% set diskless_node  = salt['grains.get']('hana_info:diskless_node') %}
{% if diskless_node|length %}
send_event_ready_to_patch_next_{{ diskless_node[0] }}:
  event.send:
    - name: suma/cluster/idle/after/maintenance/ready_to_patch_diskless_node
    - data:
        message: "patch next node"
        diskless_node: {{ diskless_node[0] }} 
    - require:
      - grains: get_diskless_node_fqdn_{{ node }}
{% endif %}
