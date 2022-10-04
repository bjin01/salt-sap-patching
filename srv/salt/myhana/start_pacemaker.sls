{% set hostname = salt['grains.get']('fqdn') %}
{% if hostname|length %}
start_pacemaker_{{ hostname }}:
  module.run:
    - name: bocrm.start_pacemaker

check_for_clusterstate_after_maintenance_off_{{ hostname }}:
  module.run:
    - name: bocrm.wait_for_cluster_idle
    - interval: 60
    - timeout: 10
    - require:
      - module: start_pacemaker_{{ hostname }}
{% endif %}

{% set hana_info = salt['grains.get']('hana_info') %}
{% if hana_info.hana_secondary|length %}
send_event_ready_to_unset_msl_maintenance_{{ hana_info.hana_secondary }}:
  event.send:
    - name: suma/cluster/secondary/started/ready_unset_maintenance_msl
    - data:
        message: "secondary node pacemaker started and cluster state is idle, ready to continue"
        node: {{ hana_info.hana_secondary }} 
        cluster_idle: True
    - require:
      - module: check_for_clusterstate_after_maintenance_off_{{ hostname }}
{% endif %}
