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

try_delete_cli_ban_rule_{{ hostname }}:
  module.run:
    - name: bocrm.delete_cli_ban_rule
    - msl_resource_name: msl_SAPHana_BJK_HDB00
    - interval: 60
    - timeout: 10
    - require:
      - module: check_for_clusterstate_idle_{{ hostname }}

set_msl_maintenance_off_{{ hostname }}:
  module.run:
    - name: bocrm.off_msl_maintenance
    - msl_resource_name: msl_SAPHana_BJK_HDB00
    - require:
      - module: check_for_clusterstate_idle_{{ hostname }}

check_for_clusterstate_after_maintenance_off_{{ hostname }}:
  module.run:
    - name: bocrm.wait_for_cluster_idle
    - interval: 60
    - timeout: 10
    - require:
      - module: set_msl_maintenance_off_{{ hostname }}

