{% set primary_node = salt['grains.get']("hana_info:hana_primary") %}
{% set node_id = salt['grains.get']("id") %}
{% if primary_node[0] in node_id %}
precheck_myhana_test_{{ node_id }}:
  crmhana.precheck:
    - name: hana

check_sr_status_{{ node_id }}:
  module.run:
    - name: bocrm.check_sr_status
    - require:
      - crmhana: precheck_myhana_test_{{ node_id }}

move_msl_resource_{{ node_id }}:
  module.run:
    - name: bocrm.move_msl_resource
    - interval: 60
    - timeout: 10
    - require:
      - module: check_sr_status_{{ node_id }}

maint_hana-primary_{{ node_id }}:
  crmhana.set_msl_maintenance:
    - name: hana
    - msl_resource: msl_SAPHana_BJK_HDB00
    - require:
      - module: move_msl_resource_{{ node_id }}

send_event_{{ primary_node[0] }}:
  event.send:
    - name: suma/hana/primary/patch/ready
    - data:
      primary_node: {{ primary_node[0] }}
    - require:
      - crmhana: maint_hana-primary_{{ node_id }}
{% endif %}
