precheck_myhana_test:
  crmhana.precheck:
    - name: hana

{% set node = salt['grains.get']('id') %}
check_sr_status_{{ node }}:
  module.run:
    - name: bocrm.check_sr_status
    - require:
      - crmhana: precheck_myhana_test 

{% set secondary_hostname = salt['grains.get']('hana_info:hana_secondary') %}
{% if secondary_hostname and secondary_hostname|length and secondary_hostname[0] in node %}
maint_hana-secondary_{{ secondary_hostname[0] }}:
  crmhana.set_msl_maintenance:
    - name: hana
    - msl_resource: msl_SAPHana_BJK_HDB00
    - require:
      - module: check_sr_status_{{ node }}

send_event_{{ secondary_hostname[0] }}:
  event.send:
    - name: suma/hana/secondary/patch/ready
    - data:
      secondary_node: {{ secondary_hostname[0] }}
    - require:
      - crmhana: maint_hana-secondary_{{ secondary_hostname[0] }}
{% endif %}

