{% set secondary_host =  data['data']['secondary_node'] %}
{% if secondary_host is defined and secondary_host|length %}
patch_sec_node_{{ secondary_host }}:
  runner.patch_hana.patch:
    - target_system: {{ secondary_host }}
    - delay: 1
{% endif %}
