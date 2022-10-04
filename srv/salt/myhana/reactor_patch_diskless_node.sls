{% set diskless_node  =  data['data']['diskless_node'] %}
{% if diskless_node is defined and diskless_node|length %}
patch_diskless_node_{{ diskless_node }}:
  runner.patch_hana.patch:
    - target_system: {{ diskless_node }}
    - delay: 1
{% endif %}

