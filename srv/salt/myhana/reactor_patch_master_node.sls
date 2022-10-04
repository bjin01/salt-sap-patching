{% set primary_node  =  data['data']['primary_node'] %}
{% if primary_node is defined and primary_node|length and primary_node in data['id'] %}
patch_primary_node_{{ primary_node }}:
  runner.patch_hana.patch:
    - target_system: {{ primary_node }}
    - delay: 1
{% endif %}

