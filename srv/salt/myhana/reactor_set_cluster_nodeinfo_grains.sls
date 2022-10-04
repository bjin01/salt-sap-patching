{% set node =  data['id'] %}
{% set grainsdata =  data['data']['hana_nodes'] %}
{% if grainsdata %}
set_grains_info_for_{{ node }}:
  runner.hanagrains.set:
    - hana_nodes: {{ grainsdata }}

{% endif %}

