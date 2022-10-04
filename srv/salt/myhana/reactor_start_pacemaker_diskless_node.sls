{% set node =  data['data']['node'] %}
{% if data['data']['reboot'] and node|length %}
adsf_start_pacemaker_{{ node }}:
  runner.state.orchestrate:
    - args:
        - mods: orchestrate.start_pacemaker_diskless_node
        - pillar:
            event_data: {{ data|json }}

{% endif %}
