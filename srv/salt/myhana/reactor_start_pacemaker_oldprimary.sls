{% set node =  data['data']['node'] %}
{% if data['data']['reboot'] and node|length and node in data['id'] %}
adsf_start_pacemaker_{{ node }}:
  runner.state.orchestrate:
    - args:
        - mods: orchestrate.start_pacemaker_oldprimary_node
        - pillar:
            event_data: {{ data|json }}

{% endif %}
