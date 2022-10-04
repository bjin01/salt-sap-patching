{% set node =  data['data']['node'] %}
{% if data['data']['cluster_idle'] and node|length %}
set_msl_maint_off_{{ node }}:
  runner.state.orchestrate:
    - args:
        - mods: orchestrate.set_maintenance_off
        - pillar:
            event_data: {{ data|json }}
{% endif %}
