{% set data = salt['pillar.get']('event_data') %}
{% if data.data.reboot %}
start_pacemaker_on_{{ data.id }}:
  salt.state:
    - tgt: {{ data.id }}
    - sls:
      - myhana.start_pacemaker_diskless_node
    - kwarg:
        pillar:
          node: {{ data.data.node }}
{% endif %}
