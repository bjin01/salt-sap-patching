{% set data = salt['pillar.get']('event_data') %}
set_maintenance_off_{{ data.id }}:
  salt.state:
    - tgt: {{ data.id }}
    - sls:
      - myhana.set_msl_maintenance_off
    - kwarg:
        pillar:
          cluster_state: {{ data.data.cluster_idle }} 
