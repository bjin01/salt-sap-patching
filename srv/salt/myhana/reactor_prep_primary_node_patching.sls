{% set node =  data['id'] %}
prep_primary_node_{{ node }}:
  runner.state.orchestrate:
    - args:
        - mods: orchestrate.prep_master_node_for_patching
