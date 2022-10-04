{% set nodes = salt['pillar.get']("hana_cluster1") %}
{% for i in nodes %}
precheck_{{ i }}:
  salt.state:
    - tgt: {{ i }}
    - sls:
      - myhana.precheck
    
prep_hana_master_node_{{ i }}:
  salt.state:
    - tgt: {{ i }}
    - sls:
      - myhana.prep_primary_node_for_patching
    - require:
      - salt: precheck_{{ i }}
{% endfor %}
