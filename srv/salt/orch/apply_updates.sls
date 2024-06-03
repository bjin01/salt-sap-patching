{% set minion_id = grains['id'] %}
{% if grains['os_family'] is match('Suse') %}
apply_zypper_updates_{{ minion_id }}:
  cmd.script:
    - name: update.sh
    - source: salt://orch/scripts/update.sh
    - cwd: /
#    - stateful:
#      - test_name: apply_updates.sh test
{% endif %}
