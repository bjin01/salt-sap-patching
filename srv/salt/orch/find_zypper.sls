# find_zypper.sls
{% set minion_id = grains['id'] %}

if_zypper_{{ minion_id }}:
  file.exists:
    - name: /usr/bin/zypper

check_zypper_process_{{ minion_id }}:
  module.run:
    - name: find_zypper.run
    - watch:
      - file: if_zypper_{{ minion_id }}

run_zypper_list_updates_on_{{ minion_id }}:
  module.run:
    - name: find_zypper.check_updates
    - require: 
      - module: find_zypper.run
   

run_zypper_up_on_failure_{{ minion_id }}:
  cmd.run:
    - name: /usr/bin/zypper --non-interactive --no-refresh update --auto-agree-with-licenses
    - bg: True
    - require: 
      - module: find_zypper.check_updates
