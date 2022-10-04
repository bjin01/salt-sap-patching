{% set node =  data['data']['node'] %}
{% if data['data']['reboot'] and node|length %}
reboot_{{ node }}:
  runner.reboot_host.reboot:
    - target_system: {{ node }}
{% endif %}
