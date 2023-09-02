disable_http_proxy:
  file.replace:
    - name: /etc/sysconfig/proxy
    - pattern: '^PROXY_ENABLED=.*'
    - repl: 'PROXY_ENABLED="no"'

snapper_create_snapshot_prepatch:
  module.run:
    - btrfs.snapper_create:
      - bundle: "bo state"
      - userdata: "important=yes"
      - type: "single"
      - cleanup_algorithm: "number"

{% if "pxesap01.bo2go.home" == grains['id'] %}
test_script_run_{{ grains['id'] }}:
  cmd.script:
    - name: salt://orch/scripts/testscript.sh 30
    - source: salt://orch/scripts/testscript.sh
    - stateful: True
{% endif %}

zypper_ref_force:
  cmd.run:
    - name: zypper ref -f 2>&1 > /dev/null &
    - bg: True

