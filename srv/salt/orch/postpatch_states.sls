enable_http_proxy:
  file.replace:
    - name: /etc/sysconfig/proxy
    - pattern: '^PROXY_ENABLED=.*'
    - repl: 'PROXY_ENABLED="yes"'

check_btrfs_readonly_if:
  cmd.script:
    - source: salt://orch/btrfs_check/btrfs_ro_check.sh
    - cwd: /

snapper_create_snapshot_postpatch:
  module.run:
    - btrfs.snapper_create:
      - bundle: "bo state"
      - userdata: "important=yes"
      - type: "single"
      - cleanup_algorithm: "number"