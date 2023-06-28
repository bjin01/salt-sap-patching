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

