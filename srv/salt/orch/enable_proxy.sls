enable_http_proxy:
  file.replace:
    - name: /etc/sysconfig/proxy
    - pattern: '^PROXY_ENABLED=.*'
    - repl: 'PROXY_ENABLED="yes"'
