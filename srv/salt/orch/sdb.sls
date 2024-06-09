venv-salt-minion-config:
  file.managed:
    - name: /etc/venv-salt-minion/minion.d/sdb.conf
    - contents: |
        patching_info:
          driver: cache
          bank: patching_info
          cachedir: /var/cache/venv-salt-minion
mkdir_patching_info:
  file.directory:
    - name: /var/cache/venv-salt-minion/patching_info
    - user: root

venv-salt-minion-restart:
  cmd.wait:
    - name: venv-salt-call --local service.restart venv-salt-minion
    - bg: True
    - order: last
    - watch:
      - file: venv-salt-minion-config
