check_zypper_refresh:
  cmd.script:
    - source: salt://orch/zypper/check_zypper_refresh.sh
    - cwd: /
    - stateful: True
    - success_stderr:
      - ERROR
      - error
    - success_stdout:
      - "All is good"

