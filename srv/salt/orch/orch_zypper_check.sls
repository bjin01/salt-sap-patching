orch_zypper_check:
  salt.state:
    - tgt: "pxe*0*"
    - sls:
      - orch.check_zypper_ref
    - test: True
