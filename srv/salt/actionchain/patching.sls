run_patching:
  salt.runner:
    - name: actionchain.run 
    - groups:
      - a_group1
      - b_group2
    - pre_states:
      - manager_org_1.bo_state_test
      - mypkgs
    - post_states:
      - pause
    - delay: 5
    - reboot: True
    - no_update: False
    - job_check_state: actionchain.check_jobs
