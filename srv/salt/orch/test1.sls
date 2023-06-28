run_patching:
  salt.runner:
    - name: sumapatch.patch 
#    - target_system: pxesap01.bo2go.home
    - groups:
      - testgrp
    - kwargs:
      delay: 1
      timeout: 3
      gather_job_timeout: 15
      logfile: /var/log/patching/sumapatching.log
      jobchecker_timeout: 20
      jobchecker_emails:
        - bo.jin@jinbo01.com
        - bo.jin@suseconsulting.ch
      grains: 
        no_patch: False
      t7user: t7udp
      prep_patching: orch.prepatch_states
      post_patching: orch.postpatch_states
      patch_level: 2023-Q2



