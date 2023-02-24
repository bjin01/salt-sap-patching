run_patching:
  salt.runner:
    - name: sumapatch.patch 
    - groups:
      - P-Basis-suma
      - testgrp
    - kwargs:
      delay: 60
      logfile: /var/log/patching/sumapatching.log
      grains: 
        no_patch: False
      presence_check_timeouts:
        timeout: 2
        gather_job_timeout: 5



