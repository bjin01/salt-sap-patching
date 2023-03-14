run_patching:
  salt.runner:
    - name: sumapatch.patch 
    - groups:
      - testgrp
      - P-Basis-suma
    - kwargs:
      delay: 5
      logfile: /var/log/patching/sumapatching.log
      jobchecker_timeout: 20
      jobchecker_emails:
        - bo.jin@jinbo01.com
        - bo.jin@suseconsulting.ch
      grains: 
        no_patch: False



