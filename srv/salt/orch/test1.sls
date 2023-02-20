run_patching:
  salt.runner:
    - name: sumapatch.patch 
    - groups:
      - P-Basis-suma
      - testgrp
    - kwarg:
        delay: 60


