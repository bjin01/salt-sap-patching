run_patching:
  salt.runner:
    - name: sumapatch.patch 
    - target_system: pxesap01.bo2go.home
    - kwarg:
        delay: 60


