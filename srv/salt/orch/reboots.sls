run_patching:
  salt.runner:
    - name: sumapatch.reboot 
    - reboot_list: /srv/pillar/sumapatch/completed_20230316141955
    - kwargs:
      delay: 15

