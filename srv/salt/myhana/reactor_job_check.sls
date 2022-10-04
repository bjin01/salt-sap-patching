patch_job_check_{{ data['data']['node'] }}_{{ data['data']['jobid'] }}:
  runner.checkjob_status.jobstatus:
    - jobid: {{ data['data']['jobid'] }}
    - target_system: {{ data['data']['node'] }}
    - interval: 60
    - timeout: 15
