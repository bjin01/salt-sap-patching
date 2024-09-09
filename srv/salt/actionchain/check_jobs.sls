check_ac_jobs:
  salt.runner:
    - name: sumajobs.actionchain_jobs
    - jobs_file: {{ pillar['ac_job_file']  }}
    - interval: 2
    - timeout: 10
    - email_to: "bo.jin@jinbo01.com"
    - log_level: info

