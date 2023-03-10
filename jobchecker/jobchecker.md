# Uyuni / SUSE Manager - jobchecker monitoring scheduled actions

The jobchecker.py is running as systemd service on SUSE Manager or Uyuni Server itself.
It runs indefinitely and provides a API endpoint to receive scheduled jobs information from saltrunner module [sumapatch](../srv/salt/_runners/sumapatch.py)

The script uses the same configuration file that [sumapatch](../srv/salt/_runners/sumapatch.py) uses. (Default: [/etc/salt/master.d/spacewalk.conf](../etc/salt/master.d/spacewalk.conf))

Use the systemd unit file [suma-jobchecker.service](./suma-jobchecker.service)

Copy the [suma-jobchecker.service](./suma-jobchecker.service) to ```/etc/systemd/system/suma-jobchecker.service``` \
Copy the [jobchecker.py](jobchecker.py) to ```/usr/local/suma_jobcheck.py``` \
```systemctl daemon-reload``` \
