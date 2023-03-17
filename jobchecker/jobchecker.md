# Uyuni / SUSE Manager - jobchecker monitoring scheduled actions and send emails

The jobchecker.py runs as systemd service on SUSE Manager or Uyuni Server.
It runs indefinitely and provides an API endpoint to receive scheduled job information from salt-runner module [sumapatch](../srv/salt/_runners/sumapatch.py).

## __Features:__
* Use SUSE Manager API to get pending, completed and failed jobs and compare them with given job IDs.
* The script runs as systemd service
* The script provides an API for receiving job ID information for further monitoring
* If jobs are no more pending emails about job status will be sent.
* For the systems where Job has been completed a file in /srv/pillar/sumapatch will be written for further reboot activities


For security reasons the API endpoint only listen on localhost (127.0.0.1 and port 12345). Yes, the port should be made configurable.

API endpoint for POST method:
```http://127.0.0.1:12345/jobchecker ```

<details><summary>The dictionary sent to the API has below scheme:</summary>

```
{
    "Patching": [
        {
            "saturn": {
                "Patch Job ID is": 731,
                "event send": true
            }
        },
        {
            "pxesap01.bo2go.home": {
                "Patch Job ID is": 732,
                "event send": true
            }
        },
        {
            "pxesap02.bo2go.home": {
                "Patch Job ID is": 733,
                "event send": true
            }
        }
    ],
    "jobchecker_emails": [
        "admin@mycorp.com",
        "admin2@others.com"
    ],
    "jobchecker_timeout": 25,
    "jobstart_delay": 5
}
```
</details>
Tested on: SUSE Manager 4.3 x86 on SLES15SP4 with python v3.6


After configured monitoring timeout emails with job status will be sent out.\
During maintenance windows admins who scheduled patch jobs through salt-runner module sumapatch will be forwarded to jobchecker for further job status monitoring.

The jobchecker runs every incoming HTTP POST request in an separate thread concurrently. This feature allows admins to run multiple salt-runner module sumapatch without to wait for existing job monitor task to finish.

The script uses the same configuration file that [sumapatch](../srv/salt/_runners/sumapatch.py) uses. (Default: [/etc/salt/master.d/spacewalk.conf](../etc/salt/master.d/spacewalk.conf))

Use the systemd unit file [suma-jobchecker.service](./suma-jobchecker.service)

Copy the [suma-jobchecker.service](./suma-jobchecker.service) to ```/etc/systemd/system/suma-jobchecker.service``` \
Copy the [jobchecker.py](jobchecker.py) to ```/usr/local/bin/suma_jobcheck.py``` \
```systemctl daemon-reload```

## Email notification:
For email notification local smtp will be used. On SLES usually __postfix__ must be configured and running properly in order to send emails to the outter world.

## __Create configuration file for SUSE Manager API:__

**Password encryption**:
The new scripts are supporting encrypted password in the configuration file.
Therefore use the [encrypt.py](../encrypt.py) to generat a encrypted password:
```
python3.6 encrypt.py <YOUR-SUMA-API-PASSWORD>
```
The output of encrypt.py gives the encrypted password and the key that will be needed for decryption.
The encrypted password must be provided in the configuration file and stored in ```/etc/salt/master.d```
For example:
```
suma_api:
  suma1.bo2go.home:
    username: 'admin'
    password: gAAAAABj_xzeu23IpzKM-mYOYOS1HwV3leuntobtovVru5TvK0pdJVJjvStXPSO3IOOCTfBSoIQZHE_GhoCokaaj0tAOdyzcvQ==
```

__The key from the encrypt.py output must be provided through environment variable in [systemd unit file](suma-jobchecker.service)__
```
[Unit]
Description=SUMA Jobchecker
After=taskomatic.service
Requires=taskomatic.service

[Service]
Type=simple
Environment="SUMAKEY=R2bfp223Qsk-pX970Jw8tyJUChT4-e2J8anZ4G4n4IM="
Restart=always
ExecStart=/usr/bin/python3.6 /usr/local/bin/suma_jobcheck.py

[Install]
WantedBy=multi-user.target
```
**Additionally you must set an OS environment variable SUMAKEY**
```
export SUMAKEY=R2bfp223Qsk-pX970Jw8tyJUChT4-e2J8anZ4G4n4IM=
```
The SUMAKEY will be needed by the salt-runner module which will use it for password encryption. \
**If the SUMAKEY is not found then the script will use the value of password in [sumaconfig](../etc/salt/master.d/spacewalk.conf) as clear text password.**

## __Installation steps (run as root or with sudo):__

```
git clone https://github.com/bjin01/salt-sap-patching.git
cd salt-sap-patching
cp jobchecker/suma-jobchecker.service /etc/systemd/system/suma-jobchecker.service
systemctl daemon-reload
cp jobchecker/jobchecker.py /usr/local/suma_jobcheck.py
systemctl enable suma-jobchecker.service
systemctl start suma-jobchecker.service
```
Now the jobchecker is running. Log file ```/var/log/jobchecker.log``` provides information if job IDs have been sent to the jobchecker API.



