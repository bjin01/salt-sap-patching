# Uyuni / SUSE Manager - jobchecker monitoring scheduled actions and send emails

The jobchecker.py runs as systemd service on SUSE Manager or Uyuni Server.
It runs indefinitely and provides an API endpoint to receive scheduled job information from salt-runner module [sumapatch](../srv/salt/_runners/sumapatch.py). \

API endpoint for POST method:
```http://localhost:12345/jobchecker ```

The dictionary sent to the API has below scheme:
```
{
    "Patching": [
        {
            "pxesap01.bo2go.home": {
                "Patch Job ID is": 722,
                "event send": true
            }
        },
        {
            "pxesap02.bo2go.home": {
                "Patch Job ID is": 723,
                "event send": true
            }
        }
    ],
    "jobchecker_timeout": 25,
    "jobstart_delay": 5
}
```

Tested on: SUSE Manager 4.3 x86 on SLES15SP4

After configured monitoring timeout emails with job status will be sent out.\
During maintenance windows admins who scheduled patch jobs through salt-runner module sumapatch will be forwarded to jobchecker for further job status monitoring.

The jobchecker runs every incoming request in an separate thread concurrently. This feature allows admins to sent multiple salt-runner module sumapatch results to the jobchecker.

The script uses the same configuration file that [sumapatch](../srv/salt/_runners/sumapatch.py) uses. (Default: [/etc/salt/master.d/spacewalk.conf](../etc/salt/master.d/spacewalk.conf))

Use the systemd unit file [suma-jobchecker.service](./suma-jobchecker.service)

Copy the [suma-jobchecker.service](./suma-jobchecker.service) to ```/etc/systemd/system/suma-jobchecker.service``` \
Copy the [jobchecker.py](jobchecker.py) to ```/usr/local/suma_jobcheck.py``` \
```systemctl daemon-reload``` \


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
ExecStart=/usr/bin/python3.6 /usr/local/suma_jobcheck.py

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
mkdir /var/log/patching/
touch /var/log/patching/patching.log
chown salt. /var/log/patching/patching.log

cp srv/salt/_runners/sumapatch.py /usr/share/susemanager/modules/runners/
cp jobchecker/suma-jobchecker.service /etc/systemd/system/suma-jobchecker.service
systemctl daemon-reload
cp jobchecker/jobchecker.py /usr/local/suma_jobcheck.py
systemctl enable suma-jobchecker.service
systemctl start suma-jobchecker.service
```
Now the jobchecker is running. Log file /var/log/patching/patching.log provides information if job IDs have been sent to the jobchecker API.



