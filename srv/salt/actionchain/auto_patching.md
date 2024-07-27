# "Automated Patching" using action chains in Uyuni / SUSE Manager
# 1. Introduction
# 2. Prerequisites
# 3. Excuting the salt runner module to start the patching
# 4. Conclusion

# 1. Introduction
# Automated patching is a feature that allows you to automatically patch your systems based on a schedule. This feature is available in Uyuni and SUSE Manager. The automated patching feature uses action chains to perform the patching. Action chains are a series of actions that are executed in a specific order. In this case, the action chain will perform the following actions:
* Run salt pre-patch states
* Apply updates 
* Reboot the system
* Run salt post-patch states

# 2. Prerequisites
Before you can use the automated patching feature, you need to make sure that the following prerequisites are met:
* You have a Uyuni or SUSE Manager server installed and configured.
* You have a Uyuni or SUSE Manager client registered to the server.
* salt runner modules [actionchain](../_runners/actionchain.py) and [sumajobs](../_runners/sumajobs.py) are placed in runners_dirs
* 

# 3. Excuting the salt runner module to start the patching
To start the automated patching process, you need to execute the salt runner module that is responsible for running the action chain. You can do this by running the following command on the Uyuni or SUSE Manager server:
```
salt-run uyuni.action_chain_run chain_id=<chain_id>
```
Where `<chain_id>` is the ID of the action chain that you want to run.
