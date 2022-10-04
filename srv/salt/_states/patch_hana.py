
def patch(name, **kwargs):
    '''
    Call suse manager / uyuni xmlrpc api and schedule a apply_all_patches job for given salt-minion name

    You could provide a delay in minutes or fixed schedule time for the job in format of: 15:30 20-04-1970

    If no delay or schedule is provided then the job will be set to now.

    Use cae:
    It can be helpful to create a reactor that catches certain event sent by minion by e.g. highstate or minion registration and trigger to patch the minion with all available patches from SUSE Manager / Uyuni 
    
    CLI Example:

    .. code-block:: bash

        salt "mysystem*" patch_hana.patch your-minion.something.domain delay=15

    State Example in sls:

    .. code-block:: yaml

        applypatches:
          patch_hana.patch:
            - name: "anything"
            - kwargs: { 
                delay: 15
            }
              
    '''
    ret = {
        "name": name,
        "changes": {},
        "result": False,
        "comment": "",
    }
    output = __salt__["patch_hana.patch"](kwargs=kwargs)
    if int(output["Patch Job ID is"]) > 0:

        ret["changes"] = {
            "old": "Nothing",
            "new": output,
        }
        ret["result"] = True
    else:
        ret["changes"] = {
            "old": "Nothing",
            "new": "Failed to schedule job",
        }
        ret["result"] = False
    return ret 
    
