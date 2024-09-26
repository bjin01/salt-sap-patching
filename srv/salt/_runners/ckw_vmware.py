import subprocess
import salt.utils.platform

def create_snapshot(vm_name, snapshot_name, description=None, memdump=False, quiesce=False):
    """
    Create a snapshot for the given VM using salt-cloud.

    :param vm_name: Name of the VM (e.g., "ckw-vts992 (SLES15)")
    :param snapshot_name: Name of the snapshot (e.g., "vor_patching")
    :param description: Optional description for the snapshot (e.g., "salt test")
    :param memdump: Boolean to indicate whether to include memory in the snapshot (default False)
    :param quiesce: Boolean to indicate whether to quiesce the filesystem (default False)
    :return: Result of the salt-cloud command execution.
    """
    # Base command
    command = [
        'salt-cloud',
        '-y',
        '-a',
        'create_snapshot',
        vm_name,
        f'snapshot_name={snapshot_name}'
    ]

    # Add optional arguments
    if description:
        command.append(f'description="{description}"')
    command.append(f'memdump={str(memdump)}')
    command.append(f'quiesce={str(quiesce)}')

    try:
        # Run the salt-cloud command
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Return the output
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.CalledProcessError as e:
        return {
            'error': True,
            'stdout': e.stdout,
            'stderr': e.stderr,
            'returncode': e.returncode
        }

