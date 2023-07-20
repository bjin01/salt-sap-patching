import subprocess

def __virtual__():
    
    return True

def send_email(message, subject, recipients):
    recipient_list = ','.join(recipients)
    command = 'echo "{message}" | mailx -s "{subject}" {recipients}'.format(
        message=message,
        subject=subject,
        recipients=recipient_list
    )

    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode == 0:
            return 'Email sent successfully. {}'.format(subject)
        else:
            return 'Failed to send email. Error: {}'.format(result.stderr)
    except subprocess.CalledProcessError as e:
        return 'Failed to send email. Error: {}'.format(e.stderr)