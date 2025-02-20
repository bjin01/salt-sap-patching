import subprocess
import json
import argparse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def get_snapshots_for_vm(vcenter_name):
    command = f'salt-cloud --out json -f list_snapshots "{vcenter_name}"'

    try:
        # Run the command with subprocess.PIPE to capture stdout and stderr
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Error executing command (list-snapshots): {stderr}")
            return None

        # Parse the JSON output
        output = json.loads(stdout)
        # print(f"JSON Output from {vcenter_name}: {output}")
        return output

    except subprocess.CalledProcessError as e:
        print(f"Error executing command (list-snapshots): {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON (list-snapshots): {e}")
        return None

def send_email(subject, body, to_email, from_email, smtp_server, smtp_port):
    """Send an email with the given subject and body."""
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the email body
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Set up the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail(from_email, to_email, msg.as_string())
            print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

def print_snapshots(snapshots, description_filter, email_body):
    """Print snapshots that match the description filter and send an email if found."""
    snapshot_found = False

    if snapshots:
        # Iterate through the nested snapshot structure
        for provider, vm_data in snapshots.items():  # Iterating over 'vmware'
            for _, snapshot_data in vm_data.items():  # Iterating over VM names like 'testvm'
                for host, snapshot_info in snapshot_data.items():  # Iterating over snapshot names
                    if isinstance(snapshot_info, dict):
                        for _, data in snapshot_info.items():
                            description = data.get('description', '')
                            name_in_snapshot = data.get('name', '')
                            if description_filter in description or description_filter in name_in_snapshot:
                                snapshot_found = True
                                # Prepare the details to be included in the email body
                                email_body += f"Snapshot found on: {host}\n"
                                email_body += f"Snapshot Name: {data.get('name', 'no name')}\n"
                                email_body += f"Description: {description}\n"
                                email_body += f"Created: {data.get('created', 'No creation date')}\n"
                                email_body += f"State: {data.get('state', 'No state')}\n"
                                email_body += f"Path: {data.get('path', 'No path')}\n"
                                email_body += "-" * 40 + "\n"

    else:
        print("No snapshots found.")

    if not snapshot_found:
        return email_body, False
    else:
        return email_body, True

def process_jobs(vcenter_name, description_filter, email_body):

    # Fetch snapshots for the short hostname
    snapshots = get_snapshots_for_vm(vcenter_name)
    if snapshots:
        print(f"Snapshots in {vcenter_name}:")
        email_content, snapshot_found = print_snapshots(snapshots, description_filter, email_body)
        if snapshot_found:
            email_body += email_content
        else:
            email_body += f"No snapshots found in '{vcenter_name}'."

        print(f"{email_body}")
    else:
        email_body += f"No snapshots in {vcenter_name}.\n"
        print(f"No snapshots found in '{vcenter_name}'.")
    return email_body

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Process a JSON file to fetch snapshots for systems.")
    parser.add_argument('--vcenter_names', required=True, nargs='+', help="names of salt-cloud provider")
    parser.add_argument('--description_filter', required=True, help="The description filter for snapshots (e.g., 'Snapshot vor Uyuni-Update').")
    parser.add_argument('--smtp_server', required=True, help="SMTP server for sending emails")
    parser.add_argument('--smtp_port', required=True, type=int, help="SMTP port for sending emails")
    parser.add_argument('--from_email', required=True, help="From email address")
    parser.add_argument('--to_email', required=True, help="To email address")

    # Parse the command-line arguments
    args = parser.parse_args()

    # Email details
    email_details = {
        'smtp_server': args.smtp_server,
        'smtp_port': args.smtp_port,
        'from_email': args.from_email,
        'to_email': args.to_email
    }

    summary_email_body = ""

    for vcenter_name in args.vcenter_names:
        email_body = ""
        summary_email_body += process_jobs(vcenter_name, args.description_filter, email_body)

    # Send the email with snapshot details
    send_email(subject=f"Snapshots list from VMware VMs",
                body=summary_email_body,
                to_email=email_details['to_email'],
                from_email=email_details['from_email'],
                smtp_server=email_details['smtp_server'],
                smtp_port=email_details['smtp_port']
     )

if __name__ == "__main__":
    main()
