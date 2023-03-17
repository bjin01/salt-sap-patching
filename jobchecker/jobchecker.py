import tornado.ioloop
import tornado.web
import concurrent.futures
import threading
import json
import yaml
from salt.ext import six
from cryptography.fernet import Fernet
import os
import time
from datetime import datetime
import logging
import atexit
import socket

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler = logging.FileHandler('/var/log/jobchecker.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

log.addHandler(file_handler)

class MyRequestHandler(tornado.web.RequestHandler):
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    _sessions = {}

    def post(self):
        # Get the data from the request
        data = self.request.body
        dict_data = json.loads(data)
        if len(dict_data["Patching"]) > 0:
            self.write("Jobchecker tasks started. {}".format(datetime.now()))
            future = self.executor.submit(self.monitor, dict_data)
            print("threads started: {}".format(datetime.now()))
            future.add_done_callback(self.on_task_done)
        else:
            self.write("No Patching info. Jobchecker not started.{}".format(datetime.now()))
            #log.info("No Patching info. Jobchecker not started.")


    def on_task_done(self, future):

        try:
            # Get the result of the task from the future object
            result = future.result()
            # Do something with the result
            log.info("Sending result via email.")
            self._send_emails(result)
            self.write_reboot_list(result)
        except Exception as e:
            # Handle any exceptions that occurred during the task execution
            log.error("Task failed: {}".format(str(e)))
        finally:
            self.finish()
        return True
    
    def write_reboot_list(self, data):
        now = datetime.now()
        date_time = now.strftime("%Y%m%d%H%M%S")
        completed_list = {}
        completed_entity = "completed_{}".format(date_time)
        file_path = "/srv/pillar/sumapatch/{}".format(completed_entity)
        completed_list[completed_entity] = []
        if len(data["completed"]) > 0:
                for i in data["completed"]:
                    for a, _ in i.items():
                        completed_list[completed_entity].append(a)
        # convert the dictionary to YAML
        if len(completed_list[completed_entity]) > 0:
            yaml_data = yaml.dump(completed_list)
            # write the YAML data to a file
            with open(file_path, 'w') as file:
                file.write(yaml_data)
                log.info("Completed system list has been written to: {}".format(file_path))

        return
    
    def format_html_content(self, data):
        methods = ["pending",
                   "completed",
                   "failed",
                   "cancelled"]
        content = ""
        html1 = '''
        <html>
            <body>
                <h1 style="text-align: center;">SUSE Manager - Job Monitoring Status</h1>
                <p style='text-align: center';>Reported by Jobchecker.</p><br><br>'''
        
        html_data = "<br>"
        for method in methods:
            if "failed" == method:
                html_data += "<p style='color:red;'><strong><font size='+2'>{}:</font></strong></p>".format(method)
            elif "completed" == method:
                html_data += "<p style='color:green;'><strong><font size='+2'>{}:</font></strong></p>".format(method)
            else:
                html_data += "<p><strong><font size='+2'>{}:</font></strong></p>".format(method)
            if len(data[method]) > 0:
                for i in data[method]:
                    for a, b in i.items():
                        html_data += '<p><span style="margin-left: 20px;">{}: {}</span></p>'.format(a, b)
            html_data += "<br>"
        html2 = '''
        </body>
        </html>
        '''
        content = html1 + html_data + html2

        return str(content)

    def _get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # doesn't even have to be reachable
            s.connect(('10.254.254.254', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
    
    def _send_emails(self, data):
        if not data["jobchecker_emails"]:
            log.warning("No jobchecker_emails provided. No emails will be sent.")
            return True
        elif len(data["jobchecker_emails"]) == 0:
            log.warning("No jobchecker_emails provided. No emails will be sent.")
            return True
        else:
            pass
            
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        ip_address = self._get_ip()
        print(socket.gethostbyaddr(ip_address)[0])
        # Define your email addresses
        message = MIMEMultipart()
        sender_email = 'susemanager@{}'.format(socket.gethostbyaddr(ip_address)[0])
        receiver_email = data["jobchecker_emails"]
        # Convert the dictionary to a string
        content = self.format_html_content(data)

        # Create a MIME message with the content
        message.attach(MIMEText(content, 'html', 'utf-8'))
        #message = MIMEText(content)

        # Set the sender, receiver, and subject of the email
        message['From'] = sender_email
        message['To'] = ", ".join(receiver_email)
        message['Subject'] = 'Jobchecker result'

        # Create a SMTP server instance and send the email
        with smtplib.SMTP('localhost') as server:
            server.sendmail(sender_email, receiver_email, message.as_string())
        return True

    def monitor(self, data):
        # Do the monitoring tasks with the data
        # This method is executed in a separate thread

        #print("data patching {}".format(data["Patching"]))
        log.info(f"thread id : {threading.get_ident()}")
        log.info("Received")
        if data["jobstart_delay"]:
            log.info("\tJob starts in {} minutes from now".format(data["jobstart_delay"]))
        for i in list(data["Patching"]):
            if isinstance(i, dict):
                for a, b in i.items():
                    if isinstance(b, dict):
                        log.info("\t{}: {}".format(a, b["Patch Job ID is"]))
                    else:
                        data["Patching"].remove(i)
            else:
                data["Patching"].remove(i)
        
        jobstart_delay = 0
        while jobstart_delay < data["jobstart_delay"]:
            jobstart_delay += 1
            in_minutes_start = int(data["jobstart_delay"]) - int(jobstart_delay)
            print("in_minutes_start {}".format(in_minutes_start))
            if in_minutes_start == 0:
                print("jobs start in less than 60 seconds")
            else:
                print("jobs start in {} minutes".format(in_minutes_start))
            time.sleep(60)
        
        jobs = self.suma_jobcheck(data)
        
        return jobs
    
    def _decrypt_password(self, password_encrypted):
        if not os.environ.get('SUMAKEY'): 
            log.fatal("You don't have ENV SUMAKEY set. Use unencrypted pwd.")
            return str(password_encrypted)
        else:    
            saltkey = bytes(str(os.environ['SUMAKEY']), encoding='utf-8')
            fernet = Fernet(saltkey)
            encmessage = bytes(str(password_encrypted), encoding='utf-8')
            pwd = fernet.decrypt(encmessage)
        
        return pwd.decode()


    def suma_jobcheck(self, data):
        client, key = self._get_session()
        methods = ["pending",
                   "completed",
                   "failed",
                   "cancelled"]
        timer = 0
        
        while timer < data["jobchecker_timeout"]:
            
            job_status = self._getJobStatus(client, key, data)
            #print(job_status)
            
            for method in methods:
                if len(job_status[method]) > 0:
                    for info in job_status[method]:
                        if isinstance(info, dict):
                            for a, b in info.items():
                                log.info("{} - {}: Job ID {}".format(method, a, b)) 
                                print("{} - {}: Job ID {}".format(method, a, b)) 
            
            if len(job_status["pending"]) == 0:
                timer = int(data["jobchecker_timeout"]) - 1
                print("No more pending jobs. Stop task.")
                return job_status
            
            timer += 1
            remaining_timeout = int(data["jobchecker_timeout"]) - timer
            print("{} minutes to go until jobcheck timeout.".format(remaining_timeout))
            time.sleep(60)
            
        return job_status

    def _getJobStatus(self, client, key, data):
        methods = ["pending",
                   "completed",
                   "failed",
                   "cancelled"]
        jobs = dict()
        
        if data["jobchecker_emails"]:
            jobs["jobchecker_emails"] = []
            if len(data["jobchecker_emails"]) > 0:
                jobs["jobchecker_emails"] = data["jobchecker_emails"]

        for m in methods:
            jobs[m] = []
        try:
            pending_jobs = client.schedule.listInProgressActions(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get pending jobs: {0}'.format(exc)
            log.error(err_msg)
        
        try:
            complete_jobs = client.schedule.listCompletedActions(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get completed jobs: {0}'.format(exc)
            log.error(err_msg)
        
        try:
            failed_jobs = client.schedule.listFailedActions(key)
        except Exception as exc:  # pylint: disable=broad-except
            err_msg = 'Exception raised when trying to get failed jobs: {0}'.format(exc)
            log.error(err_msg)

        #print("after api calls")
        if pending_jobs:
            #print(pending_jobs)
            for job in pending_jobs:
                for j in list(data["Patching"]):
                    if isinstance(j, dict):
                        for a, b in j.items():
                            if b["Patch Job ID is"] == job["id"]:
                                print("pending: {} - Job ID {}: {}".format(a, job["id"], job["name"]))
                                temp = {}
                                temp[a] = job["id"]                                
                                jobs["pending"].append(temp)

        
        if complete_jobs:
            for job in complete_jobs:
                for j in list(data["Patching"]):
                    if isinstance(j, dict):
                        for a, b in j.items():
                            if b["Patch Job ID is"] == job["id"]:
                                print("completed: {} - Job ID {}: {}".format(a, job["id"], job["name"]))
                                temp = {}
                                temp[a] = job["id"]
                                jobs["completed"].append(temp)
        
        if failed_jobs:
            for job in failed_jobs:
                for j in list(data["Patching"]):
                    if isinstance(j, dict):
                        for a, b in j.items():
                            if b["Patch Job ID is"] == job["id"]:
                                print("failed: {} - Job ID {}: {}".format(a, job["id"], job["name"]))
                                temp = {}
                                temp[a] = job["id"]
                                jobs["failed"].append(temp)
        
        if len(jobs["pending"]) == 0 and len(jobs["completed"]) == 0 and len(jobs["failed"]) == 0:
            for j in list(data["Patching"]):
                    if isinstance(j, dict):
                        for a, b in j.items():
                            temp = {}
                            temp[a] = b["Patch Job ID is"]
                            jobs["cancelled"].append(temp)
        return jobs
    
    def _get_suma_configuration(self):
        with open("/etc/salt/master.d/spacewalk.conf", "r") as yaml_file:
            yaml_content = yaml_file.read()

        parsed_yaml = yaml.safe_load(yaml_content)
        suma_config = parsed_yaml['suma_api'] if 'suma_api' in parsed_yaml else None

        if suma_config:
            try:
                for suma_server, service_config in six.iteritems(suma_config):
                    username = service_config.get('username', None)
                    password_encrypted = service_config.get('password', None)
                    password = self._decrypt_password(password_encrypted)
                    protocol = service_config.get('protocol', 'https')

                    if not username or not password:
                        log.error(
                            'Username or Password has not been specified in the master '
                            'configuration for %s', suma_server
                        )
                        return False

                    ret = {
                        'api_url': '{0}://{1}/rpc/api'.format(protocol, suma_server),
                        'username': username,
                        'password': password,
                        'servername': suma_server
                    }

                    return ret

            except Exception as exc:  # pylint: disable=broad-except
                log.error('Exception encountered: %s', exc)
                return False
        return False
    
    def _get_client_and_key(self, url, user, password, verbose=0):
        '''
        Return the client object and session key for the client
        '''
        session = {}
        session['client'] = six.moves.xmlrpc_client.Server(url, verbose=verbose, use_datetime=True)
        session['key'] = session['client'].auth.login(user, password)

        return session


    def _disconnect_session(self, session):
        '''
        Disconnect API connection
        '''
        session['client'].auth.logout(session['key'])


    def _get_session(self):
        '''
        Get session and key
        '''
        
        config = self._get_suma_configuration()
        if not config:
            raise Exception('No config found on master')

        #print("config is: {}".format(config))
        session = self._get_client_and_key(config['api_url'], config['username'], config['password'])
        atexit.register(self._disconnect_session, session)

        client = session['client']
        key = session['key']
        self._sessions[config["servername"]] = (client, key)

        return client, key

if __name__ == '__main__':
    app = tornado.web.Application([
        (r'/jobchecker', MyRequestHandler),
    ], debug=True, autoreload=False)
    app.listen(12345, "127.0.0.1")
    tornado.ioloop.IOLoop.current().start()
    