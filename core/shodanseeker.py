import sys
import os
import optparse
import re
import shodan
import datetime
import click
import time
import requests
import smtplib
from os.path import basename
from config import api, paths, mail
from datetime import datetime, date, timedelta
from optparse import OptionParser
from shodan import Shodan
from shodan.exception import APIError
from shodan.cli.alert import alert_clear
from shodan.helpers import get_ip 
from ipcalc import IP, Network
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from email.mime.application import MIMEApplication
from email import encoders


class ShodanSeeker:

    def __init__(self, api_key=None, proxies=None):
        self.api_key = api_key
        self.proxies = proxies
        self.api = Shodan(self.api_key, self.proxies)
        self.force = False

    def log(self, action="", data=""):
        date = datetime.now()
        if action == "Error":
            msg = ('[Error] ') + date.strftime("%c") + ' - ' + str(data)
        elif action == "newline":
            msg = "\n"
        else:
            msg = ('[ Log ] ') + date.strftime("%c") + ' - ' + str(action) + str(data)
        filelogname = date.strftime("%m-%Y")
        for logpath in paths:
            self.logpath = paths['logpath']
        filelogpath = str(self.logpath) + filelogname + ".txt"
        if os.path.isfile(filelogpath):
            file = open(filelogpath, "a")
            file.write(msg + '\n')
	    file.close()
        else:
            file = open(filelogpath, "w")
            file.write(msg + '\n')
            file.close()
        if action != "newline":
            print msg  # Console output

    def add_scanid(self, id):
        for scanidpath in paths:
            self.scanidpath = paths['scanidpath'] + "scanID.txt"
        date = datetime.now()
        if os.path.isfile(self.scanidpath):
            file = open(self.scanidpath, "a")
            file.write(id + '\t' + date.strftime("%c") + '\n')
            file.close()
        else:
            file = open(self.scanidpath, "w")
            file.write('    Scan ID              Date      \n')
            file.write(id + '\t' + date.strftime("%c") + '\n')
            file.close()
     
    def print_scanlistID(self):
        for scanidpath in paths:
            self.scanidpath = paths['scanidpath'] + "scanID.txt"
        if os.path.isfile(self.scanidpath):
            try:
                with open(self.scanidpath, "r") as file_lines:
                    for line in file_lines:
                        print line
            except APIError as e:
                self.log("Error", e.value)
                sys.exit(1)
        else:
            print 'No scan has been sent yet'
            sys.exit(1)
    
    def scan_range(self, input, force):
        self.log("Scan IP/netblock - ", input)
        list = input.split(" ")
        dictips = dict.fromkeys(list, [])
        #self.log("List of IPs - ", list)
        try:
            self.log ("Force status - ", str(force))
            scan = self.api.scan(dictips, force)
            id = scan["id"]
            self.log("Scan ID: ", id)
            self.add_scanid(id)
            self.log("Check results on : https://www.shodan.io/search?query=scan%3A" + id)
            self.log("newline")
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def scan_file(self, file, force):
        self.log("Scan file - ", file)
        try:
             with open(file, "r") as file_lines:
                 list = []
                 for line in file_lines:
                     list.append(line.replace('\n', ''))
                 try:
                     dictips = dict.fromkeys(list, [])
                     self.log("List of IPs - ", list)
                     self.log ("Force status - ", str(force))
                     scan = self.api.scan(dictips, force)
                     time.sleep(0.5)
                     id = scan["id"]
                     self.log("Scan ID: ", id)
 	             self.add_scanid(id)
                     self.log("Check results on : https://www.shodan.io/search?query=scan%3A" + id)
                     self.log("newline")
                 except APIError as e:
                     self.log("Error", e.value)
                     self.log("newline")
                     sys.exit(1)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def get_info(self, input, history, diff, output, toaddr, attach):
        self.log("Get info from IP/netblock - ", input)
        #self.log("History banners - ", history)
        #self.log("Diff - ", diff)
        #self.log("Format - ", output)
        if (toaddr) is not None:
            try: 
                self.log("Mail - ", mail[toaddr])
            except KeyError as e:
                e = "Address is not found in config.py: " + toaddr
                self.log("Error", e)
                self.log("newline")
                sys.exit(1)
        #else:
            #self.log("Mail - ", toaddr)
        res = ""
        res1 = ""
        list = input.split(" ")
        #self.log("List Split - ", list)
        date = datetime.now()
        filereportname = date.strftime("%Y-%m-%d-%H%M%S")
        for reportpath in paths:
            self.reportpath = paths['reportpath']
        if (history) is not None:
            if (diff) is not None:
                filereportpath = str(self.reportpath) + str('diffing/') + filereportname + ".csv"
            else:
                filereportpath = str(self.reportpath) + str('history/') + filereportname + ".csv"
        else:
            filereportpath = str(self.reportpath) + filereportname + ".csv"
        for item in list:
            if "/" not in item:
                try:
                    host = self.api.host(item, history)
                    resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                    res = str(res) + '\n' + str(resaux) #body mail            
                except APIError as e:
                    self.log("Error", e.value)
                    self.log("newline")
                    pass
            else:
                for x in Network(item):
                    try:
                        host = self.api.host(str(x), history)
                        time.sleep(0.5)
                        resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                        res = str(res) + '\n' + str(resaux) #body mail
                    except APIError as e:
                        self.log("Error", e.value)
                        self.log("newline")
                        time.sleep(0.5)
                        pass 
        if (output) is not None:
            self.log("Report: ", filereportpath)
            self.log("newline")
            res1 = "Results on " + filereportpath
        if (toaddr) is not None:
            body = res1 + "\n" + res
            subject = "[Searching results]"
            if (diff):
                subject = subject + " New services published"
            else:
                if (history):
                    subject = subject + " All historical banners"
                else:
                    subject = subject + " All services"
            self.send_mail(subject, body, toaddr, attach, filereportpath) 

    def get_infofromfile(self, file, history, diff, output, toaddr, attach):
        self.log("Get info from file - ", file)
        #self.log("History banners - ", history)
        #self.log("Diff - ", diff)
        #self.log("Format - ", output)
        if (toaddr) is not None:
            try:
                self.log("Mail - ", mail[toaddr])
            except KeyError as e:
                e = "Address is not found in config.py: " + toaddr
                self.log("Error", e)
                self.log("newline")
                sys.exit(1)
        #else:
            #self.log("Mail - ", toaddr)
        res = "" #body mail
        res1 = ""
        try:
            with open(file, "r") as file_lines:
                list = []
                for line in file_lines:
                    list.append(line.replace('\n', ''))
                self.log("List of IPs/netblock - ", list)
                date = datetime.now()
                filereportname = date.strftime("%Y-%m-%d-%H%M%S")
                for reportpath in paths:
                    self.reportpath = paths['reportpath']
                if (history) is not None:
                    if (diff) is not None:
                        filereportpath = str(self.reportpath) + str('diffing/') + filereportname + ".csv"
                    else:
                        filereportpath = str(self.reportpath) + str('history/') + filereportname + ".csv"
                else:
                    filereportpath = str(self.reportpath) + filereportname + ".csv"
                for item in list:
                    if "/" not in item:
                        try:
                            host = self.api.host(item, history)
                            time.sleep(0.5)
                            resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                            res = str(res) + '\n' + str(resaux) #body mail
                        except APIError as e:
                             self.log("Error", e.value)
                             self.log("newline")
                             pass
                    else:
                        for x in Network(item):
                            try:
                                host = self.api.host(str(x), history)
                                time.sleep(0.5)
                                resaux = self.host_print(host, history, output, filereportpath, diff, toaddr)
                                res = str(res) + '\n' + str(resaux) # body mail
                            except APIError as e:
                                self.log("Error", e.value)
                                self.log("newline")
                                time.sleep(0.5)
                                pass
                if (output) is not None:
                    self.log("Report: ", filereportpath)
                    self.log("newline")
                    res1 = "Results on " + filereportpath
                if (toaddr) is not None:
                    body = res1 + "\n" + res
                    subject = "[Searching results]"
                    if (diff):
                        subject = subject + " New services published"
                    else:
                        if (history):
                            subject = subject + " All historical banners"
                        else:
                            subject = subject + " All services"
                    self.send_mail(subject, body, toaddr, attach, filereportpath)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def host_print(self, host, history, output, filereportpath, diff, toaddr):
        self.res = ""
        if (output == None):
            self.host_gethistdiff(host, history, None, filereportpath, diff, toaddr, None)
        else:
            if (output == 'csv'):
                self.res = self.host_gethistdiff(host, history, output, filereportpath, diff, toaddr, None)
            else:
                print '[Error] Output format not supported'
                sys.exit(1)
        return self.res

    def host_printoutput(self, port, transport, product, version, date, toaddr, subs):
        res = 'Port: ' + str(port) + ' ' + str(transport)
        if (product or version):
            res = res + ' ' + str(product) + ' ' +  str(version)
        if date:
            resaux = ' Timestamp: ' + str(date)
            res = res + resaux
        if (toaddr is None) and (subs is None):
            print str(res)
        else:
            res = res + '\n'
        return res

    def host_gethistdiff(self, host, history, output, filereportpath, diff, toaddr, subs):
        self.file = None
        self.hostname = None
        self.os = None
        self.lastupdate = None
        self.ports = []
        self.product = None
        self.version = None
        self.transport = None
        self.timestamp = None
        self.res = ""

        if (output != None):
            if os.path.isfile(filereportpath):
                self.file = open(filereportpath, "a")
            else:
                self.file = open(filereportpath, "w")    
                data = 'Hostname,OS,LastUpdate,Port,Transport,Product,Version,Timestamp'
                self.file.write(data + '\n')
      
        self.hostname = get_ip(host)
        if 'os' in host and host['os']:
            self.os = host['os']
        if 'last_update' in host and host['last_update']:
            self.lastupdate = host['last_update'][:10]

        if (output == None) and (subs == None):
            resaux = '\n' + 'Hostname: ' + str(self.hostname)
            if (toaddr) is None:
                print str(resaux)
            else:
                self.res = self.res + str(resaux) + '\n'
            if self.os:
                resaux = 'OS: ' + str(self.os)
                if (toaddr) is None:
                    print str(resaux)
                else:
                    self.res = self.res + str(resaux) + '\n'
            resaux = 'LastUpdate: ' + str(self.lastupdate) + '\n'
            if (toaddr) is None:
                print str(resaux)
            else:
                self.res = self.res + str(resaux)

        if len(host['ports']) != len(host['data']):
            ports = host['ports']
            for banner in host['data']:
                if banner['port'] in ports:
                    ports.remove(banner['port'])

            for port in ports:
                banner = {
                    'port': port,
                    'transport': 'tcp',
                    'timestamp': host['data'][-1]['timestamp'] 
                }
                host['data'].append(banner)

        if (diff == None): # Regular and History option
      
            for banner in sorted(host['data'], key=lambda k: k['port']):
                self.product = None
                self.version = None
                self.transport = None
                self.timestamp = None

                if 'product' in banner and banner['product']:
                    self.product = banner['product']

                if 'version' in banner and banner['version']:  
                   self.version = '({})'.format(banner['version'])

                if 'transport' in banner:
                   self.transport = banner['transport']

                if history:
                    # Format the timestamp to only show the year-month-day
                    self.timestamp = banner['timestamp'][:10]

                if (output == None):
                    resaux = self.host_printoutput(banner['port'], self.transport, self.product, self.version, self.timestamp, toaddr, subs)
                    self.res = self.res + resaux
                else:
                    data = str(self.hostname) + ',' + str(self.os) + ',' + str(self.lastupdate)
                    data = data + ',' + str(banner['port']) + ',' + str(self.transport) 
                    data = data + ',' + str(self.product) + ',' + str(self.version) + ',' + str(self.timestamp)
                    self.file.write(data + '\n')
                
        if (diff): # Diffing option 

            self.ports_uniq = host['ports']
             
            if len(self.ports_uniq) < 1:
                for banner in host['data']:
                    if banner['port'] not in self.ports_uniq:
                        self.ports_uniq.append(banner['port'])
 
            # list_timestamps_uniq_sort_host           
            self.listtimestamp = [] 
            for banner in host['data']:
                timestamp = banner['timestamp'][:10]
                if timestamp and timestamp not in self.listtimestamp:
                   self.listtimestamp.append(timestamp)
            
            # list_timestamp_host_port
            for port in self.ports_uniq:
                self.listbannerport = []
                self.listporttimestamps = []
                for banner in sorted(host['data'], key=lambda k: k['port']):
                    if port == banner['port']:
                        timestampport = banner['timestamp'][:10]
                        if timestampport and timestampport not in self.listporttimestamps:
                            self.listporttimestamps.append(timestampport)
                            self.listbannerport.append(banner)

                for bannerport in self.listbannerport:
                    self.timestamp = bannerport['timestamp'][:10]
                    self.port = bannerport['port']
                    if 'product' in bannerport and bannerport['product']:
                        self.product = bannerport['product']
                    if 'version' in bannerport and bannerport['version']:
                        self.version = '({})'.format(bannerport['version'])
                    if 'transport' in bannerport:
                        self.transport = (bannerport['transport'])
                    next_timestamp_port = None
                    next_timestamp_host = None

                    if (self.lastupdate == self.timestamp):
                        date = datetime.now()
                        timestamp = datetime.strptime(self.lastupdate, '%Y-%m-%d')                    
                        timestamp_ajust = timestamp + timedelta(days=32)
                        if (date <= timestamp_ajust):
                            if (len(self.listbannerport) == 1):
                                if (output == None): 
                                    resaux = self.host_printoutput(self.port, self.transport, self.product, self.version, self.timestamp, toaddr, subs)
                                    self.res = self.res + resaux
                                else:
                                    data = str(self.hostname) + ',' + str(self.os) + ',' + str(self.lastupdate)
                                    data = data + ',' + str(self.port) + ',' + str(self.transport)
                                    data = data + ',' + str(self.product) + ',' + str(self.version) + ',' + str(self.timestamp)
                                    self.file.write(data + '\n')
                            else:
                                next_timestamp_port = self.listbannerport[1]['timestamp'][:10]
                                next_timestamp_host = self.listtimestamp[1]
                                if (next_timestamp_port != next_timestamp_host):
                                    if (output == None):
                                        resaux = self.host_printoutput(self.port, self.transport, self.product, self.version, self.timestamp, toaddr, subs)
                                        self.res = self.res + resaux
                                    else:
                                        data = str(self.hostname) + ',' + str(self.os) + ',' + str(self.lastupdate)
                                        data = data + ',' + str(self.port) + ',' + str(self.transport)
                                        data = data + ',' + str(self.product) + ',' + str(self.version) + ',' + str(self.timestamp)
                                        self.file.write(data + '\n')
        if (output != None):
            self.file.close()
        return self.res

    def send_mail(self, subject, body, toaddr, attached, filepath):
        self.fromaddress = mail['fromaddress']
        self.frompassword = mail['frompassword']
        self.toaddress = mail[toaddr]
        self.smtp = mail['smtp']
        msg = msg = MIMEMultipart()
        msg['From'] = str(self.fromaddress)
        msg['To'] = str(self.toaddress)
        msg['Subject'] = str(subject)
        body = str(body)
        msg.attach(MIMEText(body, 'plain'))
        if (attached):
            part = MIMEApplication(open(filepath, 'rb').read())
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(filepath)
            msg.attach(part)
        server = smtplib.SMTP(self.smtp, 587)
        try:
            server.starttls()
            server.login(self.fromaddress, self.frompassword)
            text = msg.as_string()
            server.sendmail(self.fromaddress, self.toaddress, text)
            server.quit()
            self.log("Mail sent: ", subject)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def create_alert(self, name, ips):
        self.log("Create alert")
        self.log("IPs/netblock - ", ips)
        list = ips.split(" ")
        self.log("List of IPs - ", list)
        try:
            i=0
            for ip in list:
                namenew = name + '_' + str(i)
                alert = self.api.create_alert(name, ip)
                time.sleep(0.5)
                id = alert["id"]
                self.log("Alert Name: ", namenew)
                self.log("Alert ID: ", id)
                self.log("newline")
                i=i+1
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def create_alertfile(self, name, file):
        self.log("Create alert")
        self.log("File of ips ", file)
        try:
             with open(file, "r") as file_lines:
                 list = []
                 i=0
                 for line in file_lines:
                     list.append(line.replace('\n', ''))
                 try:
                     self.log("List of IPs - ", list)
                     for ip in list:
                         namenew = name + '_' + str(i)
                         alert = self.api.create_alert(namenew, ip)
                         time.sleep(0.5)
                         id = alert["id"]
                         self.log("Alert Name: ", namenew)
                         self.log("Alert ID: ", id)
                         self.log("newline")
                         i=i+1
                 except APIError as e:
                     self.log("Error", e.value)
                     self.log("newline")
                     sys.exit(1)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def list_alerts(self):
        try:
            results = self.api.alerts()
        except APIError as e:
            print '[Error]' +  e.value
            sys.exit(1)
         
        if len(results) > 0:
            click.echo(click.style('{0:<30}'.format('AlertID')) + click.style('{0:<30}'.format('Name') + 'IP/Netblock') + '\n')
            for alert in results:
                click.echo(click.style('{0:<30}'.format(alert['id'])) + click.style('{0:<30}'.format(alert['name']) + str(alert['filters']['ip'][0])))
        else:
            print 'You have not created any alerts yet'

    def delete_alert(self, alertid):
        if str(alertid) == "all":
            self.remove_allalerts()
        else: 
            try:
                self.api.delete_alert(alertid)
                self.log("Alert ID removed: ", alertid)
                self.log("newline")
            except APIError as e:
                self.log("Error", e.value)
                self.log("newline")
                sys.exit(1)

    def remove_allalerts(self):
        try:
            alerts = self.api.alerts()
            time.sleep(0.5)
            for alert in alerts:
                self.log("Removing alert: " + alert['name'] + " - " +  alert['id'])
                self.api.delete_alert(alert['id'])
                time.sleep(0.5)
            self.log("All alerts have been removed")
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)

    def subscribe_ports(self, alertid, monport, toaddr):
        self.alertid = alertid
        self.monport = monport
        self.toaddr = toaddr
        try:
            monitemlist = monport.split(" ")
            self.api.stream.base_url = "https://stream.shodan.io"
            if str(alertid) == "all":
                self.alertid = None
            else:
                self.alertid = alertid
            for banner in self.api.stream.alert(self.alertid):
                for m in monitemlist:
                    if str((banner['port'])) == str(m):
                        ip = str(get_ip(banner))
                        port = str((banner['port']))
                        data = 'Hostname: ' + ip + ' Port: ' + port
                        self.log('Alert: ', data)
                        if (toaddr) is not None:
                            self.send_mail('[Alert] Risk port open', data, toaddr, None, None)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)
        except requests.exceptions.ChunkedEncodingError:
            self.subscribe_ports(self.alertid, self.monport, self.toaddr)

    def subscribe_diff(self, alertid, toaddr):
        self.alertid = alertid
        self.toaddr = toaddr
        try:
            self.api.stream.base_url = "https://stream.shodan.io"
            if str(alertid) == "all":
                self.alertid = None
            else:
                self.alertid = alertid
            for banner in self.api.stream.alert(self.alertid):
                ip_stream = str(get_ip(banner))
                port_stream = str((banner['port']))
                #print "IP " + str(ip_stream)
                #print "port_stream " + str(port_stream)
                banner = self.api.host(ip_stream, True)
                time.sleep(0.5)    
                res = self.host_gethistdiff(banner, True, None, None, True, None, True)
                res = res.split(' ')
                #print "RES " + str(res)
                if port_stream in res:
                    data = 'Hostname: ' + ip_stream + ' Port: ' + port_stream
                    self.log('Alert : ', data)
                    if (toaddr) is not None:
                        self.send_mail('[Alert] New service detected', data, toaddr, None, None)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)
        except requests.exceptions.ChunkedEncodingError:
            self.subscribe_diff(self.alertid, self.toaddr)

    def subscribe_tags(self, alertid, montags, toaddr):
        self.alertid = alertid
        self.montags = montags
        self.toaddr = toaddr
        try:
            monitemlist = montags.split(" ")
            self.api.stream.base_url = "https://stream.shodan.io"
            if str(alertid) == "all":
                self.alertid = None
            else:
                self.alertid = alertid
            for banner in self.api.stream.alert(self.alertid):
                for m in monitemlist:
                    if 'tags' in banner and str(m) in banner['tags']:
                        ip = str(get_ip(banner))
                        data = 'Hostname: ' + ip + ' Tag: ' + str(m)
                        self.log('Alert: ', data)
                        if (toaddr) is not None:
                            self.send_mail('[Alert] Tag detected', data, toaddr, None, None)
        except APIError as e:
            self.log("Error", e.value)
            self.log("newline")
            sys.exit(1)
        except requests.exceptions.ChunkedEncodingError:
            self.subscribe_tags(self.alertid, self.montags, self.toaddr)

    def get_services(self, input):
        if str(input) == "services":
            res = self.api.services()
            for name, description in iter(res.items()):
                click.echo(click.style('{0:<30}'.format(name)) + description)
        elif str(input) == "protocols":
            res = self.api.protocols()
            for name, description in iter(res.items()):
                click.echo(click.style('{0:<30}'.format(name)) + description)
        elif str(input) == "ports":
            res = self.api.protocols()
            for name, description in iter(res.items()):
                click.echo(click.style('{0:<30}'.format(name)) + description)
        elif str(input) == "tags":
            for mainpath in paths:
                mainpath = paths['mainpath'] + "tags"
            if os.path.isfile(mainpath):
                try:
                    with open(mainpath, "r") as file_lines:
                        for line in file_lines:
                            print line.rstrip('\n')
                except APIError as e:
                   self.log("Error", e.value)
                   sys.exit(1)
            else:
                print 'No scan has been sent yet'
                sys.exit(1) 
        else:
            print "[Error] - Input must be: protocols, services or ports"
            sys.exit(1)

    def run(self):
        usage = "usage: python %prog [options]"
 
        epi = """
EXAMPLES:
  ./shodanseeker --si 'X.X.X.X X.X.X.X/24'                                   # Scan IPs/netblocks
  ./shodanseeker --sf 'pathfilename'                                         # Scan IPs/netblocks from a file
  ./shodanseeker -l                                                          # List previously submitted scans
  ./shodanseeker -i 'X.X.X.X X.X.X.X/24 Y.Y.Y.Y'                             # Get all information of IP/netblocks
  ./shodanseeker -f 'pathfilename'                                           # Get all information from a file of IPs/netblocks
  ./shodanseeker -i 'X.X.X.X' --history                                      # Get all historical banners
  ./shodanseeker -i 'X.X.X.X' --diff                                         # Detect new services published 
  ./shodanseeker -f 'pathfilename' [--history|--diff] --output csv           # Output results in csv format
  ./shodanseeker -i 'X.X.X.X' --diff --output csv --mail toaddr -a           # Send email with csv results attached
  ./shodanseeker --ca Name 'X.X.X.X X.X.X.X/24'                              # Create network alerts for the IP/netblock 
  ./shodanseeker --cf Name 'pathfilename'                                    # Create network alerts from file
  ./shodanseeker --la                                                        # List of all the network alerts activated on the account
  ./shodanseeker --da [alertid|all]                                          # Remove the specified network alert
  ./shodanseeker --subs [alertid|all] --monport '3389 22' [--mail toaddr]    # Subscribe to the Streaming and monitoring for high risk services
  ./shodanseeker --subs [alertid|all] --mondiff [--mail toaddr]              # Subscribe to the Streaming and monitoring for new services published
  ./shodanseeker --subs [alertid|all] --montag 'compromised' [--mail toaddr] # Subscribe to the Streaming and monitoring for tags (ex: compromised, doublepulsar, self-signed)
  ./shodanseeker --get [protocols|services|ports|tags]                       # List of (protocols,services,ports,tags) supported
"""
        class myParser(OptionParser):
            def format_epilog(self, formatter):
                return self.epilog

        parser = myParser(epilog=epi) 
        #parser = optparse.OptionParser()
        parser.set_usage(usage)
        
        parser.add_option("--mail", dest="mail", help="Send email with results and alerts", default=None)
        parser.add_option("-a", dest="attach", action="store_true", help="Attach csv results to an email", default=None)         

        group1 = optparse.OptionGroup(parser, "Scanning Options")
        group1.add_option("--si", dest="scaninput", help="Scan an IP/netblock", default=None)
        group1.add_option("--sf", dest="scanfile", help="Scan an IP/netblock from file", default=None)
        group1.add_option("--force", dest="scanforce", help="Force Shodan to re-scan the provided IPs", action="store_true", default=None)
        group1.add_option("-l", dest="scanlist", action="store_true", help="List previously submitted scans", default=None)
        parser.add_option_group(group1)

        group2 = optparse.OptionGroup(parser, "Searching Options")
        group2.add_option("-i", dest="getinfo", help="Get all information of an IP/netblock", default=None)
        group2.add_option("-f", dest="getinfofromfile", help="Get all information of an IP/netblock from file", default=None)
        group2.add_option("--history", dest="history", help="Return all Historical Banners", action="store_true", default=None)
        group2.add_option("--diff", dest="diff", help="Detect New Services Published", action="store_true", default=None)
        group2.add_option("--output", dest="output", help="Output results in csv format", default=None)  
        parser.add_option_group(group2)

        group3 = optparse.OptionGroup(parser, "Monitoring in Real-Time")
        group3.add_option("--ca", dest="addalert", help="Create network alerts for the IP/netblock", nargs=2, default=None)
        group3.add_option("--cf", dest="addalertfile", help="Create network alerts from file", nargs=2, default=None)
        group3.add_option("--la", dest="listalerts", help="List of all the network alerts activated", action="store_true", default=None)
        group3.add_option("--da", dest="delalert", help="Remove the specified network alert", default=None)
        group3.add_option("--subs", dest="subsalerts", help="Subscribe to the Private Horse Streaming", default=None) 
        group3.add_option("--monport", dest="monport", help="Monitoring for High Risk Services", default=None)
        group3.add_option("--mondiff", dest="mondiff", action="store_true", help="Monitoring for New Services Published", default=None)
        group3.add_option("--montag", dest="montag", help="Tags (ex: compromised, doublepulsar, self-signed)", default=None)
        group3.add_option("--get", dest="get", help="Protocols, services, ports and tags supported", default=None)
        parser.add_option_group(group3)

        (options,args) = parser.parse_args()

        for key in api:
            self.api_key = key['key']
        for logpath in paths:
            self.logpath = paths['logpath']

        if self.api_key == '':
	    print '[Error] Set the API Key into the configuration file'
            sys.exit(1)
         
        if options.scaninput != None:
            if (options.scaninput):
                if (options.scanforce):
                    self.force = True
                shodanscan = ShodanSeeker(self.api_key)
                shodanscan.scan_range(options.scaninput, self.force)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif options.scanfile != None:
            if (options.scanfile):
                if os.path.isfile(options.scanfile):
                    if (options.scanforce):
                        self.force = True
                    shodanscan = ShodanSeeker(self.api_key)
                    shodanscan.scan_file(options.scanfile, self.force)
                else:
                    print '[Error] File does not exist'
                    sys.exit(1)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)
        
        elif options.scanlist != None:
            self.print_scanlistID()

        elif options.getinfo != None:
            if (options.getinfo):
                shodangetinfo = ShodanSeeker(self.api_key)
                if options.history and options.diff:
                    parser.error("Options --history and --diff are mutually exclusive")
                if (options.history):
                    if (options.output):
                        if (options.output == 'csv'):
                            if (options.mail):
                                if (options.mail) in mail:
 				    if (options.attach):
				        shodangetinfo.get_info(options.getinfo, options.history, None, options.output, options.mail, options.attach)
     				    else:
                                        shodangetinfo.get_info(options.getinfo, options.history, None, options.output, options.mail, None)
                                else:
                                    print '[Error] Select a valid toaddress list from config file'
                            else:
                                shodangetinfo.get_info(options.getinfo, options.history, None, options.output, None, None)
                        else:
                            print '[Error] Output format not supported' 
                    else:
                        if (options.mail):
			    if (options.attach):
                                print '[Error] Select a file format output'
			    else:
                                shodangetinfo.get_info(options.getinfo, options.history, None, None, options.mail, None)
                        else:
                            shodangetinfo.get_info(options.getinfo, options.history, None, None, None, None) 
                else:
                    if (options.diff):
                        if (options.output):
                            if (options.output == 'csv'):
                                if (options.mail):
                                    if (options.mail) in mail:
 				        if (options.attach):
                                            shodangetinfo.get_info(options.getinfo, True, options.diff, options.output, options.mail, options.attach)
			                else:
                                            shodangetinfo.get_info(options.getinfo, True, options.diff, options.output, options.mail, None)
                                    else:
                                        print '[Error] Select a valid toaddress list from config file'
                                else:
                                    shodangetinfo.get_info(options.getinfo, True, options.diff, options.output, None, None)
			    else:
		                print '[Error] Output format not supported'		
                        else:
                            if (options.mail):
                                if (options.mail) in mail:
	 			    if (options.attach):
				        print '[Error] Select a file format output'
                                    else:
					shodangetinfo.get_info(options.getinfo, True, options.diff, None, options.mail, None)
                                else:
                                    print '[Error] Select a valid toaddress list from config file'
                            else:
                                shodangetinfo.get_info(options.getinfo, True, options.diff, None, None, None)
                    else:
                        if (options.output):
                            if (options.output == 'csv'):
                                if (options.mail):
                                    if (options.mail) in mail:
				        if (options.attach):
					    shodangetinfo.get_info(options.getinfo, None, None, options.output, options.mail, options.attach)
			                else:
				            shodangetinfo.get_info(options.getinfo, None, None, options.output, options.mail, None)
                                    else:
                                        print '[Error] Select a valid toaddress list from config file'
                                else:
                                    shodangetinfo.get_info(options.getinfo, None, None, options.output, None, None)
			    else:
                                print '[Error] Output format not supported'
                        else:
                            if (options.mail):
				if (options.attach):
				    print '[Error] Select a file format output'
				else:
			            shodangetinfo.get_info(options.getinfo, None, None, None, options.mail, None)
                            else:
                                shodangetinfo.get_info(options.getinfo, None, None, None, None, None)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif options.getinfofromfile != None:
            if (options.getinfofromfile):
                if os.path.isfile(options.getinfofromfile):
                    shodangetinfofromfile = ShodanSeeker(self.api_key)
                    if options.history and options.diff:
                        parser.error("Options --history and --diff are mutually exclusive")
                    if (options.history):
                        if (options.output):
                            if (options.output == 'csv'):
                                if (options.mail):
                                    if (options.mail) in mail:
 				        if (options.attach):
                                            shodangetinfofromfile.get_infofromfile(options.getinfofromfile, options.history, None, options.output, options.mail, options.attach)
			                else:
					    shodangetinfofromfile.get_infofromfile(options.getinfofromfile, options.history, None, options.output, options.mail, None)
                                    else:
                                        print '[Error] Select a valid toaddress list from config file'
                                else:
                                    shodangetinfofromfile.get_infofromfile(options.getinfofromfile, options.history, None, options.output, None, None)
                            else:
                                print '[Error] Output format not supported'
                        else:
                            if (options.mail):
 				if (options.attach):
                                    print '[Error] Select a file format output'
				else:
				    shodangetinfofromfile.get_infofromfile(options.getinfofromfile, options.history, None, None, options.mail, None)	
                            else:
                                shodangetinfofromfile.get_infofromfile(options.getinfofromfile, options.history, None, None, None, None)
                    else:
                        if (options.diff):
                            if (options.output):
                                if (options.output == 'csv'):
                                    if (options.mail):
                                        if (options.mail) in mail:
					    if (options.attach):
                                                shodangetinfofromfile.get_infofromfile(options.getinfofromfile, True, options.diff, options.output, options.mail, options.attach)
					    else:
			                        shodangetinfofromfile.get_infofromfile(options.getinfofromfile, True, options.diff, options.output, options.mail, None)
                                        else:
                                            print '[Error] Select a valid toaddress list from config file'
                                    else:
                                        shodangetinfofromfile.get_infofromfile(options.getinfofromfile, True, options.diff, options.output, None, None)
                                else:
                                    print '[Error] Output format not supported'
                            else:
                                if (options.mail):
                                    if (options.mail) in mail:
					if (options.attach):
					    print '[Error] Select a file format output'
					else:
				            shodangetinfofromfile.get_infofromfile(options.getinfofromfile, True, options.diff, None, options.mail, None)
			            else:
                                        print '[Error] Select a valid toaddress list from config file'
                                else:
                                    shodangetinfofromfile.get_infofromfile(options.getinfofromfile, True, options.diff, None, None, None)
                        else:
                            if (options.output):
                                if (options.output == 'csv'):
                                    if (options.mail):
                                        if (options.mail) in mail:
					    if (options.attach):
                                                shodangetinfofromfile.get_infofromfile(options.getinfofromfile, None, None, options.output, options.mail, options.attach)
				            else:
                                                shodangetinfofromfile.get_infofromfile(options.getinfofromfile, None, None, options.output, options.mail, None)
                                        else:
                                            print '[Error] Select a valid toaddress list from config file'
                                    else:
                                        shodangetinfofromfile.get_infofromfile(options.getinfofromfile, None, None, options.output, None, None)
                                else:
                                    print '[Error] Output format not supported'    
                            else:
                                if (options.mail):
                                    if (options.mail) in mail:
					if (options.attach):
					    print '[Error] Select a file format output'
				        else:
				            shodangetinfofromfile.get_infofromfile(options.getinfofromfile, None, None, None, options.mail, None)
				    else:
                                        print '[Error] Select a valid toaddress list from config file'
                                else:
                                    shodangetinfofromfile.get_infofromfile(options.getinfofromfile, None, None, None, None, None)
                else:
                    print '[Error] File does not exist'
                    sys.exit(1)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif options.addalert != None:
            if (options.addalert):
                name = options.addalert[0]
                ips = options.addalert[1]
                shodanaddalert = ShodanSeeker(self.api_key)
                shodanaddalert.create_alert(name, ips)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif options.addalertfile != None:
            if (options.addalertfile):
                name = options.addalertfile[0]
                file = options.addalertfile[1]
                if os.path.isfile(file):
                    shodanaddalertfile = ShodanSeeker(self.api_key)
                    shodanaddalertfile.create_alertfile(name, file)
                else:
                    print '[Error] File does not exist'
                    sys.exit(1)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif (options.listalerts):
            shodanlistalerts = ShodanSeeker(self.api_key)
            shodanlistalerts.list_alerts()

        elif options.delalert != None:
            if (options.delalert):
                shodanadddelalert = ShodanSeeker(self.api_key)
                shodanadddelalert.delete_alert(options.delalert)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif options.subsalerts != None:
            if (options.subsalerts):
                if (options.monport):
                    shodansubs = ShodanSeeker(self.api_key)
                    if (options.mail):
                        if (options.mail) in mail:
                            shodansubs.subscribe_ports(options.subsalerts, options.monport, options.mail)            
                        else:
                            print '[Error] Select a valid toaddress list from config file'
                    else:
                        shodansubs.subscribe_ports(options.subsalerts, options.monport, None)
                elif (options.mondiff):
                    shodansubs = ShodanSeeker(self.api_key)
                    if (options.mail):
                        if (options.mail) in mail:
                            shodansubs.subscribe_diff(options.subsalerts, options.mail)
                        else:
                            print '[Error] Select a valid toaddress list from config file'
                    else:
                        shodansubs.subscribe_diff(options.subsalerts, None)
                elif (options.montag):
                    shodansubs = ShodanSeeker(self.api_key)
                    if (options.mail):
                        if (options.mail) in mail:
                            shodansubs.subscribe_tags(options.subsalerts, options.montag, options.mail)
                        else:
                            print '[Error] Select a valid toaddress list from config file'
                    else:
                        shodansubs.subscribe_tags(options.subsalerts, options.montag, None)
                else:
                    print '[Error] --mon option must not be null'
                    sys.exit(1)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)

        elif options.get != None:
            if (options.get):
                shodanget = ShodanSeeker(self.api_key)
                shodanget.get_services(options.get)
            else:
                print '[Error] Input must not be null'
                sys.exit(1)
 
        else:
            parser.print_help()
            print ""
            sys.exit(1)

