########################################################################################################################
#AUTHOR: Steve Markey | smarkey@ncontrolsec.com
#VERSION: v1.0
#PURPOSE: Python-based Baseline Security Analyzer (BSA) for Windows 10
#RIGHTS: MIT
#ENVIRO: Win10, PySimpleGUI via PyCharm
#TO-DOS: tmp path to nmap.exe
########################################################################################################################
import nmap, errno, winreg, re, gc, datetime, os, requests, subprocess, win32net, win32netcon, io
import PySimpleGUI as sg
import logging.handlers
from fpdf import FPDF

hostPorts = []
swInstalls = []
hostInfo = []
myHotfix = []
avVendors = ['Symantec', 'McAfee', 'Defender', 'Sophos', 'Kaspersky', 'AVG', 'Spybot', 'Trend Micro', 'ESET', 'Fortinet', 'FireEye', 'Malwarebytes', 'Avast', 'Cylance', 'Crowdstrike', 'Carbon Black']
now = datetime.datetime.now()
psFlag = False
uFlag = False
avFlag = False
jFlag = False
pcap = False
wUpdate = False
gUsername = ""
gPW = ""
my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.ERROR)

def listusers(server=None):
    level=0
    filter=win32netcon.FILTER_NORMAL_ACCOUNT
    resume_handle=0
    my_user_list = []

    while True:
        result = win32net.NetUserEnum(server,level,filter,resume_handle)
        my_user_list +=[user['name'] for user in result[0]]
        resume_handle=result[2]
        if not resume_handle:
            break
    my_user_list.sort()
    return my_user_list

#Grab localhost SysInfo
try:
    lclOutput = subprocess.getoutput("SystemInfo.exe")
    s = io.StringIO(lclOutput)
    for line in s:
        if 'Host Name:' in line:
            hostInfo.append(str(line.rstrip()))
        elif 'OS Name' in line:
            hostInfo.append(str(line.rstrip()))
        elif 'OS Version' in line:
            if 'BIOS' not in line:
                hostInfo.append(str(line.strip()))
        elif 'KB4516068' in line:
            wUpdate = True
    nm = nmap.PortScanner()
    nm.scan(hosts="localhost", arguments='-T4 -v')
    for host in nm.all_hosts():
        hostInfo.append('Internal IP:                  ' + str(host))
        tip = str(host).split(".")
        nip = tip[0] + "." + tip[1] + "." + tip[2] + ".1/8"
    gc.collect()
except:
    my_logger.log(50, "localhost sysinfo error")
    gc.collect()
    exit()

#GUI
try:
    #is_connected()
    layout = [
        [sg.Text('Suggested IP Range to Scan: ' + nip)],
        [sg.Text('Enter IP Range:', size=(15, 1)), sg.InputText('localhost')],
        [sg.Text('Username:', size=(15, 1)), sg.InputText()],
        [sg.Text('Password:', size=(15, 1)), sg.InputText(password_char='*')],
        [sg.OK(), sg.Cancel()]
    ]
    window = sg.Window('PyBSAw', layout)
    while True:
        event, values = window.Read()
        if event in (None, 'Cancel'):
            exit()
        elif event in (None, 'OK'):
            mystr = values[0]
            gUsername = str(values[1])
            gPW = str(values[2])
            if(mystr.lower() == 'localhost'):
                ipRange = values[0]
            elif(re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$",mystr)):
                ipRange = values[0]
            else:
                sg.popup("ERROR", "Wrong Address")

            if(len(gUsername) > 0) and (len(gPW) > 0):
                uFlag = True
            else:
                break
        break
    window.Close()
    gc.collect()
except:
    my_logger.log(50, "GUI error")
    gc.collect()
    exit()

#LAN Scan
try:
    nm = nmap.PortScanner()
    nm.scan(hosts=ipRange, arguments='-T4 -v')
    for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                            hostPorts.append(str(host) +'|'+ str(port))
                            print(str(host) +'|'+ str(port))

                            #Flagging on 445 for Windows
                            if(str(port) == "445"):
                                    #Registry query
                                    proc_arch = os.environ['PROCESSOR_ARCHITECTURE'].lower()
                                    proc_arch64 = os.environ['PROCESSOR_ARCHITEW6432'].lower()

                                    if proc_arch == 'x86' and not proc_arch64:
                                        arch_keys = {0}
                                    elif proc_arch == 'x86' or proc_arch == 'amd64':
                                        arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
                                    else:
                                        raise Exception("Unhandled arch: %s" % proc_arch)

                                    for arch_key in arch_keys:
                                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | arch_key)
                                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                                            skey_name = winreg.EnumKey(key, i)
                                            skey = winreg.OpenKey(key, skey_name)
                                            try:
                                                for avV in avVendors:
                                                    if(avV in winreg.QueryValueEx(skey, 'DisplayName')[0]):
                                                        avFlag = True
                                                if('PowerShell' in winreg.QueryValueEx(skey, 'DisplayName')[0]):
                                                    psFlag = True
                                                if ('Java' in winreg.QueryValueEx(skey, 'DisplayName')[0]):
                                                    if not "Java Auto Updater" in winreg.QueryValueEx(skey, 'DisplayName')[0]:
                                                        jFlag = True
                                                        link = "http://javadl-esd-secure.oracle.com/update/baseline.version"
                                                        f = requests.get(link)
                                                        myStr = (winreg.QueryValueEx(skey, 'DisplayName')[0])
                                                        hStr = myStr.split(" ")
                                                        if(hStr[3].find(str(f))):
                                                            jFlag = False
                                                if ('pcap' in winreg.QueryValueEx(skey, 'DisplayName')[0]):
                                                    pcap = True
                                                print(winreg.QueryValueEx(skey, 'DisplayName')[0])
                                                swInstalls.append(winreg.QueryValueEx(skey, 'DisplayName')[0])
                                            except OSError as e:
                                                if e.errno == errno.ENOENT:
                                                    pass
                                            finally:
                                                skey.Close()
    gc.collect()
except:
    my_logger.log(50,"LAN scan error")
    gc.collect()
    exit()

#Report formation
try:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for h in hostInfo:
        pdf.cell(200, 10, txt="Internal Scan Report for " + str(h) + ' on ' + now.strftime("%Y-%m-%d %H:%M"), ln=1, align="L")
    for hf in myHotfix:
            pdf.cell(200, 10, txt=str(hf), ln=1, align="L")
    pdf.cell(200, 10, txt="Users on system " + str(listusers()), ln=1, align="L")
    if(wUpdate):
        pdf.cell(200, 10, txt="Win10 system on legacy version.", ln=1, align="L")
    if(psFlag):
        pdf.cell(200, 10, txt="PowerShell detected on system.", ln=1, align="L")
    if not avFlag:
        pdf.cell(200, 10, txt="AV not detected on system.", ln=1, align="L")
    if(jFlag):
        pdf.cell(200, 10, txt="Legacy Java detected on system.", ln=1, align="L")
    if(pcap):
        pdf.cell(200, 10, txt="PCAP detected on system.", ln=1, align="L")
    for fp in hostPorts:
        pdf.cell(200, 10, txt="Port detected: "+fp, ln=1, align="L")
    pdf.output("PyBSAw_Scan_Report_" + now.strftime("%Y_%m_%d") + ".pdf")
    gc.collect()
except:
    my_logger.log(50, "PDF error")
    gc.collect()
    exit()