from NetSweep import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from scapy.all import *
import sys
import os
import string

#Worker thread object for passing signals to worker
class WorkerSignals(QObject):
    result = pyqtSignal(object)
    finished = pyqtSignal()

#Worker that runs a function passed in parameter in a separate thread and returns output via signals
class Worker(QRunnable):
    def __init__(self, fn):
        super(Worker, self).__init__()
        self.fn = fn
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self):
        output = self.fn()
        self.signals.result.emit(output)
        self.signals.finished.emit()


#########################################################################################
#Main GUI ->
#########################################################################################
class NetSweepGUI(QWidget):
    def __init__(self):
        super().__init__()

        #Create threadpool for automatic thread handling
        self.threadpool = QThreadPool()
        self.threadpool.maxThreadCount()

        #Creating and naming main display
        self.setWindowTitle("NetSweep")
        self.setGeometry(400, 400, 1200, 800)
        layout = QVBoxLayout()

        #Creation of label for output box
        self.topLayout = QHBoxLayout()
        self.mainDisplayLabel = QLabel("  Output")
        self.mainDisplayLabel.setObjectName("OutputWindow")
        self.mainDisplayLabel.setFont(QFont('Arial', 13,-1,True))
        self.mainDisplayLabel.setFixedSize(125, 30)
        self.mainDisplayLabel.setAlignment(Qt.AlignLeft)
        self.topLayout.addWidget(self.mainDisplayLabel)

        #Creation of clear display button
        self.clearMainDisplayButton = QPushButton(self)
        self.clearMainDisplayButton.setObjectName("clearMainDisplayButton")
        self.clearMainDisplayButton.pressed.connect(lambda: self.mainDisplay.clear())
        self.clearMainDisplayButton.setIcon(QIcon('resetButton2'))
        self.clearMainDisplayButton.setFixedSize(40, 40)
        self.clearMainDisplayButton.setIconSize(QSize(28,28))
        self.topLayout.addWidget(self.clearMainDisplayButton)

        #Creation of spacer item
        self.spacer = QSpacerItem(1200, 40, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.topLayout.addItem(self.spacer)
        layout.addLayout(self.topLayout)

        #First text display widget
        self.mainDisplay = QTextBrowser()
        self.cursor = self.mainDisplay.textCursor()
        self.mainDisplay.setOpenExternalLinks(True)
        self.mainDisplay.setReadOnly(True)
        layout.addWidget(self.mainDisplay)

        #Initialize tab menu
        self.tab_menu = MyTabWidget(self)
        layout.addWidget(self.tab_menu)

        self.setLayout(layout)
        
    #Setter function for main display
    def set_mainDisplay(self, string):
        self.mainDisplay.moveCursor(self.cursor.End, self.cursor.MoveAnchor)
        self.mainDisplay.insertHtml(string)

#########################################################################################
#Custom Tab widget and its containers ->
#########################################################################################
class MyTabWidget(QWidget):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)

        #Initialize tab container
        self.layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab1.setObjectName("tab1")
        self.tab2.setObjectName("tab2")
        
        #Add tabs
        self.tabs.addTab(self.tab1,"Basic")
        self.tabs.addTab(self.tab2,"Advanced")
        
        #Create first tab
        self.tab1.layout = QVBoxLayout(self)
        self.tab2.layout = QVBoxLayout(self)

    #IpConfig Button (tab 1)
        self.IpConfigButton = QPushButton(self)
        self.IpConfigButton.setText("Get IP configuration")
        self.tab1.layout.addWidget(self.IpConfigButton)
        self.IpConfigButton.clicked.connect(self.handle_ipConfigButton)
        self.layout.addWidget(self.IpConfigButton)

    #ICMP Ping Button (tab 1)
        self.frame = QFrame(self)
        self.frame.setObjectName("inputBox")
        self.frame.setFixedHeight(115)
        #ICMP Layout
        self.inputLayout = QHBoxLayout()
        self.togetherLayout = QVBoxLayout()
        #ICMP Ping button
        self.icmpPingButton = QPushButton(self)
        self.icmpPingButton.setText("Ping Test")
        self.icmpPingButton.clicked.connect(self.handle_pingButton)
        self.togetherLayout.addWidget(self.icmpPingButton)
        #ICMP Label
        self.inputLabel = QLabel("Enter an IP address: ")
        self.inputLayout.addWidget(self.inputLabel)
        #ICMP input box
        self.icmpPingButtonInput = QLineEdit(placeholderText = "(Blank = Default gateway)")
        self.inputFont = self.icmpPingButtonInput.font()
        self.inputFont.setItalic(True)
        self.icmpPingButtonInput.setFont(self.inputFont)
        self.inputLayout.addWidget(self.icmpPingButtonInput)
        #Combining Layouts
        self.togetherLayout.addLayout(self.inputLayout)
        self.frame.setLayout(self.togetherLayout)
        self.tab1.layout.addWidget(self.frame)
        
    #Scan subnet Button (tab 1)
        self.scanSubnetButton = QPushButton(self)
        self.scanSubnetButton.setText("Scan subnet")
        self.tab1.layout.addWidget(self.scanSubnetButton)
        self.scanSubnetButton.clicked.connect(self.handle_scanSubnetButton)
        self.layout.addWidget(self.scanSubnetButton)

    #Public IP Button (tab 1)
        self.publicIpButton = QPushButton(self)
        self.publicIpButton.setText("Get my Public IP")
        self.tab1.layout.addWidget(self.publicIpButton)
        self.publicIpButton.clicked.connect(self.handle_publicIpButton)
        self.layout.addWidget(self.publicIpButton)

    #Sniff Button (tab 2)
        self.frame = QFrame(self)
        self.frame.setObjectName("inputBox")
        self.frame.setFixedHeight(115)
        #Sniff Button Layout
        self.inputLayout = QHBoxLayout()
        self.togetherLayout = QVBoxLayout()
        #Sniff Button
        self.sniffButton = QPushButton(self)
        self.sniffButton.setText("Execute Timed Sniff")
        self.sniffButton.clicked.connect(self.handle_sniffButton)
        self.togetherLayout.addWidget(self.sniffButton)
        #Sniff Button Label
        self.inputLabel = QLabel("Enter an integer for sniff time(seconds): ")
        self.inputLayout.addWidget(self.inputLabel)
        #Sniff Button input box
        self.sniffButtonInput = QLineEdit(placeholderText = "(Blank = 3 seconds)")
        self.inputFont = self.sniffButtonInput.font()
        self.inputFont.setItalic(True)
        self.sniffButtonInput.setFont(self.inputFont)
        self.inputLayout.addWidget(self.sniffButtonInput)
        #Combining Layouts
        self.togetherLayout.addLayout(self.inputLayout)
        self.frame.setLayout(self.togetherLayout)
        self.tab2.layout.addWidget(self.frame)

    #TCP Traceroute Button (tab 2)
        self.frame = QFrame(self)
        self.frame.setObjectName("inputBox")
        self.frame.setFixedHeight(115)
        #TCP Traceroute Layout
        self.inputLayout = QHBoxLayout()
        self.togetherLayout = QVBoxLayout()
        #TCP Traceroute button
        self.tcpTracerouteButton = QPushButton(self)
        self.tcpTracerouteButton.setText("Run TCP Traceroute")
        self.tcpTracerouteButton.clicked.connect(self.handle_tcpTraceroute)
        self.togetherLayout.addWidget(self.tcpTracerouteButton)
        #TCP Traceroute Label
        self.inputLabel = QLabel("Enter an IP address or URL: ")
        self.inputLayout.addWidget(self.inputLabel)
        #TCP Traceroute input box
        self.tcpTracerouteButtonInput = QLineEdit(placeholderText = "(Blank = www.google.com)")
        self.inputFont = self.tcpTracerouteButtonInput.font()
        self.inputFont.setItalic(True)
        self.tcpTracerouteButtonInput.setFont(self.inputFont)
        self.inputLayout.addWidget(self.tcpTracerouteButtonInput)
        #Combining Layouts
        self.togetherLayout.addLayout(self.inputLayout)
        self.frame.setLayout(self.togetherLayout)
        self.tab2.layout.addWidget(self.frame)

    #Port Scanner Button (tab 2)
        self.frame = QFrame(self)
        self.frame.setObjectName("inputBox")
        self.frame.setFixedHeight(115)
        #Port Scan Layout
        self.inputLayout = QHBoxLayout()
        self.togetherLayout = QVBoxLayout()
        #Port Scan button
        self.portScanButton = QPushButton(self)
        self.portScanButton.setText("Run TCP Port Scan")
        self.portScanButton.clicked.connect(self.handle_portScan)
        self.togetherLayout.addWidget(self.portScanButton)
        #Port Scan IP Label
        self.inputLabel = QLabel("Enter an IP address: ")
        self.inputLayout.addWidget(self.inputLabel)
        #Port Scan input box
        self.portScanButtonInput = QLineEdit(placeholderText = "(Blank = Default gateway)")
        self.inputFont = self.portScanButtonInput.font()
        self.inputFont.setItalic(True)
        self.portScanButtonInput.setFont(self.inputFont)
        self.inputLayout.addWidget(self.portScanButtonInput)
        #Port Scan lower range Label
        self.inputLabel = QLabel("Lower range: ")
        self.inputLayout.addWidget(self.inputLabel)
        #Port Scan lower range input box
        self.portScanButtonInputLower = QLineEdit(placeholderText = "(Blank = 0)")
        self.portScanButtonInputLower.setFont(self.inputFont)
        self.inputLayout.addWidget(self.portScanButtonInputLower)
        #Port Scan upper range Label
        self.inputLabel = QLabel("Upper range: ")
        self.inputLayout.addWidget(self.inputLabel)
        #Port Scan upper range input box
        self.portScanButtonInputUpper = QLineEdit(placeholderText = "(Blank = 65535)")
        self.portScanButtonInputUpper.setFont(self.inputFont)
        self.inputLayout.addWidget(self.portScanButtonInputUpper)
        #Combining Layouts
        self.togetherLayout.addLayout(self.inputLayout)
        self.frame.setLayout(self.togetherLayout)
        self.tab2.layout.addWidget(self.frame)

    #DNS Request Button (tab 2)
        self.frame = QFrame(self)
        self.frame.setObjectName("inputBox")
        self.frame.setFixedHeight(145)
        #DNS Request Layout
        self.inputLayout = QHBoxLayout()
        self.radioButtonLayout = QHBoxLayout()
        self.togetherLayout = QVBoxLayout()
        #DNS Request button
        self.dnsRequestButton = QPushButton(self)
        self.dnsRequestButton.setText("Run DNS Request")
        self.dnsRequestButton.clicked.connect(self.handle_dnsRequest)
        self.togetherLayout.addWidget(self.dnsRequestButton)
        #DNS Request Label
        self.inputLabel = QLabel("Enter an IP address or URL: ")
        self.inputLayout.addWidget(self.inputLabel)
        #DNS Request input box
        self.dnsRequestButtonInput = QLineEdit(placeholderText = "(Blank = www.google.com)")
        self.inputFont = self.dnsRequestButtonInput.font()
        self.inputFont.setItalic(True)
        self.dnsRequestButtonInput.setFont(self.inputFont)
        self.inputLayout.addWidget(self.dnsRequestButtonInput)
        #DNS Request server selection radio buttons
        self.dnsRequestRadioButtonLabel = QLabel("Select a DNS server: ")
        self.dnsRequestRadioButtonLabel.setFixedWidth(115)
        self.dnsRequestRadioButton1 = QRadioButton(self)
        self.dnsRequestRadioButton1.setText("Cloudflare: 1.1.1.1")
        self.dnsRequestRadioButton1.toggle()
        self.dnsRequestRadioButton2 = QRadioButton(self)
        self.dnsRequestRadioButton2.setText("Google: 8.8.8.8")
        self.dnsRequestRadioButton3 = QRadioButton(self)
        self.dnsRequestRadioButton3.setText("Quad9: 9.9.9.9")
        self.dnsRequestRadioButton4 = QRadioButton(self)
        self.dnsRequestRadioButton4.setText("Open DNS: 208.67.222.222")
        self.radioButtonLayout.addWidget(self.dnsRequestRadioButtonLabel)
        self.radioButtonLayout.addWidget(self.dnsRequestRadioButton1)
        self.radioButtonLayout.addWidget(self.dnsRequestRadioButton2)
        self.radioButtonLayout.addWidget(self.dnsRequestRadioButton3)
        self.radioButtonLayout.addWidget(self.dnsRequestRadioButton4)
        #Combining Layouts
        self.togetherLayout.addLayout(self.inputLayout)
        self.togetherLayout.addLayout(self.radioButtonLayout)
        self.frame.setLayout(self.togetherLayout)
        self.tab2.layout.addWidget(self.frame)

        #Combine and set appropriate layouts and widgets for parent tab container
        self.tab1.setLayout(self.tab1.layout)
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
        self.tab2.setLayout(self.tab2.layout)

#########################################################################################
#Networking Functions
#########################################################################################        
    #Runs sniffer() function from Netsweep.py
    def get_sniff(self):
        if self.sniffButtonInput.text() != "":
            time = self.sniffButtonInput.text()
            time = int(time)
        else:
            time = 3
        sniffedPackets = sniffer(time)
        formatedText = packet_group_to_string(sniffedPackets)
        summary = str(sniffedPackets)
        summary = summary.replace("<","&lt;").replace(">","&gt;")
        summary = "<br>" + summary + "<br>"
        result = (summary + formatedText)
        return result
    
    #Runs public_ip() function from Netsweep.py
    def get_public_ip(self):
        IP = public_ip()
        return IP + "<br>"

    #Runs scan_subnet() function from Netsweep.py
    def get_subnetScan(self):
        hosts = scan_subnet()
        formattedText = packet_group_to_string(hosts)
        return formattedText

    #Runs icmp_ping() function from Netsweep.py
    def get_ping(self):
        Output = icmp_ping(self.icmpPingButtonInput.text())
        if isinstance(Output, str) == True:
            return Output + "<br>"
        else:
            formattedText = packet_group_to_string(Output)
            if not Output:
                return "<div style=\"color:red;\">No response recieved from address: " + self.icmpPingButtonInput.text() + "<\div><br>"
            return "<div style=\"color:green;\">Response recieved from address: " + self.icmpPingButtonInput.text() +"</div><br>" + formattedText

    #Runs tcp_traceroute() function from Netsweep.py
    def get_tcp_traceroute(self):
        route = tcp_traceroute(default = self.tcpTracerouteButtonInput.text())
        routeOutput = packet_group_to_string_traceroute(route)
        return routeOutput

    #Runs public_ip() function from Netsweep.py
    def get_dns_request(self):
        if len(self.dnsRequestButtonInput.text()) > 0:
            domain = self.dnsRequestButtonInput.text()
        else:
            domain = "www.google.com"
        if self.dnsRequestRadioButton1.isChecked() == True:
            dns_server = "1.1.1.1"
            self.parent().set_mainDisplay("<br>DNS Request: <div style=\"color:#9b4dfa\">(DNS Server = "+ self.dnsRequestRadioButton1.text() +" ; Domain = " + domain + ")<br>")
        if self.dnsRequestRadioButton2.isChecked() == True:
            dns_server = "8.8.8.8"
            self.parent().set_mainDisplay("<br>DNS Request: <div style=\"color:#9b4dfa\">(DNS Server = "+ self.dnsRequestRadioButton2.text() +" ; Domain = " + domain + ")<br>")
        if self.dnsRequestRadioButton3.isChecked() == True:
            dns_server = "9.9.9.9"
            self.parent().set_mainDisplay("<br>DNS Request: <div style=\"color:#9b4dfa\">(DNS Server = "+ self.dnsRequestRadioButton3.text() +" ; Domain = " + domain + ")<br>")
        if self.dnsRequestRadioButton4.isChecked() == True:
            dns_server = "208.67.222.222"
            self.parent().set_mainDisplay("<br>DNS Request: <div style=\"color:#9b4dfa\">(DNS Server = "+ self.dnsRequestRadioButton4.text() +" ; Domain = " + domain + ")<br>")
        route = public_ip(domain, dns_server)
        if route == "Error parsing domain":
            return "<div style=\"color:red\">Error parsing domain</div><br>"
        return "<b style=\"color:grey;\">Resolved IP = </b> <a style=\"color:orange;\" href=https://iplocation.io/ip/" + route + ">" + route + "<br>"

    #Runs scanPorts() function from Netsweep.py
    def get_portScan(self):
        if self.portScanButtonInput.text() != "":
            IP = self.portScanButtonInput.text()
        else:
            IP = getGateway()
        if self.portScanButtonInputLower.text() != "":
            lower = self.portScanButtonInputLower.text()
        else:
            lower = 0
        if self.portScanButtonInputUpper.text() != "":
            upper = self.portScanButtonInputUpper.text()
        else:
            upper = 65535
        if (int(lower) < 0) or (int(upper) > 65535):
                return "<br>Please enter a number within the range."
        if int(lower) > int(upper):
                return "<br>Please ensure the ranges are set correctly."
        ports = scanPorts(IP,lower,upper)
        output = "<br>Open Ports on "+ "<a style=\"color:orange;\" href=https://iplocation.io/ip/" + IP + "\">" + IP + ": <br>"
        for port in ports:
            portString = str(port)
            output = output + "<b style=\"color:grey;\">TCP</b> <a style=\"color:#059efc\" href=\"https://www.speedguide.net/port.php?port="+portString+"\">"+ portString + "</a><br>"
        return output

    #Runs ipconfig() function from Netsweep.py
    def get_ipconfig(self):
        self.parent().set_mainDisplay("<br>" + "<div style=\"color:red\">++++++++++++++++++++++++++++++++++++++++++++++++ Start IpConfig ++++++++++++++++++++++++++++++++++++++++++++++++</div>" + "<br>")
        self.parent().mainDisplay.insertPlainText(ipconfig())
        self.parent().set_mainDisplay("<br>" + "<div style=\"color:red\">+++++++++++++++++++++++++++++++++++++++++++++++++ End IpConfig +++++++++++++++++++++++++++++++++++++++++++++++++</div>" + "<br>")

#########################################################################################
#Button Handlers
#########################################################################################
    #Handles DNS Request Button
    def handle_dnsRequest(self):
        self.dnsRequestButton.setText("(Sending DNS request...)")
        worker = Worker(self.get_dns_request)
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.dnsRequestButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.dnsRequestButton.setStyleSheet(""))

        #Start thread
        self.parent().threadpool.start(worker)
        self.dnsRequestButton.setEnabled(False)
        self.dnsRequestButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.dnsRequestButton.setText("Run DNS request"))

    #Handles Get IP configuration Button
    def handle_ipConfigButton(self):
        self.IpConfigButton.setText("Fetching IP configuration...")
        worker = Worker(self.get_ipconfig)
        worker.signals.finished.connect(lambda: self.IpConfigButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.IpConfigButton.setStyleSheet(""))
        
        #Start thread
        self.parent().threadpool.start(worker)
        self.IpConfigButton.setEnabled(False)
        self.IpConfigButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.IpConfigButton.setText("Get IP configuration"))

    #Handles Port Scan Button
    def handle_portScan(self):
        self.portScanButton.setText("Scanning ports (this could take a while)...")
        worker = Worker(self.get_portScan)
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.portScanButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.portScanButton.setStyleSheet(""))

        #Start thread
        self.parent().threadpool.start(worker)
        self.portScanButton.setEnabled(False)
        self.portScanButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.portScanButton.setText("Run TCP Port Scan"))

    #Handles TCP traceroute Button
    def handle_tcpTraceroute(self):
        self.tcpTracerouteButton.setText("(Tracing TCP packet route...)")
        worker = Worker(self.get_tcp_traceroute)
        if (self.tcpTracerouteButtonInput.text() == ""): 
            target = "www.google.com" 
        else:
            target = self.tcpTracerouteButtonInput.text()
        worker.signals.result.connect(lambda: self.parent().set_mainDisplay("<br>TCP Traceroute results to " + target + ": <br>"))
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.tcpTracerouteButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.tcpTracerouteButton.setStyleSheet(""))

        #Start thread
        self.parent().threadpool.start(worker)
        self.tcpTracerouteButton.setEnabled(False)
        self.tcpTracerouteButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.tcpTracerouteButton.setText("Run TCP Traceroute"))
    #Handles ICMP Ping Button

    def handle_pingButton(self):
        self.icmpPingButton.setText("(Running ICMP ping...)")
        worker = Worker(self.get_ping)
        worker.signals.result.connect(lambda: self.parent().set_mainDisplay("<br>Ping results:<br>"))
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.icmpPingButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.icmpPingButton.setStyleSheet(""))

        #Start thread
        self.parent().threadpool.start(worker)
        self.icmpPingButton.setEnabled(False)
        self.icmpPingButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.icmpPingButton.setText("Ping Test"))
    #Handles Get Public IP Button

    def handle_publicIpButton(self):
        self.publicIpButton.setText("(Retrieving Public IP...)")
        worker = Worker(self.get_public_ip)
        worker.signals.result.connect(lambda: self.parent().set_mainDisplay("<br>Your public IP is: "))
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.publicIpButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.publicIpButton.setStyleSheet(""))

        #Start thread
        self.parent().threadpool.start(worker)
        self.publicIpButton.setEnabled(False)
        self.publicIpButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.publicIpButton.setText("Get my Public IP"))

    #Handles Scan Subnet Button
    def handle_scanSubnetButton(self):
        self.scanSubnetButton.setText("(subnet scan in progress...)")
        worker = Worker(self.get_subnetScan)
        worker.signals.result.connect(lambda: self.parent().set_mainDisplay("<br>Live hosts in the subnet:<br>"))
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.scanSubnetButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.scanSubnetButton.setStyleSheet(""))

        #Start thread
        self.parent().threadpool.start(worker)
        self.scanSubnetButton.setEnabled(False)
        self.scanSubnetButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.scanSubnetButton.setText("Scan subnet"))

    #Handles Sniff Button
    def handle_sniffButton(self):
        self.sniffButton.setText("(sniff in progress...)")
        worker = Worker(self.get_sniff)
        worker.signals.result.connect(lambda: self.parent().set_mainDisplay("<br>Packets sniffed:"))
        worker.signals.result.connect(self.parent().set_mainDisplay)
        worker.signals.finished.connect(lambda: self.sniffButton.setEnabled(True))
        worker.signals.finished.connect(lambda: self.sniffButton.setStyleSheet(""))
        
        #Start thread
        self.parent().threadpool.start(worker)
        self.sniffButton.setEnabled(False)
        self.sniffButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.sniffButton.setText("Start 3 second sniff"))

#########################################################################################
#Supporting functions
#########################################################################################
#Converts a scappy packet object to string
def packet_group_to_string(packetGroup):
    string =""
    count = 0
    for packet in packetGroup:
        count = count + 1
        string = string + "<num style=\"color:red;font-style:italic;\">" + str(count) + "&nbsp;&nbsp;</num>" +  str(HTML_summary(packet))  + "<br>"
    return string

#(Special version for TCP traceroute)
def packet_group_to_string_traceroute(packetGroup):
    string =""
    count = 0
    for packet in packetGroup:
        count = count + 1
        string = string + "<num style=\"color:red;font-style:italic;\">Hop " + str(count) + "&nbsp;&nbsp;</num>" +  str(HTML_summary(packet))  + "<br>"
    return string

#Function to format the packets for HTML output in mainDisplay() with links to reference data
def HTML_summary(packet):
    layers = []
    #Extract and print the Ethernet layer
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        layers.append(f"<b style=\"color:grey;\">Ethernet </b><a style=\"color:#029c14\" href=https://www.macvendorlookup.com/search/{eth_layer.src}><i>{eth_layer.src}</a> > <a style=\"color:#029c14\" href=https://www.macvendorlookup.com/search/{eth_layer.dst}>{eth_layer.dst}</i></a>")
    
    #Extract and print the IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        layers.append(f"<b style=\"color:grey;\">IP</b> <sub>[src]</sub> <i><a style=\"color:orange;\" href=https://iplocation.io/ip/{ip_layer.src}>{ip_layer.src}</a> &nbsp; -> &nbsp; <a style=\"color:orange;\" href=https://iplocation.io/ip/{ip_layer.dst}>{ip_layer.dst}</a></i> <sub>[dst]</sub>")
    
    #Extract and print the TCP layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        layers.append(f"<b style=\"color:grey;\">TCP</b> <a style=\"color:#059efc\" href=\"https://www.speedguide.net/port.php?port={tcp_layer.sport}\"><i>{tcp_layer.sport}</a> > <a style=\"color:#059efc\" href=\"https://www.speedguide.net/port.php?port={tcp_layer.dport}\">{tcp_layer.dport}</i></a>")
    
    #Extract and print the UDP layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        layers.append(f"<b style=\"color:grey;\">UDP</b> <a style=\"color:#059efc\" href=\"https://www.speedguide.net/port.php?port={udp_layer.sport}\"><i>{udp_layer.sport}</a> > <a style=\"color:#059efc\" href=\"https://www.speedguide.net/port.php?port={udp_layer.dport}\">{udp_layer.dport}</i></a>")
    
    #Extract and print the ICMP layer
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        layers.append(f"<b style=\"color:grey;\">ICMP</b> <i>{icmp_layer.type} / {icmp_layer.code}</i>")

    #Extract and print the ARP layer
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        layers.append(f"<b style=\"color:grey;\">ARP</b> <sub>[src]</sub> <i><a style=\"color:orange;font-style:italic;\" href=https://iplocation.io/ip/{arp_layer.psrc}>{arp_layer.psrc}</a> &nbsp; -> &nbsp; <a style=\"color:orange;font-style:italic;\" href=https://iplocation.io/ip/{arp_layer.pdst}>{arp_layer.pdst}</a></i><sub>[dst]</sub>")
    
    #Print the summary
    return("<temp style=\"color:lightgreen;\">  ~~  </temp>".join(layers))

#Launches GUI
def main():
    #Get the path to the QSS file (stylesheet)
    qss_file = os.path.join(os.path.dirname(__file__), "style.qss")
    #Load the QSS file
    with open(qss_file, "r") as f:
        style = f.read()
    #Create app obj
    app = QApplication(sys.argv)
    #Apply the style
    app.setStyleSheet(style)
    #Initialize window
    window = NetSweepGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()