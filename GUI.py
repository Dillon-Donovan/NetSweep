from NetSweep import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from scapy.all import *
import sys
import os
import string

#Subthread for running longer process (May need to add more depends on how execution of final product works)
class Worker(QObject):
    finished = pyqtSignal()
    packetInfo = pyqtSignal(str)
    subnetScan = pyqtSignal(str)

    def get_sniff(self):
        sniffedPackets = sniffer(3)
        formatedText = packet_group_to_string(sniffedPackets)
        summary = str(sniffedPackets)
        summary = summary.replace("<","&lt;").replace(">","&gt;")
        summary = "<br>" + summary + "<br>"
        output = (summary + formatedText)
        self.packetInfo.emit(output)
        self.finished.emit()
    
    def get_subnetScan(self):
        hosts = scan_subnet()
        formattedText = packet_group_to_string(hosts)
        self.subnetScan.emit(formattedText)
        self.finished.emit()

#########################################################################################
#Main GUI ->
#########################################################################################
class NetSweepGUI(QWidget):
    def __init__(self):
        super().__init__()

        #Creating and naming main display
        self.setWindowTitle("NetSweep")
        self.setGeometry(100, 100, 600, 300)
        layout = QVBoxLayout()

        #First text display widget
        self.mainDisplay = QTextBrowser()
        self.mainDisplay.setOpenExternalLinks(True)
        self.mainDisplay.setFixedHeight(225)
        self.mainDisplay.setFixedWidth(1150)
        self.mainDisplay.setReadOnly(True)
        layout.addWidget(self.mainDisplay)

        #Init tab menu
        self.tab_menu = MyTabWidget(self)
        layout.addWidget(self.tab_menu)

        #Button 2
        button2 = QPushButton("Button 2")
        layout.addWidget(button2)

        #Button 3
        button3 = QPushButton("Button 3")
        layout.addWidget(button3)

        #Button 4
        button4 = QPushButton("Button 4")
        layout.addWidget(button4)

        self.setLayout(layout)
        
    #Setter function for main display
    def set_mainDisplay(self, string):
        self.mainDisplay.insertHtml(string)

#########################################################################################
#Custom widgets ->
#########################################################################################


class MyTabWidget(QWidget):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tabs.resize(300,200)
        
        # Add tabs
        self.tabs.addTab(self.tab1,"Tab 1")
        self.tabs.addTab(self.tab2,"Tab 2")
        
        # Create first tab
        self.tab1.layout = QVBoxLayout(self)

        #Sniff button
        self.sniffButton = QPushButton(self)
        self.sniffButton.setText("Start 3 second sniff")
        self.tab1.layout.addWidget(self.sniffButton)
        self.sniffButton.clicked.connect(self.handle_sniffButton)
        self.layout.addWidget(self.sniffButton)

        #Subnet button
        self.scanSubnetButton = QPushButton(self)
        self.scanSubnetButton.setText("Scan subnet")
        self.tab1.layout.addWidget(self.scanSubnetButton)
        self.scanSubnetButton.clicked.connect(self.handle_scanSubnetButton)
        self.layout.addWidget(self.scanSubnetButton)
        self.tab1.setLayout(self.tab1.layout)
        
        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

    #Handler for the scanSubnet Button
    def handle_scanSubnetButton(self):
        #subnet = self.text_input.text()  # Get subnet from the text input
        self.scanSubnetButton.setText("(subnet scan in progress)")
        
        #Create a Qthread and worker obj
        self.thread = QThread()
        self.worker = Worker()

        #Move worker to thread
        self.worker.moveToThread(self.thread)

        #Connect signals and slots from worker to function (how they communicate)
        self.thread.started.connect(self.worker.get_subnetScan)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.parent().set_mainDisplay("<br>Live hosts in the subnet:<br>")
        self.worker.subnetScan.connect(self.parent().set_mainDisplay)
        self.thread.finished.connect(lambda: self.scanSubnetButton.setEnabled(True))
        self.thread.finished.connect(lambda: self.scanSubnetButton.setStyleSheet(""))
        self.thread.finished.connect(lambda: self.scanSubnetButton.setText("Scan subnet"))

        #Start thread
        self.thread.start()
        self.scanSubnetButton.setEnabled(False)
        self.scanSubnetButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")

    def handle_sniffButton(self):

        #Create a Qthread and worker obj
        self.thread = QThread()
        self.worker = Worker()

        #Move worker to thread
        self.worker.moveToThread(self.thread)

        #Connect signals and slots from worker to function (how they communicate)
        self.thread.started.connect(self.worker.get_sniff)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.packetInfo.connect(self.parent().set_mainDisplay)
        self.thread.finished.connect(lambda: self.sniffButton.setEnabled(True))
        self.thread.finished.connect(lambda: self.sniffButton.setStyleSheet(""))

        #Start thread
        self.thread.start()
        self.sniffButton.setEnabled(False)
        self.sniffButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")

#########################################################################################
#Supporting functions
#########################################################################################
#Converts a packet object to string
def packet_group_to_string(packetGroup):
    string =""
    count = 0
    for packet in packetGroup:
        count = count + 1
        string = string + "<num style=\"color:red;font-style:italic;\">" + str(count) + "&nbsp;&nbsp;</num>" +  str(HTML_summary(packet))  + "<br>"
    return string

#Function to format the packets for best output to QTextBrowser
def HTML_summary(packet):
    layers = []
    #Extract and print the Ethernet layer
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        layers.append(f"<b style=\"color:grey;\">Ethernet</b> <i>{eth_layer.src} > {eth_layer.dst}</i>")
    
    #Extract and print the IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        layers.append(f"<b style=\"color:grey;\">IP</b> <sub>[src]</sub> <i><a style=\"color:orange;\" href=https://iplocation.io/ip/{ip_layer.src}>{ip_layer.src}</a> &nbsp; -> &nbsp; <a style=\"color:orange;\" href=https://iplocation.io/ip/{ip_layer.dst}>{ip_layer.dst}</a></i><sub>[dst]</sub>")
    
    #Extract and print the TCP layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        layers.append(f"<b style=\"color:grey;\">TCP</b> <i>{tcp_layer.sport} > {tcp_layer.dport}</i>")
    
    #Extract and print the UDP layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        layers.append(f"<b style=\"color:grey;\">UDP</b> <i>{udp_layer.sport} > {udp_layer.dport}</i>")
    
    #Extract and print the ICMP layer
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        layers.append(f"<b style=\"color:grey;\">ICMP</b> <i>{icmp_layer.type} / {icmp_layer.code}</i>")

    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        layers.append(f"<b style=\"color:grey;\">ARP</b> <sub>[src]</sub> <i><a style=\"color:orange;font-style:italic;\" href=https://iplocation.io/ip/{arp_layer.psrc}>{arp_layer.psrc}</a> &nbsp; -> &nbsp; <a style=\"color:orange;font-style:italic;\" href=https://iplocation.io/ip/{arp_layer.pdst}>{arp_layer.pdst}</a></i><sub>[dst]</sub>")
    
    #Print the summary
    return("<temp style=\"color:lightgreen;\">  ~~  </temp>".join(layers))


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