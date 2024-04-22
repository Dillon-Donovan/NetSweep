from NetSweep import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from scapy.all import *
import sys
import os
import string

#Subthread for running longer process (May need to add more depends on how execution of final product works)
class WorkerSignals(QObject):
    result = pyqtSignal(object)
    finished = pyqtSignal()

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
        self.setGeometry(400, 400, 1200, 650)
        layout = QVBoxLayout()

        #Creation of label for output box
        self.mainDisplayLabel = QLabel("Output window")
        self.mainDisplayLabel.setFont(QFont('Arial', 13,-1,True))
        self.mainDisplayLabel.setFixedWidth(125)
        layout.addWidget(self.mainDisplayLabel)

        #First text display widget
        self.mainDisplay = QTextBrowser()
        self.cursor = self.mainDisplay.textCursor()
        self.mainDisplay.setOpenExternalLinks(True)
        self.mainDisplay.setReadOnly(True)
        layout.addWidget(self.mainDisplay)

        #Init tab menu
        self.tab_menu = MyTabWidget(self)
        layout.addWidget(self.tab_menu)

        self.setLayout(layout)
        
    #Setter function for main display
    def set_mainDisplay(self, string):
        self.mainDisplay.moveCursor(self.cursor.End, self.cursor.MoveAnchor)
        self.mainDisplay.insertHtml(string)

#########################################################################################
#Custom widgets ->
#########################################################################################
class MyTabWidget(QWidget):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        
        #Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab1.setObjectName("tab1")
        self.tab2.setObjectName("tab2")
        #self.tabs.resize(300,200)
        
        #Add tabs
        self.tabs.addTab(self.tab1,"Tab 1")
        self.tabs.addTab(self.tab2,"Tab 2")
        
        #Create first tab
        self.tab1.layout = QVBoxLayout(self)

        #Sniff button
        self.sniffButton = QPushButton(self)
        self.sniffButton.setText("Start 3 second sniff")
        self.tab1.layout.addWidget(self.sniffButton)
        self.sniffButton.clicked.connect(self.handle_sniffButton)
        self.layout.addWidget(self.sniffButton)
        self.sniffButtonTime = QLineEdit()
        self.tab1.layout.addWidget(self.sniffButtonTime)

        #Subnet button
        self.scanSubnetButton = QPushButton(self)
        self.scanSubnetButton.setText("Scan subnet")
        self.tab1.layout.addWidget(self.scanSubnetButton)
        self.scanSubnetButton.clicked.connect(self.handle_scanSubnetButton)
        self.layout.addWidget(self.scanSubnetButton)

        #IpConfig button
        self.IpConfigButton = QPushButton(self)
        self.IpConfigButton.setText("Run IpConfig")
        self.tab1.layout.addWidget(self.IpConfigButton)
        self.IpConfigButton.clicked.connect(lambda: self.parent().set_mainDisplay("<br>" + "<div style=\"color:red\">++++++++++++++++++++++++++++++++++++++++++++++++ Start IpConfig ++++++++++++++++++++++++++++++++++++++++++++++++</div>" + "<br>"))
        self.IpConfigButton.clicked.connect(lambda: self.parent().mainDisplay.insertPlainText(get_ipconfig()))
        self.IpConfigButton.clicked.connect(lambda: self.parent().set_mainDisplay("<br>" + "<div style=\"color:red\">+++++++++++++++++++++++++++++++++++++++++++++++++ End IpConfig +++++++++++++++++++++++++++++++++++++++++++++++++</div>" + "<br>"))
        self.layout.addWidget(self.IpConfigButton)

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


        self.setLayout(self.layout)

        #Combining Layouts
        self.togetherLayout.addLayout(self.inputLayout)
        self.frame.setLayout(self.togetherLayout)
        self.tab1.layout.addWidget(self.frame)

        

        #Add tabs to widget
        self.tab1.setLayout(self.tab1.layout)
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

    def get_sniff(self):
        sniffedPackets = sniffer(3)
        formatedText = packet_group_to_string(sniffedPackets)
        summary = str(sniffedPackets)
        summary = summary.replace("<","&lt;").replace(">","&gt;")
        summary = "<br>" + summary + "<br>"
        result = (summary + formatedText)
        return result
    
    def get_subnetScan(self):
        hosts = scan_subnet()
        formattedText = packet_group_to_string(hosts)
        return formattedText

    def get_ping(self):
        Output = icmp_ping(self.icmpPingButtonInput.text())
        if isinstance(Output, str) == True:
            return Output + "<br>"
        else:
            formattedText = packet_group_to_string(Output)
            if not Output:
                return "<div style=\"color:red;\">No response recieved from address: " + self.icmpPingButtonInput.text() + "<\div><br>"
            return "<div style=\"color:green;\">Response recieved from address: " + self.icmpPingButtonInput.text() +"</div><br>" + formattedText
        
    def handle_pingButton(self):
        self.icmpPingButton.setText("(ICMP ping in progress...)")

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

        #Start thread
        self.parent().threadpool.start(worker)
        self.icmpPingButton.setEnabled(False)
        self.icmpPingButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        worker.signals.finished.connect(lambda: self.icmpPingButton.setText("Ping Test"))

    def handle_scanSubnetButton(self):
        
        #subnet = self.text_input.text()  # Get subnet from the text input
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
    #Extract and print the Ethernet layer https://www.macvendorlookup.com/search/
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