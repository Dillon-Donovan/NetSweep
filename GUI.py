from NetSweep import sniffer
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from scapy.all import *
from sys import *
from scan_subnet_file import scan_subnet  # Import the function from the second Python file

class Worker(QObject):
    finished = pyqtSignal()
    packetInfo = pyqtSignal(str)

    def get_sniff(self):
        sniffedPackets = sniffer(3)
        formatedText = packet_group_to_string(sniffedPackets)
        output = (str(sniffedPackets) + "\n" + formatedText)
        self.packetInfo.emit(output)
        self.finished.emit()

class NetSweepGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetSweep")
        self.setGeometry(100, 100, 600, 300)
        layout = QVBoxLayout()

        self.mainDisplay = QTextEdit()
        self.mainDisplay.setStyleSheet("background-color: #0E1726; color: #FFFFFF; border-color: #0056B3; border-width: 2px")
        self.mainDisplay.setFixedHeight(225)
        self.mainDisplay.setFixedWidth(1150)
        self.mainDisplay.setReadOnly(True)
        layout.addWidget(self.mainDisplay)

        hbox = QHBoxLayout()

        self.slim_text_display = QTextEdit()
        self.slim_text_display.setFixedHeight(50)
        self.slim_text_display.setStyleSheet("background-color: #0E1726; color: #FFFFFF; border-color: #0056B3; border-width: 2px")
        self.slim_text_display.setReadOnly(True)
        hbox.addWidget(self.slim_text_display)

        self.text_input = QLineEdit()
        self.text_input.setFixedWidth(100)
        self.text_input.setStyleSheet("background-color: #0E1726; color: #FFFFFF; border-color: #0056B3; border-width: 2px")
        hbox.addWidget(self.text_input)
        layout.addLayout(hbox)

        self.sniffButton = QPushButton("Start 3 second sniff")
        self.sniffButton.setStyleSheet("background-color: #0056B3; color: #FFFFFF; border: 2px solid #0056B3; border-radius: 5px; padding: 5px")
        self.sniffButton.clicked.connect(self.handle_sniffButton)
        layout.addWidget(self.sniffButton)

        button2 = QPushButton("Scan Subnet")
        button2.setStyleSheet("background-color: #0056B3; color: #FFFFFF; border: 2px solid #0056B3; border-radius: 5px; padding: 5px")
        button2.clicked.connect(self.handle_scanSubnet)  # Connect to the handler function
        layout.addWidget(button2)

        button3 = QPushButton("Button 3")
        button3.setStyleSheet("background-color: #0056B3; color: #FFFFFF; border: 2px solid #0056B3; border-radius: 5px; padding: 5px")
        layout.addWidget(button3)

        button4 = QPushButton("Button 4")
        button4.setStyleSheet("background-color: #0056B3; color: #FFFFFF; border: 2px solid #0056B3; border-radius: 5px; padding: 5px")
        layout.addWidget(button4)

        self.setLayout(layout)

    def handle_sniffButton(self):
        self.mainDisplay.insertPlainText("Sniffing packets...\n")
        self.thread = QThread()
        self.worker = Worker()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.get_sniff)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.packetInfo.connect(self.set_mainDisplay)
        self.thread.start()
        self.sniffButton.setEnabled(False)
        self.sniffButton.setStyleSheet("background-color: #0E1726; color: #FFFFFF; border: 2px solid #0056B3; border-radius: 5px; padding: 5px")
        self.thread.finished.connect(lambda: self.sniffButton.setEnabled(True))

    def set_mainDisplay(self, string):
        self.mainDisplay.insertPlainText(string)

    def handle_scanSubnet(self):
        subnet = self.text_input.text()  # Get subnet from the text input
        self.mainDisplay.insertPlainText(f"Scanning subnet {subnet}...\n")
        live_hosts = scan_subnet(subnet)  # Call the function from the second Python file
        self.mainDisplay.insertPlainText("Live hosts in the subnet:\n")
        for host in live_hosts:
            self.mainDisplay.insertPlainText(str(host) + "\n")

    #Function that converts a packet object to string
def packet_group_to_string(packetGroup):
    string =""
    for packet in packetGroup:
        string = string + str(packet.summary()) + "\n"
    return string + "\n"

def main():
    app = QApplication(sys.argv)
    window = NetSweepGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()