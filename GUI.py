from NetSweep import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from scapy.all import *
from sys import *

#Subthread for running longer process (May need to add more depends on how execution of final product works)
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

#########################################################################################
#Functions used to create gui ->
#########################################################################################
        #Creating and naming main display
        self.setWindowTitle("NetSweep")
        self.setGeometry(100, 100, 600, 300)
        layout = QVBoxLayout()

        #First text display widget
        self.mainDisplay = QTextEdit()
        self.mainDisplay.setStyleSheet("background-color: #191A2C; color: white; border-color: #B58800; border-width: 3px")
        self.mainDisplay.setFixedHeight(225)
        self.mainDisplay.setFixedWidth(1150)
        self.mainDisplay.setReadOnly(True)
        layout.addWidget(self.mainDisplay)

        #Container for slim text display box and text input box
        hbox = QHBoxLayout()

        #Slim text display box
        self.slim_text_display = QTextEdit()
        self.slim_text_display.setFixedHeight(50)
        self.slim_text_display.setStyleSheet("background-color: #191A2C; color: white; border-color: #B58800; border-width: 3px")
        self.slim_text_display.setReadOnly(True)
        hbox.addWidget(self.slim_text_display)

        #Text input box
        self.text_input = QLineEdit()
        self.text_input.setFixedWidth(100)
        hbox.addWidget(self.text_input)
        layout.addLayout(hbox)

        #Sniff button
        self.sniffButton = QPushButton("Start 3 second sniff")
        self.sniffButton.clicked.connect(self.handle_sniffButton)
        layout.addWidget(self.sniffButton)

        #Button 2 -- Subnet Test
        button2 = QPushButton("Subnet Test - IP Scan")
        layout.addWidget(button2)

        #Button 3
        button3 = QPushButton("Button 3")
        layout.addWidget(button3)

        #Button 4
        button4 = QPushButton("Button 4")
        layout.addWidget(button4)

        self.setLayout(layout)

#########################################################################################
#Supporting functions ->
#########################################################################################
    def handle_sniffButton(self):

        #Setting placeholder text
        self.mainDisplay.insertPlainText("Sniffing packets...\n")

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
        self.worker.packetInfo.connect(self.set_mainDisplay)

        #Start thread
        self.thread.start()
        self.sniffButton.setEnabled(False)
        self.sniffButton.setStyleSheet("background-color: #253626; border: 3px solid Yellow")
        self.thread.finished.connect(lambda: self.sniffButton.setEnabled(True))
        self.thread.finished.connect(lambda: self.sniffButton.setStyleSheet(""))



    #Setter function for main display
    def set_mainDisplay(self, string):
        self.mainDisplay.insertPlainText(string)

#Function that converts a packet object to string
def packet_group_to_string(packetGroup):
    string =""
    for packet in packetGroup:
        string = string + str(packet.summary()) + "\n"
    return string + "\n"

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

#Run main
if __name__ == "__main__":
    main()