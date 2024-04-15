from NetSweep import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from scapy.all import *
import sys
import os

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
        
        #WORKING ON THIS
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
        self.text_input.setStyleSheet("background-color: #191A2C; color: white; border: black 1.5px solid;")
        hbox.addWidget(self.text_input)
        layout.addLayout(hbox)

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
        self.mainDisplay.insertPlainText(string)

#########################################################################################
#Supporting functions ->
#########################################################################################

#WORKING ON THIS
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
        self.tab1.setLayout(self.tab1.layout)
        
        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
        
    def handle_sniffButton(self):
        #Setting placeholder text
        #self.emit("Sniffing packets...\n")
        #functionStartSignal = pyqtSignal(String)

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
        

#Function that converts a packet object to string
def packet_group_to_string(packetGroup):
    string =""
    count = 0
    spacing = "     "
    for packet in packetGroup:
        count = count + 1
        if(count == 10):
            spacing = "   "
        if(count == 100):
            spacing = "  "
        if(count == 1000):
            spacing = " "
        string = string + str(count) + spacing + str(packet.summary()) + "\n"
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