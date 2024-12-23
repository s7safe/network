import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QListWidget
from PyQt5.QtCore import Qt
import scapy.all as scapy
import socket

class NetworkScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('局域网设备管理和唤醒')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.ipInput = QLineEdit(self)
        self.ipInput.setPlaceholderText('请输入当前IP地址')
        layout.addWidget(self.ipInput)
        
        self.scanButton = QPushButton('扫描设备', self)
        self.scanButton.clicked.connect(self.scanNetwork)
        layout.addWidget(self.scanButton)
        
        self.deviceList = QListWidget(self)
        layout.addWidget(self.deviceList)
        
        self.wakeButton = QPushButton('唤醒设备', self)
        self.wakeButton.clicked.connect(self.wakeDevice)
        layout.addWidget(self.wakeButton)
        
        # Add a status label to display messages
        self.statusLabel = QLabel('', self)
        layout.addWidget(self.statusLabel)
        
        self.setLayout(layout)
        
    def scanNetwork(self):
        ip = self.ipInput.text()
        if not ip:
            self.statusLabel.setText('请输入有效的IP地址')
            return
        
        self.statusLabel.setText('正在扫描...')
        ip_range = ip + '/24'
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        self.deviceList.clear()
        for element in answered_list:
            device_info = f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}"
            self.deviceList.addItem(device_info)
        
        self.statusLabel.setText('扫描完成')
    
    def wakeDevice(self):
        selected_item = self.deviceList.currentItem()
        if not selected_item:
            self.statusLabel.setText('请选择一个设备')
            return
        
        device_info = selected_item.text()
        mac_address = device_info.split(', ')[1].split(': ')[1]
        
        def send_magic_packet(mac):
            mac_bytes = bytes.fromhex(mac.replace(':', ''))
            magic_packet = b'\xff' * 6 + mac_bytes * 16
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, ('<broadcast>', 9))
        
        send_magic_packet(mac_address)
        self.statusLabel.setText('唤醒信号已发送')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle("windows")  # 设置 Windows 主题样式
    ex = NetworkScanner()
    ex.show()
    sys.exit(app.exec_())