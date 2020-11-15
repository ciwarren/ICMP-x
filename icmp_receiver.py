#Authors: Ben Kangas and Charles Warren
from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import path
import argparse

HEADER_LENGTH = 10
CHUNK_SIZE = 256
session_key = "99dbb171849cb81330244b664297225d"

# Initialize parser
parser = argparse.ArgumentParser()
 
# Adding optional argument
parser.add_argument("-p", "--Preferred_Path", help = "Path to save output files to.")
parser.add_argument("-i", "--Interface", help = "Interface to receieve on.")
# Read arguments from command line
args = parser.parse_args()
 
INTERFACE = None

if args.Preferred_Path:
    PREFERRED_PATH = args.Preferred_Path

if args.Interface:
	INTERFACE = args.Interface


def interpretConfig(file):
	file = open(file, "r")
	serverConfig = file.readlines()
	file.close()
	configDict = {}

	for x in serverConfig:
		try:
			element = x.split(":")
			key = element[0]
			value = element[1]
			configDict[key] = value

		except:
			continue
	return configDict

class Session:
	def __init__(self, session_key, ip_addr):
		self.sender_addr = ip_addr
		self.session_key = session_key.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)
		self.mode = "none"
		self.filename = "none"
		self.file = "none"
		self.current_packet = "none"
		self.message_total = "none"
		self.message_counter = 0
		self.capture = "none"

	def Set_Mode(self, value):

		data = self.current_packet[Raw].load

		if str(value) == "0x1":
			data = Decrypt_Process(data, self)
			file_vars = data.decode('utf-8')
			print(file_vars)
			file_vars = file_vars.split(":")
			self.filename = file_vars[0]
			self.message_total = file_vars[1]
			self.file = open(path.join(PREFERRED_PATH,file_vars[0]),"wb")
			self.mode = "file"

		if str(value) == "0x2":
			self.mode = "stream"

	def Message_Increment(self):
		self.message_counter += 1
		print (self.message_counter)

	def Store_File(self, message):
		self.file.write(bytes(message))
		self.file.flush()

	def Start_Session(self):
		self.capture = AsyncSniffer(filter=f"ip src {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].type==0x8 and x.haslayer(Raw) and len(x[Raw].load) >= 128, stop_filter=lambda x:x[ICMP].id == 0x3, prn= lambda x:Receive_Message(x,self), iface = INTERFACE)
		print(f"Starting session sniff of sender {self.sender_addr}")
		self.capture.start()

def Receive_Message(packet, session):
	session.current_packet = packet
	if packet.sprintf("%ICMP.id%") != "0x3":
		session.Message_Increment()
		message = Decrypt_Process(packet[Raw].load, session)
		if session.mode == "file":
			session.Store_File(bytes(message))
		if session.mode == "stream":
			print(messages)
	else:
		print(f"Stopping session with addr {session.sender_addr}")
		if session.mode == "file":
			session.file.close()

def Create_Session(packet, session_key):
	session = Session(session_key, packet[IP].src)
	session.current_packet = packet
	print(f'New transmission from {session.sender_addr}')
	session.Set_Mode(packet.sprintf("%ICMP.id%"))
	session.Start_Session()

def Decrypt_Process(data, session):
	message_header = unpad(session.cipher.decrypt(data[0:256]), CHUNK_SIZE)
	message_header = message_header.decode('utf-8')
	message_header = int(message_header.strip())
	message = unpad(session.cipher.decrypt(data[256:]), CHUNK_SIZE)
	return message
#	messages.append(message)

	if session.mode == "file":
		Store_File(bytes(message))

	if session.mode == "stream":
		print(messages)

sniff(filter=f"icmp",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].type == 0x8 and ( x[ICMP].id == 0x1 or x[ICMP].id == 0x2 ), prn= lambda x:Create_Session(x,session_key), iface= INTERFACE)