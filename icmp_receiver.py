#Authors: Ben Kangas and Charles Warren
from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import path
import argparse
import random
import hashlib
from math import sqrt

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

def isPrime(n):
	if n == 2 or n == 3: return True
	if n < 2 or n%2 == 0: return False
	if n < 9: return True
	if n%3 == 0: return False
	r = int(n**0.5)
	f = 5
	while f <= r:
		if n%f == 0: return False
		if n%(f+2) == 0: return False
		f +=6
	return True

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
		self.sequence_number = 0x0

	def DH_Exchange(self):
		data = self.current_packet[Raw].load
		data = data.decode('utf-8')
		diffeVars = data.split(",")
		p = int(diffeVars[0])
		g = int(diffeVars[1])

		try:
			isPrime(p)

		except: 
			print("Invalid Parameters Received!")

		b = random.randint(10001, 20001)
		B = (g**b) % p

		send(IP(dst=self.sender_addr)/ICMP(id=9)/str(B), verbose=False)

		data = sniff(filter=f"icmp and src host {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and x[ICMP].id == 0x9 , iface = INTERFACE, count=1)[0][Raw].load
		data = data.decode('utf-8')
		A = int(data)
		s = (A**b) % p
		print(s)
		secret = hashlib.sha256(str(s).encode()).hexdigest()
		x = slice(32)
	
		secret = secret[x]

		self.session_key = secret.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)

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

		if str(value) == "0x9":
			self.DH_Exchange()
			self.current_packet = sniff(filter=f"icmp and src host {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and (x[ICMP].id == 0x2 or x[ICMP].id == 0x3)  , iface = INTERFACE, count=1)[0]
			self.Set_Mode(self.current_packet.sprintf("%ICMP.id%"))

	
		

	def Check_Sequence(self, received_sequence, expected_sequence):
		if received_sequence == expected_sequence:
			self.sequence_number = received_sequence
		else:
			print(f"Received sequence {received_sequence} from {self.sender_addr} but expected sequence {expected_sequence}")

	def Store_File(self, message):
		self.file.write(bytes(message))
		self.file.flush()

	def Start_Session(self):
		self.capture = AsyncSniffer(filter=f"ip src {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].type==0x8, stop_filter=lambda x:x[ICMP].id == 0x3, prn= Receive_Message(self), iface = INTERFACE)
		print(f"Starting session sniff for sender {self.sender_addr}")
		self.capture.start()

def Receive_Message(session):
	def Process_Message(packet):
		print(f"{session.sender_addr}:{session.filename}:{packet[ICMP].seq}")
		session.current_packet = packet
		if packet.sprintf("%ICMP.id%") != "0x3":
			session.Check_Sequence(packet[ICMP].seq, session.sequence_number+1)
			message = Decrypt_Process(packet[Raw].load, session)
			if session.mode == "file":
				session.Store_File(bytes(message))
			if session.mode == "stream":
				print(messages)
		else:
			print(f"Closing session with sender {session.sender_addr}")
			if session.mode == "file":
				session.file.close()
	return Process_Message

def Create_Session(packet, session_key):
	session = Session(session_key, packet[IP].src)
	session.current_packet = packet
	print(f'New transmission from {session.sender_addr}')
	session.Set_Mode(packet.sprintf("%ICMP.id%"))
	session.Start_Session()

def Decrypt_Process(data, session):
	data = session.cipher.decrypt(data)
	message = unpad(data, CHUNK_SIZE)
	return message

sniff(filter=f"icmp",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].type == 0x8 and ( x[ICMP].id == 0x1 or x[ICMP].id == 0x2 or x[ICMP].id == 0x9 ), prn= lambda x:Create_Session(x,session_key), iface= INTERFACE)
