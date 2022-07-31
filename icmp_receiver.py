#Authors: Ben Kangas and Charles Warren
from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import path, getcwd
import argparse
import random
import hashlib
from math import sqrt
from tqdm import tqdm

HEADER_LENGTH = 10
CHUNK_SIZE = 256
session_key = "99dbb171849cb81330244b664297225d"
session_list=[]

# Initialize parser
parser = argparse.ArgumentParser()
 
# Adding optional argument
parser.add_argument("-p", "--Preferred_Path", help = "Path to save output files to.")
parser.add_argument("-i", "--Interface", help = "Interface to receieve on.")
parser.add_argument("-l", "--Local_Address", help = "The preferred interface's ip address.")
# Read arguments from command line
args = parser.parse_args()
 
INTERFACE = None


if args.Preferred_Path:
    PREFERRED_PATH = args.Preferred_Path

else:
	PREFERRED_PATH = getcwd()

if args.Interface:
	INTERFACE = args.Interface

if args.Local_Address:
	LOCAL_ADDRESS = args.Local_Address
else:
	LOCAL_ADDRESS = "255.255.255.255"

def Is_Prime(n):
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

def Interpret_Config(file):
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
	def __init__(self, session_id, session_key, ip_addr):
		self.session_id = session_id
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
		session_list.append({'id':self.session_id,'client':self.sender_addr})

	def Encrypt_Message(self, data):
		data = pad(data,CHUNK_SIZE)
		payload = self.cipher.encrypt(data)
		return payload

	def DH_Exchange(self):
		data = self.current_packet[Raw].load
		data = data.decode('utf-8')
		time.sleep(1)
		send(IP(dst=self.sender_addr)/ICMP(id=9,type=8,code=self.session_id)/data, verbose=False)
		diffeVars = data.split(",")
		p = int(diffeVars[0])
		g = int(diffeVars[1])

		try:
			Is_Prime(p)

		except: 
			print("Invalid Parameters Received!")

		b = random.randint(10001, 20001)
		B = (g**b) % p
		data = sniff(filter=f"icmp and src host {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and x[ICMP].id == 0x9 and x[ICMP].code == self.session_id, iface = INTERFACE, count=1)[0][Raw].load
		time.sleep(1)
		send(IP(dst=self.sender_addr)/ICMP(id=9,type=8,code=self.session_id)/str(B), verbose=False)

		
		data = data.decode('utf-8')
		A = int(data)
		s = (A**b) % p
		secret = hashlib.sha256(str(s).encode()).hexdigest()
		x = slice(32)
	
		secret = secret[x]

		self.session_key = secret.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)

	def Set_Mode(self, value):
		data = self.current_packet[Raw].load

		if value == 2:
			data = Decrypt_Process(data, self)
			if self.current_packet[ICMP].code == 0x0:
				time.sleep(1)
				print(f"Sending session id {self.session_id} to {self.sender_addr}.")
				Send_Message_Encrypted(self, data, int(value))
			file_vars = data.decode('utf-8')
			file_vars = file_vars.split(",")
			#print(file_vars)
			self.filename = file_vars[0]
			self.message_total = int(file_vars[1])
			print(f"Writing to {path.join(PREFERRED_PATH,file_vars[0])} in session {self.session_id}.")
			self.file = open(path.join(PREFERRED_PATH,file_vars[0]),"wb")
			self.mode = "file"

		if value == 3:
			data = Decrypt_Process(data, self)
			file_vars = data.decode('utf-8')
			file_vars = file_vars.split(",")
			#print(file_vars)
			self.filename = file_vars[0]
			self.message_total = int(file_vars[1])
			print(f"Writing to {path.join(PREFERRED_PATH,file_vars[0])} in session {self.session_id}.")
			self.file = open(path.join(PREFERRED_PATH,file_vars[0]),"wb")
			self.mode = "one-way-file"
			if self.current_packet[ICMP].code == 0x0:
				time.sleep(1)


		if value == 8:
			self.DH_Exchange()
			print(f"Negotiated session {self.session_id} key.")
			self.current_packet = sniff(filter=f"icmp and src host {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and x[ICMP].code == self.session_id and (x[ICMP].id == 0x2 or x[ICMP].id == 0x3)  , iface = INTERFACE, count=1)[0]
			self.Set_Mode(self.current_packet[ICMP].id)


	def Check_Sequence(self, received_sequence, expected_sequence):
		if received_sequence == expected_sequence:
			self.sequence_number = received_sequence
			return True
		else:
			print(f"Received sequence {received_sequence} from {self.sender_addr} but expected sequence {expected_sequence}")
			return False

	def Store_File(self, message):
		self.file.write(bytes(message))
		self.file.flush()

	def Start_Session(self):
		#self.progress_bar = tqdm(total=self.message_total,desc=f"Transfer {self.filename} from {self.sender_addr} session {self.session_id}")
		self.capture = AsyncSniffer(filter=f"ip src {self.sender_addr}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].type==0x8 and x[ICMP].code == self.session_id, stop_filter=lambda x:x[ICMP].id == 0x4, prn= Receive_Message(self), iface = INTERFACE)
		self.capture.start()

def Send_Message_Encrypted(session, message, control_code):
	message = session.Encrypt_Message(message)
	send(IP(dst=session.sender_addr)/ICMP(type=8,id=control_code,code=session.session_id)/message, verbose=False)


def Receive_Message(session):
	def Process_Message(packet):
		#print(f"{session.sender_addr}:{session.filename}:{packet[ICMP].seq}")
		session.current_packet = packet
		if session.mode == "one-way-file":
			message = Decrypt_Process(packet[Raw].load, session)
			#session.progress_bar.update()
			session.Store_File(bytes(message))

		elif packet[ICMP].id != 4:
			if session.Check_Sequence(packet[ICMP].seq, session.sequence_number+1):
				message = Decrypt_Process(packet[Raw].load, session)
				#session.progress_bar.update()
				session.Store_File(bytes(message))
			else:
				send(IP(dst=session.sender_addr)/ICMP(type=8,id=5,code=session.session_id,seq=session.sequence_number+1),verbose=False)
		else:
			#session.progress_bar.close()
			print(f"Closing session {session.session_id} with sender {session.sender_addr}")
			if session.mode == "file":
				session.file.close()
			session_list.remove({'id':session.session_id,'client':session.sender_addr})
	return Process_Message

def Create_Session(packet, session_key):
	session_id = random.randint(1,255)
	if packet[ICMP].id == 3:
		session_id = 0
	else:
		while session_id in session_list:
			session_id = random.randint(1,255)

	session = Session(session_id, session_key, packet[IP].src)
	session.current_packet = packet
	print(f'Created session {session.session_id} with {session.sender_addr}')
	print(f"Current sessions: {session_list}")
	session.Set_Mode(packet[ICMP].id)
	session.Start_Session()

def Decrypt_Process(data, session):
	data = session.cipher.decrypt(data)
	message = unpad(data, CHUNK_SIZE)
	return message

sniff(filter=f"icmp and src host not {LOCAL_ADDRESS}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].type == 0x8 and ( x[ICMP].id == 0x2 or x[ICMP].id == 0x3 or x[ICMP].id == 0x8 ) and x[ICMP].code == 0x0 , prn= lambda x:Create_Session(x,session_key), iface= INTERFACE)
