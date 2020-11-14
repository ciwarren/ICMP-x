#Authors: Ben Kangas and Charles Warren

from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import time

HEADERLENGTH = 10
CHUNK_SIZE = 256
DESTINATION_ADDR = "192.168.86.42"

#Referred to as context
class Context:
	def __init__(self, session_key):
		self.session_key = session_key.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)
		self.last_message = "none"
		self.mode = "none"
		self.id = "none"
		self.file_length = "none"

	def Encrypt_Message(self, data):
		print(len(data))
		data = pad(data,CHUNK_SIZE)
		payload = self.cipher.encrypt(data)
		return payload

	def Set_Mode(self,mode):
		self.mode = mode

		if self.mode == "file":
			self.id = 1
			Send_Message_Encrypted(f'{sys.argv[2]}:{(self.file_length // 32)}'.encode('utf-8'))
			self.id = 0


		if self.mode == "stream":
			self.id = 2
			Send_Message_Encrypted("Hello")
			self.id = 0

		time.sleep(3)

session_key = "99dbb171849cb81330244b664297225d"
context = Context(session_key)

def Send_Message_Encrypted(message):
	#message = str(message)
	message 
	message = context.Encrypt_Message(message)
	message_header = context.Encrypt_Message(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'))
	payload = message_header + message
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=context.id)/payload)


def Send_File(file):
	x_previous = 0 
	print(len(file))
	for x in range(32,len(file)+(len(file)%32),32):
		file_segment = file[x_previous:x]
		print(file_segment)
		Send_Message_Encrypted(file_segment)
		time.sleep(.01)
		x_previous = x

	send(IP(dst=DESTINATION_ADDR)/ICMP(id=3))

mode = sys.argv[1]

print(mode)

if mode == "file":
	try:
		file = open(sys.argv[2], 'rb')

	except:
		print("file not found")
	file = file.read()
	context.file_length = len(file)
	context.Set_Mode("file")
	Send_File(file)

if mode == "stream":
	context.Set_Mode("stream")
	print