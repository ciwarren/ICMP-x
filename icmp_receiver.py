#Authors: Ben Kangas and Charles Warren
from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HEADER_LENGTH = 10
CHUNK_SIZE = 256
SENDER_ADDR = "192.168.86.44"

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

class Context:
	def __init__(self, session_key):
		self.session_key = session_key.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)
		self.mode = "none"
		self.filename = "none"
		self.file = "none"
		self.last_message = "none"
		self.current_packet = "none"
		self.message_total = "none"
		self.message_counter = 0

	def Set_Mode(self, value):

		data = self.current_packet[Raw].load

		if str(value) == "0x1":
			Decrypt_Process(data)
			file_vars = self.last_message.decode('utf-8')
			print(file_vars)
			file_vars = file_vars.split(":")
			self.filename = file_vars[0]
			self.message_total = file_vars[1]
			self.file = open(self.filename,"wb")
			self.mode = "file"
			self.sender_addr = ""

		if str(value) == "0x2":
			self.mode = "stream"

	def Message_Increment(self):
		self.message_counter += 1
		print (self.message_counter)



session_key = "99dbb171849cb81330244b664297225d"
context = Context(session_key)

def Decrypt_Process(data):
	message_header = unpad(context.cipher.decrypt(data[0:256]), CHUNK_SIZE)
	message_header = message_header.decode('utf-8')
	message_header = int(message_header.strip())
	message = unpad(context.cipher.decrypt(data[256:]), CHUNK_SIZE)
	#message = str(message)
	context.last_message = message
	messages.append(message)

	if context.mode == "file":

		Store_File(bytes(message))

	if context.mode == "stream":
		print(messages)


def Receive_Message(packet):
	context.current_packet = packet

	if context.mode == "none": 
		#context.sender_addr = print(packet[IP].src) dynamic sender registration WIP
		context.Set_Mode(packet.sprintf("%ICMP.id%"))

	
	else:
		context.Message_Increment()

		data = packet[Raw].load
		Decrypt_Process(data)

def Store_File(message):
	context.file.write(bytes(message))


messages = []

while context.mode == "none":
		sniff(filter=f"icmp", count=1, prn=Receive_Message)


t = sniff(filter=f"icmp and host {SENDER_ADDR}", prn=Receive_Message, count=int(context.message_total))

context.file.close()

