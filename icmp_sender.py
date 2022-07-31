#Authors: Ben Kangas and Charles Warren

from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import getrandbits
from os import path
import argparse
import time
import random
import hashlib
from math import sqrt
from tqdm import tqdm 

CHUNK_SIZE = 256
DATA_SIZE = CHUNK_SIZE - 1

 
# Initialize parser
parser = argparse.ArgumentParser()
 
# Adding optional argument
parser.add_argument("-p", "--Peer", help = "IP address of receiving host -ex 192.168.1.1")
parser.add_argument("-m", "--Mode", help = "Operation mode, 'file', 'one-way-file'. Defaults to file.", default="file") 
parser.add_argument("-f", "--Filename", help = "File to transfer. Used with 'file' mode.")
parser.add_argument("-k", "--Key_Type", help = "dynamic or static")
# Read arguments from command line
args = parser.parse_args()
 
if args.Peer:
    DESTINATION_ADDR = args.Peer
if args.Mode:
	mode = args.Mode
if args.Filename:
	filename = args.Filename
if args.Key_Type:
	Key_Type = args.Key_Type

#Referred to as context
class Context:
	def __init__(self, session_id, session_key):
		self.session_id = session_id
		self.session_key = session_key.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)
		self.last_message = "none"
		self.mode = "none"
		self.control_code = 0
		self.file_length = "none"
		self.sequence_number = 0x1
		self.sequence_target = 0
		self.sequence_update = "none"
		self.previous_sequence=0

	def Encrypt_Message(self, data):
		data = pad(data,CHUNK_SIZE)
		payload = self.cipher.encrypt(data)
		return payload

	def Set_Mode(self,mode):
		self.mode = mode
		if self.mode == "file":
			self.control_code = 2
			mode_message = f'{base_filename},{(self.file_length // DATA_SIZE)}'

		if self.mode == "one-way-file":
			self.control_code = 3
			mode_message = f'{base_filename},{(self.file_length // DATA_SIZE)}'

		Send_Message_Encrypted(mode_message.encode("utf-8"))

		if self.session_id == 0 and self.control_code == 2:
			while self.session_id == 0:
				print("Waiting for Session ID")
				mode_response = sniff(filter=f"icmp and src host {DESTINATION_ADDR}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8, count=1)[0]
				if Decrypt_Process(mode_response[Raw].load, self) == mode_message.encode("utf-8"):
					self.session_id = mode_response[ICMP].code
				
			print(f"Assigned session id {self.session_id}.")
		time.sleep(3)




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

def Gen_Prime(min, max):
	primes = [i for i in range(min,max) if Is_Prime(i)]
	p = random.choice(primes)
	return p

def Find_Prime_Factors(s, n) : 
  
    # Print the number of 2s that divide n  
    while (n % 2 == 0) : 
        s.add(2)  
        n = n // 2
  
    # n must be odd at this po. So we can   
    # skip one element (Note i = i +2)  
    for i in range(3, int(sqrt(n)), 2): 
          
        # While i divides n, print i and divide n  
        while (n % i == 0) : 
  
            s.add(i)  
            n = n // i  
          
    # This condition is to handle the case  
    # when n is a prime number greater than 2  
    if (n > 2) : 
        s.add(n) 

def Find_Primitive( n) : 
    s = set()  

    # Check if n is prime or not  
    if (Is_Prime(n) == False):  
        return -1
  
    # Find value of Euler Totient function  
    # of n. Since n is a prime number, the  
    # value of Euler Totient function is n-1  
    # as there are n-1 relatively prime numbers. 
    phi = n - 1
  
    # Find prime factors of phi and store in a set  
    Find_Prime_Factors(s, phi)  
  
    # Check for every number from 2 to phi  
    for r in range(2, phi + 1):  
  
        # Iterate through all prime factors of phi.  
        # and check if we found a power with value 1  
        flag = False
        for it in s:  
  
            # Check if r^((phi)/primefactors) 
            # mod n is 1 or not  
            if (pow(r, phi // it, n) == 1):  
  
                flag = True
                break
              
        # If there was no power with value 1.  
        if (flag == False): 
            return r  
  
    # If no primitive root found  
    return -1

def DH_Exchange():
	min = 100000
	max = 999999
	p = Gen_Prime(min, max)
	g = Find_Primitive(p)
	message =  f'{p},{g}'
	
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=8)/message, verbose=False)
	a = random.randint(0, 10000)
	A = (g**a) % p 
	session_id = sniff(filter=f"icmp and src host {DESTINATION_ADDR}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and x[ICMP].id == 0x9  and x[Raw].load == bytes(message.encode("utf-8")), count=1)[0][ICMP].code
	print(f"Assigned session id {session_id}")
	time.sleep(.5)
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=9, code=session_id)/str(A), verbose=False)
	data = sniff(filter=f"icmp and src host {DESTINATION_ADDR}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and x[ICMP].id == 0x9 and x[ICMP].code == session_id, count=1)[0][Raw].load
	data = data.decode('utf-8')
	B = int(data)
	s = (B**a) % p
	
	#print(s)

	secret = hashlib.sha256(str(s).encode()).hexdigest()
	x = slice(32)
	secret = secret[x]
	time.sleep(1)
	return [session_id,secret]


def Send_Message_Encrypted(message):
	message = context.Encrypt_Message(message)
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=context.control_code,seq=context.sequence_number,code=context.session_id) /message, verbose=False)
	print(f"Sent packet with id {context.session_id} and sequence {context.sequence_number}, and control_code {context.control_code}")

def Update_Sequence(context):
	def Read_Sequence(packet):
		context.sequence_update = packet[ICMP].seq
		print(f"Server requested retransmit starting at sequence {context.sequence_update}")
	return Read_Sequence
	
def Send_File(file):
	sequence_sniffer = AsyncSniffer(filter=f"icmp and src host {DESTINATION_ADDR}",lfilter=lambda x: x.haslayer(IP) and x.haslayer(ICMP) and x[ICMP].code == context.session_id and x[ICMP].id==0x5,prn=Update_Sequence(context))
	sequence_sniffer.start()
	print(context.sequence_target)
	progress = tqdm(total=context.sequence_target, desc=f"Transfer {base_filename} to {DESTINATION_ADDR} session {context.session_id}")
	while context.sequence_number <= context.sequence_target:
		if context.sequence_number < context.sequence_target:	
			file_segment = file[(context.sequence_number-1)*DATA_SIZE:context.sequence_number*DATA_SIZE]
		else:
			file_segment = file[(context.sequence_number-1)*DATA_SIZE:]
		Send_Message_Encrypted(file_segment)
		if context.sequence_update != "none":
			context.sequence_number = context.sequence_update
			time.sleep(1)
			context.sequence_update = "none"
		else:
			context.sequence_number += 1
		time.sleep(.001)
		progress.update(context.sequence_number-context.previous_sequence)
		context.previous_sequence = context.sequence_number
		pass
	time.sleep(3)
	progress.update(context.sequence_target)
	progress.close()
	print(f"Closing session {context.session_id} with destination {DESTINATION_ADDR}.")
	sequence_sniffer.stop()
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=4,seq=context.sequence_number,code=context.session_id), verbose=False)

def Send_One_Way(file):
	print(context.session_id)
	context.control_code = 0
	progress = tqdm(total=context.sequence_target, desc=f"Transfer {base_filename} to {DESTINATION_ADDR} session {context.session_id}")
	print(context.sequence_target)
	while context.sequence_number <= context.sequence_target:
		if context.sequence_number < context.sequence_target:	
			file_segment = file[(context.sequence_number-1)*DATA_SIZE:context.sequence_number*DATA_SIZE]
		else:
			file_segment = file[(context.sequence_number-1)*DATA_SIZE:]
		Send_Message_Encrypted(file_segment)
		context.sequence_number += 1
		time.sleep(.001)
		progress.update(context.sequence_number-context.previous_sequence)
		context.previous_sequence = context.sequence_number

	time.sleep(3)
	progress.update(context.sequence_target)
	progress.close()
	print(f"Closing session {context.session_id} with destination {DESTINATION_ADDR}.")
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=4,seq=context.sequence_number,code=context.session_id), verbose=False)

def Decrypt_Process(data, session):
	data = session.cipher.decrypt(data)
	message = unpad(data, CHUNK_SIZE)
	return message

if Key_Type == "dynamic":
	print(f"Negotiating session details with {DESTINATION_ADDR}.")
	session_details = DH_Exchange()
	session_id = session_details[0]
	session_key = session_details[1]

else:
	session_id = 0
	session_key = "99dbb171849cb81330244b664297225d"

context = Context(session_id,session_key)


if mode == "file":
	try:
		file = open(filename, 'rb')
		base_filename = path.basename(filename)
	except:
		print("file not found")
	file = file.read()
	context.file_length = len(file)
	context.sequence_target = (context.file_length // DATA_SIZE) + 1
	print(f"Starting session {context.session_id} with {DESTINATION_ADDR} in {mode} mode.")
	context.Set_Mode("file")
	Send_File(file)

if mode == "stream":
	print(f"Starting session {context.session_id} with {DESTINATION_ADDR} in {mode} mode.")
	context.Set_Mode("stream")
	print('STREAM')

if mode == "one-way-file":
	try:
		file = open(filename, 'rb')
		base_filename = path.basename(filename)
	except:
		print("file not found")
	
	file = file.read()
	context.file_length = len(file)
	context.sequence_target = (context.file_length // DATA_SIZE) + 1
	print(f"Starting session {context.session_id} with {DESTINATION_ADDR} in {mode} mode.")
	context.Set_Mode("one-way-file")
	Send_One_Way(file)

