#Authors: Ben Kangas and Charles Warren

from scapy.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import getrandbits
import argparse
import time
import random
import hashlib
from math import sqrt

CHUNK_SIZE = 256
DATA_SIZE = CHUNK_SIZE - 1

 
# Initialize parser
parser = argparse.ArgumentParser()
 
# Adding optional argument
parser.add_argument("-p", "--Peer", help = "IP address of receiving host -ex 192.168.1.1")
parser.add_argument("-m", "--Mode", help = "Operation mode, 'file' or 'stream'. Defaults to file.") 
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
	def __init__(self, session_key, code):
		self.session_key = session_key.encode('utf-8')
		self.cipher = AES.new(self.session_key, AES.MODE_ECB)
		self.last_message = "none"
		self.mode = "none"
		self.id = "none"
		self.file_length = "none"
		self.sequence_number = 0x0
		self.code = code

	def Encrypt_Message(self, data):
		data = pad(data,CHUNK_SIZE)
		payload = self.cipher.encrypt(data)
		return payload

	def Set_Mode(self,mode):
		self.mode = mode
		print(mode)
		if self.mode == "file":
			self.id = 1
			Send_Message_Encrypted(f'{filename}:{(self.file_length // DATA_SIZE)}'.encode('utf-8'))
			self.id = 0


		if self.mode == "stream":
			self.id = 2
			Send_Message_Encrypted("Hello")
			self.id = 0

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
	
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=8)/message, verbose=True)
	a = random.randint(0, 10000)
	A = (g**a) % p 
	
	time.sleep(1)

	send(IP(dst=DESTINATION_ADDR)/ICMP(id=9, code=1)/str(A), verbose=True)
	data = sniff(filter=f"icmp and src host {DESTINATION_ADDR}",lfilter=lambda x:x.haslayer(IP) and x.haslayer(ICMP) and x.haslayer(Raw) and x[ICMP].type == 0x8 and x[ICMP].id == 0x9 , count=1)[0][Raw].load
	data = data.decode('utf-8')
	B = int(data)
	s = (B**a) % p
	
	print(s)

	secret = hashlib.sha256(str(s).encode()).hexdigest()
	x = slice(32)
	secret = secret[x]
	time.sleep(1)

	return secret


def Send_Message_Encrypted(message):
	message = context.Encrypt_Message(message)
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=context.id,seq=context.sequence_number,code=context.code) /message, verbose=False)
	print(f"Sent packet with id {context.id} and sequence {context.sequence_number}")
	context.sequence_number += 0x1



def Send_File(file):
	x_previous = 0 
	print(len(file))
	for x in range(DATA_SIZE,len(file),DATA_SIZE):
		file_segment = file[x_previous:x]
		#print(f'{str(x)} of {str(len(file))} is: {file_segment}')
		Send_Message_Encrypted(file_segment)
		time.sleep(.001)
		x_previous = x

	file_segment = file[x_previous:]
	#print(f'{str(x)} of {str(len(file))} is: {file_segment}')
	Send_Message_Encrypted(file_segment)
	time.sleep(.01)
	print(f"Closing session with destination {DESTINATION_ADDR}.")
	send(IP(dst=DESTINATION_ADDR)/ICMP(id=3,seq=context.sequence_number), verbose=False)



if Key_Type == "dynamic":
	session_key = DH_Exchange()
	code = 1

else:
	session_key = "99dbb171849cb81330244b664297225d"
	code = 0

context = Context(session_key, code)


if mode == "file":
	try:
		file = open(filename, 'rb')

	except:
		print("file not found")
	file = file.read()
	context.file_length = len(file)
	context.Set_Mode("file")
	Send_File(file)

if mode == "stream":
	context.Set_Mode("stream")
	print
