from AES_CBC_Padding_Attack import *


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom

####################
## Oracle Example ##
####################
class oracle:
	def __init__(self,key,iv):		
		assert len(key) == len(iv) == 16
		self.key = key
		self.iv  = iv

	# (only useful for demo)
	def encrypt(self,data:bytes) -> bytes:
		engine = AES.new(self.key,AES.MODE_CBC, IV=self.iv)
		return engine.encrypt(pad(data,16))
 
	def check_padding(self,data:bytes) -> bool:
		engine = AES.new(self.key,AES.MODE_CBC, IV=self.iv)
		data = engine.decrypt(data)
		# Check PKCS#7 Padding
		return data[-data[-1]:] == bytes([data[-1]])*data[-1]

iv = urandom(16)
oracle_cbc = oracle(
	key = urandom(16),
	iv  = iv
)	

####################
## Padding Attack ##
####################
cbc = Padding_Attack(
	padding_function = oracle_cbc.check_padding,
	iv = iv,
	ciphertext = oracle_cbc.encrypt(b'Hello This Is vozec !')
)

for flag in cbc.attack():
	print(flag)
