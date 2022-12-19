from binascii import unhexlify,hexlify
import string


class Padding_Attack:
	def __init__(self,padding_function,ciphertext,iv=None):
		if iv:
			ciphertext = iv+ciphertext
		self.check = padding_function
		self.result = []
		self.ct = self.split_blocks(ciphertext)
		assert len(self.ct) > 1, "The Ciphertext is to short. (1 block)"

	def split_blocks(self,cnt):
		return [cnt[i*16:(i+1)*16] for i in range(len(cnt)//16)]

	def block_pad(self,x):
		return b"\x00" * (16 - (x + 1)) + b"".join([unhexlify(
				bytes(str(hex(x + 1)).split('0x')[1].zfill(2),'utf-8')
		) for _ in range(0, x + 1)])

	def attack(self):		
		for i in reversed(range(1, len(self.ct))):
			found = []
			for j in range(0, 16):
				before = found.copy()
				for k in range(0, 256):
					if k != j + 1 or (len(found) > 0 and ord(found[-1]) == k):
						bl = (15-j) * b'\x00' + bytes([k]) + b''.join(found)
						
						payload  = b''.join(
							[bytes([x^y]) for x,y in zip(
								self.block_pad(j),
								b''.join([bytes([x^y]) for x,y in zip(
									self.ct[i - 1],bl)])
						)]) + self.ct[i]	

						if self.check(payload):
							found.insert(0, bytes([bl[(16-1-j)]]))
							yield (b''.join(found)+b''.join(self.result))
							break
				assert found != before, 'Padding not found ..'
			self.result.insert(0, b"".join(found))
		return b''.join(self.result)[:-(b''.join(self.result))[-1]]