# AES-CBC-Padding-attack
This tool automates and facilitates a padding attack on AES with CBC mode

# Usage :
```python
cbc = Padding_Attack(
	padding_function = oracle_cbc.check_padding,
	iv = iv,
	ciphertext = oracle_cbc.encrypt(b'Hello This Is vozec !')
)

for flag in cbc.attack():
	print(flag)
```

# Input: 
- The *padding_function* takes bytes as input and returns whether the padding of the decrypted is valid as a bool
- If the iv is given, then the tool can decrypt the first block in addition
- 
# Output:
```bash
b'\x0b'
b'\x0b\x0b'
b'\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'!\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b' !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'c !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'ec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'zec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'ozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b' vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b's vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b' Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b's Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'is Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'his Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b' This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'o This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'lo This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'llo This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'ello This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
b'Hello This Is vozec !\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
```

