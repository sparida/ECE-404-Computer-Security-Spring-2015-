"""
HW #: HW 1 Problem 1 (ECE 404 Spring 2015)
Name: Sthitapragyan Parida
ECN Login: sparida
Due Date: 1/22/2015

Python Version: 2.7
To execute script:
python cipher.py

Note: 
1. The following cipher used the complete set of alphabets from a-z and A-Z for the key and distinguishes between case.
2. Therefore the look up table has a size of 52 * 52 entries.
3. All characters other than alphabets are ignored.
4. Non-alphabets in key are overlooked
5. Non-alphabets in plaintext are added to ciphertext as is
"""

# Vigenere class to handle cipher
class Vigenere():
	def __init__(self, key=None):
		self.key = key # Key
		self.key_set = False # Test variable for whetehr key is set
		
		# List of all alphabets from a - z and A - Z
		self.char_set = list(map(chr, range(ord('a'), ord('z') + 1))) + list(map(chr, range(ord('A'), ord('Z') + 1)))
		if self.key != None:
			self.key_set = True
	# Sets a key	
	def setKey(self, key=None):
		self.key = key
		self.key_set = False
		if self.key != None:
			self.key_set = True
	
	# Encrypts plaintext
	def encrypt(self, plaintext=None):
		if plaintext != None and self.key_set == True:
			cipher_text = ""
			key_index = 0 # Initial key index
			for c in plaintext:
				# If plaintext character is an alphabet, encrypt it, otherwise add it as it is
				if c in self.char_set:
					# The while loop ensures that only alphabets in the key are used for encryption
					while(self.key[key_index] not in self.char_set):
						key_index = (key_index + 1) % len(self.key)
						
					# Index of cipher text character in char set
					c_index = (self.char_set.index(c) + self.key.index(self.key[key_index])) % len(self.char_set) 
					cipher_c = self.char_set[c_index]
					cipher_text = cipher_text + cipher_c

					# Ensures key is looped circularly
					key_index = (key_index + 1) % len(self.key) 
				else:
					cipher_text = cipher_text + c # For non alphabetical plaintext characters 
			return cipher_text
		else:
			return None

	# Decrypts ciphertext
	def decrypt(self, ciphertext=None):
		if ciphertext != None and self.key_set == True:
			plain_text = ""
			key_index = 0
			for c in ciphertext:
				# If cipher text character is an alphabet, decrypt it, otherwise add it as it is
				if c in self.char_set:
					# The while loop ensures that only alphabets in the key are used for encryption
					while(self.key[key_index] not in self.char_set):
						key_index = (key_index + 1) % len(self.key)

					# Index of cipher text character in char set
					c_index = (self.char_set.index(c) - self.key.index(self.key[key_index])) % len(self.char_set) 
					plain_c = self.char_set[c_index]
					plain_text = plain_text + plain_c

					# Ensures key is looped circularly
					key_index = (key_index + 1) % len(self.key)
				else:
					plain_text = plain_text + c # For non alphabetical ciphertext characters
			return plain_text
		else:
			return None

def main():
	
	#Read key file
	with open ("key.txt", "r") as f:
		key = f.read()

	#Read input file
	with open ("input.txt", "r") as f:
		p_text = f.read()

	#Create object of Vigenere class to implement cipher 
	v = Vigenere(key)
	
	#Encrypt plaintext and write cipher text to output file
	c_text = v.encrypt(p_text)
	with open("output.txt", "w") as f:
		f.write("%s" % c_text)

	#For testing purposes, uncomment lines to test
	#Decrypt ciphertext and write plain text to test output file
	#dp_text = v.decrypt(c_text)
	#with open("testoutput.txt", "w") as f:
	#f.write("%s" % dp_text)
	
if __name__ == '__main__':
	main()
	
