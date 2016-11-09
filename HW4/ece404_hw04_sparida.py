#!/usr/bin/env python

#HW #: HW 4(AES) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 2/17/2015
### ece404_hw04_sparida.py

from copy import deepcopy
from BitVector import BitVector

modulus = BitVector(bitstring = '100011011')
n = 8
##########################CODE FOR GENERATING THE LOOKUP TABLES##########################################################
def getEncryptionSubBox():
	sbox = [[0 for i in range(16)] for j in range(16)]
	modulus = BitVector(bitstring = '100011011')
	n = 8
	c = BitVector(bitstring = '01100011')   
	for i in range(16):
		for j in range(16):
			if i == 0 and j == 0:
				bv = BitVector(bitstring = '00000000')
				sbox[i][j] = bv
			else:
				i_s = bin(i)[2:].zfill(4)
				j_s = bin(j)[2:].zfill(4)
				bv = BitVector(bitstring = i_s + j_s)
				sbox[i][j] = bv
				sbox[i][j] = bv.gf_MI(modulus, n)
			sboxt = sbox[i][j].deep_copy()
			for k in range(8):
				sbox[i][j][k] = sboxt[k]^sboxt[(k-4)%8]^sboxt[(k-5)%8]^sboxt[(k-6)%8]^sboxt[(k-7)%8]^c[k]
			sbox[i][j] = sbox[i][j].get_hex_string_from_bitvector()
	
	return sbox

def getDecryptionSubBox():
	dbox = [[0 for i in range(16)] for j in range(16)]
	modulus = BitVector(bitstring = '100011011')
	n = 8
	d = BitVector(bitstring = '00000101')   
	for i in range(16):
		for j in range(16):
			i_s = bin(i)[2:].zfill(4)
			j_s = bin(j)[2:].zfill(4)
			bv = BitVector(bitstring = i_s + j_s)
			dboxt = bv.deep_copy()
			for k in range(8):
				bv[k] = dboxt[(k-2)%8]^dboxt[(k-5)%8]^dboxt[(k-7)%8]^d[k]
			if bv.get_hex_string_from_bitvector() != '00':
				dbox[i][j] = bv.gf_MI(modulus, n)
			else:
				dbox[i][j] = BitVector(bitstring = '00000000')
			dbox[i][j] = dbox[i][j].get_hex_string_from_bitvector()

	return dbox

#############Call Functions#####################################################
sbox = getEncryptionSubBox()
dbox = getDecryptionSubBox()
###########################################KEY SCHEDULING###################################################################

#Implements the G function using during scheduling
def g(word, i):
	[left, right] = word.divide_into_two()
	[b1, b2] = left.divide_into_two()
	[b3, b4] = right.divide_into_two()
	# b2 b3 b4 b1
	a1 = lookUpBox(b2, 'e') ^ roundConst(i/4)
	a2 = lookUpBox(b3, 'e')
	a3 = lookUpBox(b4, 'e')
	a4 = lookUpBox(b1, 'e')
	return (a1 + a2 + a3 + a4)

# Supplies the round constant for each round of scheduling
def roundConst(i):
	if i == 1:
		return BitVector(bitstring = '00000001')
	else:
		return BitVector(bitstring = '00000010').gf_multiply_modular(roundConst(i - 1), modulus, n)

# Looks up the proper lookup table to find teh inverse in GF(2^8) 
def lookUpBox(b, m):
	[left, right] = b.divide_into_two()
	r = int(str(left), 2)	
	c = int(str(right), 2)
	if m == 'e':
		return BitVector(hexstring = sbox[r][c])
	elif m == 'd':
		return BitVector(hexstring = dbox[r][c])

# Schedules the 44 round keys for 128 bit encryption using Rjindal algorithm
def getRoundKeys(key):
	
	bv_key = BitVector(textstring = key)
	kw = [BitVector(size = 0) for i in range(44)]
	[l, r] = bv_key.divide_into_two()
	[kw[0], kw[1]] = l.divide_into_two()
	[kw[2], kw[3]] = r.divide_into_two()

	for i in range(4, 41, 4):
		kw[i] = kw[i-4] ^ g(kw[i-1], i)
		kw[i+1] = kw[i]   ^ kw[i-3]
		kw[i+2] = kw[i+1] ^ kw[i-2]
		kw[i+3] = kw[i+2] ^ kw[i-1]
	return kw

# The Keys are now available as 44 words from kw[0] to kw[43] - Check
############################################################################################################################

#####################Functions for individual steps for eac round of processing in AES######################################

# Reads bits from a textfile in block of 128 each
def getBlocksFromText(fn):
	blocks = []
	bv = BitVector(filename = fn)
	c = 0
	while (bv.more_to_read or (c == 0)):
		bitvec = bv.read_bits_from_file(128) 
		bitvec.pad_from_right(128 - len(bitvec))
	    	blocks = blocks + [bitvec]
	    	c = 1
	return blocks

# Read bits into blocks of 128 and create state arrays from a hexstring
def getCipherSASFromHexFile(hexfile):
	cipher_sas = []
	hf = open(hexfile, 'r')
	h_str = hf.read()
	hf.close()
	for i in range(len(h_str)/32):
		hex_str = h_str[i*32: (i+1)*32]
		bv = BitVector(hexstring = hex_str)
		sa = getStateArray(bv) 
		cipher_sas = cipher_sas + [sa]
	return cipher_sas
		

def writeToFile(filename, text):
	f = open(filename, 'w')
	f.write("%s" % text)
	f.close()
	
# Take a BitVector object of lenght 128 and breaks it down into a 4 by 4 byte state array
def getStateArray(block):
	state_array = [[BitVector(size = 0) for i in range(4)] for j in range(4)]
	for i in range(4):
		for j in range(4):
			start = 8 * i + 32 * j
			state_array[i][j] = BitVector(bitstring = str(block[start:(start+8)]))
	return state_array

# Converts a state array into 4 words with each column resulting in a word
def conSATo4Words(sa):
	return [ (sa[0][0]+sa[1][0]+sa[2][0]+sa[3][0]), (sa[0][1]+sa[1][1]+sa[2][1]+sa[3][1]), (sa[0][2]+sa[1][2]+sa[2][2]+sa[3][2]), (sa[0][3]+sa[1][3]+sa[2][3]+sa[3][3]) ]

# Converst 4 words into a 4 by 4 state array
def con4WordsToSA(fw):
	state_array = [[BitVector(size = 0) for i in range(4)] for j in range(4)]
	for i in range(4):
			state_array[0][i] = BitVector(bitstring = str(fw[i][0:8]))
			state_array[1][i] = BitVector(bitstring = str(fw[i][8:16]))
			state_array[2][i] = BitVector(bitstring = str(fw[i][16:24]))
			state_array[3][i] = BitVector(bitstring = str(fw[i][24:32]))
	return state_array

# Rotates a given list circularly by the specified number of steps 
def rotate(l, n):
	return l[-n:] + l[:-n]

# Implements Shift Row Step On StateArray - Check
def shiftRows(sa, step):
	c = 1 if (step == 'e') else -1
	for i in range(4):
		sa[i] = rotate(sa[i], c * -i)
	return sa

# Implements Substitute Byte Step On StateArray- Check			
def SingleByteSub(sa, step):
	for i in range(4):
		for j in range(4):
			sa[i][j] = lookUpBox(sa[i][j] , step)
	return sa

# Implements Mix Columns Step On StateArray- Check
def mixColumns(sa, step):
	if step == 'e':
		ma = [BitVector(bitstring = '00000010'), BitVector(bitstring = '00000011'), BitVector(bitstring = '00000001'), BitVector(bitstring = '00000001')]
	elif step == 'd':
		ma = [BitVector(bitstring = '00001110'), BitVector(bitstring = '00001011'), BitVector(bitstring = '00001101'), BitVector(bitstring = '00001001')]
	sat= deepcopy(sa)
	for r in range(4):
		mr = rotate(ma, r)
		for c in range(4):
			res = BitVector(bitstring = '00000000')
			for k in range(4):
				l = mr[k].gf_multiply_modular(sat[k][c], modulus, n)
				res = res ^ l
			sa[r][c] = res
	return sa	

# Adds Round Key to State Array - Check		
def addRoundKeys(sa, step, r):
	if step == 'e':
		rk = kw[(r)*4: (r+1)*4]
	elif step == 'd':
		rk = kw[(44 - ((r+1)*4)): (44 - ((r)*4))]
		
	fw = conSATo4Words(sa)
	for i in range(4):	
		fw[i] = fw[i] ^ rk[i]
	sa = con4WordsToSA(fw)
	return sa

# Return entire cipher as eitehr hex or text
def printCipher(cipher_sas, mode = 't'):
	s = ""
	for sa in cipher_sas:
		for c in range(4):
			for r in range(4):
				if mode == 't':
					s = s + sa[r][c].get_text_from_bitvector()
				elif mode == 'h':	
					s = s + sa[r][c].get_hex_string_from_bitvector()
	return s

# Test Functions sa should stay the same even after all operations
"""
plainblocks = getBlocksFromText('plaintext.txt')
sa = getStateArray(plainblocks[0])
fw = conSATo4Words(sa)
sa = con4WordsToSA(fw)
sa = SingleByteSub(sa, 'e')
sa = SingleByteSub(sa, 'd')
sa = shiftRows(sa, 'e')
sa = shiftRows(sa, 'd')
sa = mixColumns(sa, 'e')
sa = mixColumns(sa, 'd')
sa = addRoundKeys(sa, 'e', 1)
sa = addRoundKeys(sa, 'd', 9)

# Print plaintext
print "Plaintext:"
s = ""
for pb in plainblocks:
	sa = getStateArray(pb)
	for c in range(4):
		for r in range(4):
			s = s + sa[r][c].get_text_from_bitvector()
print s
"""

#############################SCHEDULE KEYs#####################################################################
key = "lukeimyourfather"
kw = getRoundKeys(key)
####################################ENCRYPTION################################################################
# Read Text File and Initial Input Array XOR With Key
plainblocks = getBlocksFromText('plaintext.txt')
cipher_sas = []

step = 'e'
for pb in plainblocks:
	sa = getStateArray(pb) 
	sa = addRoundKeys(sa, step, 0)
	cipher_sas = cipher_sas + [sa]
# Encrypt
for r in range(1, 11):
	for ind in range(len(cipher_sas)):
		sa = cipher_sas[ind]
		sa = SingleByteSub(sa, step)
		sa = shiftRows(sa, step)
		if r != 10:
			sa = mixColumns(sa, step)
		sa = addRoundKeys(sa, step, r)
		cipher_sas[ind] = sa

enc_hex = printCipher(cipher_sas, 'h')
#print enc_hex
writeToFile('encryptedtext.txt', enc_hex)
####################################DECRYPTION################################################################

cipher_sas = getCipherSASFromHexFile('encryptedtext.txt')
step = 'd'
for ind in range(len(cipher_sas)):
	cipher_sas[ind] = addRoundKeys(cipher_sas[ind], step, 0)	

# Decrypt
for r in range(1, 11):
	for ind in range(len(cipher_sas)):
		sa = cipher_sas[ind]
		sa = shiftRows(sa, step)
		sa = SingleByteSub(sa, step)
		sa = addRoundKeys(sa, step, r)
		if r != 10:
			sa = mixColumns(sa, step)
		cipher_sas[ind] = sa

# Print Decrypted Text
dec_text =  printCipher(cipher_sas, 't')
dec_text = dec_text.replace("\0", "")
#print dec_text
writeToFile('decryptedtext.txt', dec_text)
