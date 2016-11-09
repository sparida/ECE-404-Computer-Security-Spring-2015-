#!/usr/bin/env python

#HW #: HW 6(Break RSA) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 3/3/2015
### Parida_breakRSA_hw06.py
# Run using: ./Parida_breakRSA_hw06.py message.txt cracked.txt
# Test using: diff message.txt cracked.txt

from BitVector import BitVector
from PrimeGenerator import PrimeGenerator
import sys
import cPickle
from solve_pRoot import solve_pRoot
import string

e = 3
ebv = BitVector(intVal = e)

# Reads bitvectors from a text file as blocks of size 256 with padding
def getBlocksFromText(fn):
	blocks = []
	bv = BitVector(filename = fn)
	c = 0
	while (bv.more_to_read or (c == 0)):
		bitvec = bv.read_bits_from_file(128)
		bitvec = make128BitVector(bitvec)
		bitvec.pad_from_left(128)
		#print(len(bitvec))
	    	blocks = blocks + [bitvec]
	    	c = 1
	return blocks

# Makes a 128 bit vector out of the bitvector
def make128BitVector(bv):
	l = int(len(bv))
	nbv = BitVector(textstring = "\n")
	for i in range((128 - l)/8):
		bv = bv + nbv
		#print len(nbv), len(bv)
	return bv

# Writes text to file
def writeToFile(filename, text):
	f = open(filename, 'w')
	f.write("%s" % text)
	f.close()

# Returns three Ns: n1, n2, n3
def getPQD(n123):
	c = True
	generator1 = PrimeGenerator( bits = 128, debug = 0 )
	generator2 = PrimeGenerator( bits = 128, debug = 0 )
	count = 0
	while c == True:
		p = generator1.findPrime()
		q = generator2.findPrime()
		pbv = BitVector(intVal = p, size = 128)
		qbv = BitVector(intVal = q, size = 128)
		#print p, q
		if(not (p != q)):
			c = True
		elif(not ( (pbv[0] == 1) and (qbv[0] == 1) ) ):
			c = True
		elif(not((int(BitVector(intVal = p-1).gcd(ebv)) == 1) and (int(BitVector(intVal = q-1).gcd(ebv)) == 1))):
			c = True
		else:
			nbv = BitVector(intVal = p*q, size = 256)
			n = int(nbv)
			if(int(n123[0].gcd(nbv)) == 1) and (int(n123[1].gcd(nbv)) == 1) and (int(n123[2].gcd(nbv)) == 1):
				#print count
				n123[count] = nbv
				count = count + 1
				if count >= 3:
					c = False
				else:
					c = True  

	return n123

# Encrypts based on RSA
def encrypt(outfile, blocks, n):
	e_hex_str = ""
	for b in blocks:
		e_num = pow(int(b), e, n)
		e_numbv = BitVector(intVal = e_num, size = 256)
		e_hex_str = e_hex_str + e_numbv.get_hex_string_from_bitvector()
	return e_hex_str
	
# Code to crack RSA cipher for small e = 3 using CRT
def crackEncText(crackfile, estr123, n123):
	n1 = int(n123[0])
	n2 = int(n123[1])
	n3 = int(n123[2])
	M1 = n2*n3
	M2 = n1*n3
	M3 = n1*n2
	M1I = BitVector(intVal = M1).multiplicative_inverse(n123[0])
	M2I = BitVector(intVal = M2).multiplicative_inverse(n123[1])
	M3I = BitVector(intVal = M3).multiplicative_inverse(n123[2])
	c1 = M1 * int(M1I)
	c2 = M2 * int(M2I)
	c3 = M3 * int(M3I)
	block1 = getEncBlocksFromHexString(estr123[0])
	block2 = getEncBlocksFromHexString(estr123[1])
	block3 = getEncBlocksFromHexString(estr123[2])
	d_str = ""
	for i in range(len(block1)):
		e1 = int(block1[i])
		e2 = int(block2[i])	
		e3 = int(block3[i])	
		M_cube = pow(e1*c1+e2*c2+e3*c3, 1, n1*n2*n3)
		M = solve_pRoot(3, M_cube)
		bv = BitVector(intVal = M, size = 128)
		d_str = d_str +  bv.get_text_from_bitvector()
	d_str = filter(lambda x: x in string.printable, d_str)
	writeToFile(crackfile, d_str[:-1])

# Read bits into blocks of 256 and create encrypotes text blocks of BitVectors from a hexstring
def getEncBlocksFromHexString(h_str):
	cipher_sas = []
	for i in range(len(h_str)/64):
		hex_str = h_str[i*64: (i+1)*64]
		bv = BitVector(hexstring = hex_str)
		cipher_sas = cipher_sas + [bv]
	return cipher_sas

def main():
	if len(sys.argv) == 3:
		msgfile = str(sys.argv[1])
		crackfile = str(sys.argv[2])
		blocks = getBlocksFromText(msgfile)
		n123 = [BitVector(intVal = 1), BitVector(intVal = 1), BitVector(intVal = 1)]
		n123 = getPQD(n123)
		estr123 = []
		for i in range(3):
			estr = encrypt(crackfile, blocks, int(n123[i]))
			estr123 = estr123 + [estr]
		crackEncText(crackfile, estr123, n123)
	else:
		print "Wrong"
	
if __name__ == "__main__":
	main()
