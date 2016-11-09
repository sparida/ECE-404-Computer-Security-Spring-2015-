#!/usr/bin/env python

#HW #: HW 6(RSA) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 3/3/2015
### Parida_RSA_hw06.py
# Run using: ./Parida_RSA_hw06.py -e message.txt output.txt
#	     ./Parida_RSA_hw06.py -d output.txt decrypted.txt
# Test using: diff message.txt decrypted.txt

# Note1: The p and q values are generated randomly. Hence the -e command is run the current p and q is stored in a file which is read when the output is called to be decrypted (-d).
# Note2: The encrypted output is stored as hexstring which is decoded during decrypting as in the guidelines for hw 4. 

from BitVector import BitVector
from PrimeGenerator import PrimeGenerator
import sys
import cPickle

e = 65537
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

# Returns p, q, n, d and their BitVectors
def getPQD():
	c = True
	generator1 = PrimeGenerator( bits = 128, debug = 0 )
	generator2 = PrimeGenerator( bits = 128, debug = 0 )
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
			c = False
	nbv = BitVector(intVal = p*q, size = 256)
	n = int(nbv)
	dbv = ebv.multiplicative_inverse( BitVector(intVal = (p-1) * (q-1), size = 256) )
	d = int(dbv)
	return p, q, n, int(dbv), pbv, qbv, nbv, dbv

# Encrypts file based on RSA block by block
def encrypt(outfile, blocks, p, q, n, d, pbv, qbv, nbv, dbv):
	e_hex_str = ""
	for b in blocks:
		e_num = pow(int(b), e, n)
		e_numbv = BitVector(intVal = e_num, size = 256)
		e_hex_str = e_hex_str + e_numbv.get_hex_string_from_bitvector()
	writeToFile(outfile, e_hex_str)

	with open('keys','wb') as fp:
		cPickle.dump(pbv,fp)
		cPickle.dump(qbv,fp)
		cPickle.dump(nbv,fp)
		cPickle.dump(dbv,fp)

# Decrypts hex file based which is teh encrypted output to get the plaintext
def decrypt(outfile, decfile, p, q, n, d, pbv, qbv, nbv, dbv):
	enc_blocks = getEncBlocksFromHexFile(outfile)
	d_text_str = ""
	for eb in enc_blocks:
		d_num = crtPow(int(eb), d, p, q)
		d_numbv = BitVector(intVal = d_num, size = 256)
		d_numbv = d_numbv[128:256]
		d_text_str = d_text_str + d_numbv.get_text_from_bitvector()
		#d_text_str = d_text_str.replace('\n', '')
	writeToFile(decfile, d_text_str[:-1])

# Implements faster pow function using CRT
def crtPow(c, d, p, q):
	vp = pow(c, d, p)
	vq = pow(c, d, q)
	xp = q * int(BitVector(intVal = q).multiplicative_inverse(BitVector(intVal = p)))
	xq = p * int(BitVector(intVal = p).multiplicative_inverse(BitVector(intVal = q)))
	return pow(vp*xp + vq* xq, 1, p*q)

# Read bits into blocks of 256 and create encrypotes text blocks of BitVectors from a hexstring
def getEncBlocksFromHexFile(hexfile):
	cipher_sas = []
	hf = open(hexfile, 'r')
	h_str = hf.read()
	hf.close()
	for i in range(len(h_str)/64):
		hex_str = h_str[i*64: (i+1)*64]
		bv = BitVector(hexstring = hex_str)
		cipher_sas = cipher_sas + [bv]
	return cipher_sas

# Main function to differentiate between encrypt mode and decrypt mode
def main():
	if len(sys.argv) == 4:
		if str(sys.argv[1]) == "-e":
			msgfile = str(sys.argv[2])
			outfile = str(sys.argv[3])
			blocks = getBlocksFromText(msgfile)
			p, q, n, d, pbv, qbv, nbv, dbv = getPQD()
			encrypt(outfile, blocks, p, q, n, d, pbv, qbv, nbv, dbv)
		elif str(sys.argv[1]) == "-d":
			outfile = str(sys.argv[2])
			decfile = str(sys.argv[3])
			with open('keys','rb') as fp:
				pbv = cPickle.load(fp)
				qbv = cPickle.load(fp)
				nbv = cPickle.load(fp)
				dbv = cPickle.load(fp)
			p = int(pbv)
			q = int(qbv)
			n = int(nbv)
			d = int(dbv)
			decrypt(outfile, decfile, p, q, n, d, pbv, qbv, nbv, dbv)
	else:
		print "Wrong"
	
if __name__ == "__main__":
	main()
