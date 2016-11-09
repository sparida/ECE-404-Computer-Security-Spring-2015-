#!/usr/bin/env python

#HW #: HW 7(SHA-512) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 3/12/2015
### ./hw07.py input.txt

import sys
from copy import deepcopy
from BitVector import BitVector

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s  <string to be hashed>\n" % sys.argv[0])
    sys.exit(1)


message_file = sys.argv[1]
# Hex values for key
hx = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
"3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
"d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
"72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
"e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
"2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
"983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
"c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
"27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
"650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
"a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
"d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
"19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
"391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
"748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
"90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
"ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
"06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
"28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
"4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]

K = [BitVector(hexstring = h) for h in hx]
#print K

# Reads bits from a textfile in block of 1024 each
def getBlocksFromText(fn):
	blocks = []
	bv = BitVector(filename = fn)
	c = 0
	while (bv.more_to_read or (c == 0)):
		bitvec = bv.read_bits_from_file(1024)
		l = len(bitvec)
		if l < 1024:
			if l + 128 > 1024:
				bitvec = bitvec + BitVector(intVal = 1, size = 1)
				#print "HEllo", len(bitvec)
				bitvec.pad_from_right(1024 - len(bitvec))
				#print "Damn", len(bitvec)
				bitvec.pad_from_right(1024 - 128)
				m_l = len(blocks) * 1024 + l
				bv2 = BitVector(intVal = m_l, size = 128)
				bitvec = bitvec + bv2
				[left, right] = bitvec.divide_into_two()
				blocks = blocks + [left, right]
				
			elif (l + 128) < 1024:	
				bitvec = bitvec + BitVector(intVal = 1, size = 1)
				bitvec.pad_from_right(1024 - len(bitvec) - 128)
				m_l = len(blocks) * 1024 + l
				#print l
				bv2 = BitVector(intVal = m_l, size = 128)
				bitvec = bitvec + bv2
			    	blocks = blocks + [bitvec]
			elif (l + 128) == 1024:
				m_l = len(blocks) * 1024 + l
				bv2 = BitVector(intVal = m_l, size = 128)
				bitvec = bitvec + bv2
			    	blocks = blocks + [bitvec]
		else:
	    		blocks = blocks + [bitvec]
	    	c = 1
	return blocks

# Get 80 words form each blcok needed in processing
def getWords(block):
	words = []
	for i in range(16):
		words = words + [block[i:(i + 16)]]
	#print "Ehllo"
	mod = 2**64
	for i in range(16, 80):
		w = add264(words[i - 16], sig0(words[i - 15]))
		w = add264(w, sig1(words[i - 2]))
		words = words + [w]
	return words

# Sigma 0 function
def sig0(bv):
	bv1 = deepcopy(bv)
	bv2 = deepcopy(bv)	
	bv3 = deepcopy(bv)
	bv1 = bv1 >> 1	
	bv2 = bv2 >> 8	
	bv3 = bv3.shift_right(7)
	return  bv1 ^ bv2 ^ bv3 

# Sigma 1 function
def sig1(bv):
	bv1 = deepcopy(bv)
	bv2 = deepcopy(bv)	
	bv3 = deepcopy(bv)
	bv1 = bv1 >> 19	
	bv2 = bv2 >> 61	
	bv3 = bv3.shift_right(6)
	return  bv1 ^ bv2 ^ bv3 

# Sigma a function
def siga(bv):
	bv1 = deepcopy(bv)
	bv2 = deepcopy(bv)	
	bv3 = deepcopy(bv)
	bv1 = bv1 >> 28	
	bv2 = bv2 >> 34	
	bv3 = bv2 >> 39
	return  bv1 ^ bv2 ^ bv3 

# Sigma e function
def sige(bv):
	bv1 = deepcopy(bv)
	bv2 = deepcopy(bv)	
	bv3 = deepcopy(bv)
	bv1 = bv1 >> 14	
	bv2 = bv2 >> 18	
	bv3 = bv2 >> 41
	return  bv1 ^ bv2 ^ bv3 

# Processes each block thourgh 80 rounds of processing
def processBlock(b, ha, hb, hc, hd, he, hf, hg, hh):
	hat = deepcopy(ha)
	hbt = deepcopy(hb)
	hct = deepcopy(hc)
	hdt = deepcopy(hd)
	het = deepcopy(he)
	hft = deepcopy(hf)
	hgt = deepcopy(hg)
	hht = deepcopy(hh)

	w = getWords(b)
	for i in range(80):
		Ch = (he & hf) ^ ((~deepcopy(he)) & (hg))	
		Maj = (ha & hb) ^ (ha & hc) ^ (hb & hc)
		T2 = add264(siga(ha), Maj)
		t11 = add264(hh, Ch)
		t22 = add264(sige(he), w[i])
		t33 = add264(t11, t22)
		T1 = add264(t33, K[i])
 		hh = hg
		hg = hf
		hf = he
		he = add264(hd, T1)
		hd = hc
		hc = hb
		hb = ha
		ha = add264(T1, T2)
	ha = add264(ha, hat)
	hb = add264(hb, hbt)
	hc = add264(hc, hct)
	hd = add264(hd, hdt)
	he = add264(he, het)
	hf = add264(hg, hft)
	hg = add264(hh, hgt)
	hh = add264(ha, hht)
	return (ha, hb, hc, hd, he, hf, hg, hh)

# Modulo 2^64 Addition
def add264(bv1, bv2):
	val = (int(bv1) + int(bv2)) % (2**64)
	return BitVector(intVal = val, size = 64)		  

def main():
	# Initialize hashcode for the first block. Subsequetnly, the	
	# output for each 512-bit block of the input message becomes
	# the hashcode for the next block of the message.
	ha = BitVector(hexstring='6a09e667f3bcc908')
	hb = BitVector(hexstring='bb67ae8584caa73b')
	hc = BitVector(hexstring='3c6ef372fe94f82b')
	hd = BitVector(hexstring='a54ff53a5f1d36f1')
	he = BitVector(hexstring='510e527fade682d1')
	hf = BitVector(hexstring='9b05688c2b3e6c1f')
	hg = BitVector(hexstring='1f83d9abfb41bd6b')
	hh = BitVector(hexstring='5be0cd19137e2179')
	#print(len(ha))
	blocks = getBlocksFromText(message_file)
	for b in blocks:
		(ha, hb, hc, hd, he, hf, hg, hh) = processBlock(b, ha, hb, hc, hd, he, hf, hg, hh)
	hexs = ""
	for h in [ha, hb, hc, hd, he, hf, hg, hh]:
		hexs = hexs + h.get_hex_string_from_bitvector()
	with open("output.txt", "w") as text_file:
		text_file.write(hexs)

if __name__ == "__main__":
	main()

