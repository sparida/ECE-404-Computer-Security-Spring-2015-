#!/usr/bin/env python

#HW #: HW 5(RC4) (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 2/24/2015
### ece404_hw05_sparida.py
## Works fine for smaller files. 
## Works really slow with bigger files
## Hence i decreased teh size of the tiger file down to decrease run time (To about 15 % of orginial size)
## Just run program by typing ./hw.py. The main function does everything necessary and exhibits how to run program:
#def main():
#	rc4 = RC4('qwerasdfzxcvtyui')
#	a = rc4.loadFile("Tiger2.ppm")
#	b = rc4.encrypt(a)
#	c = rc4.decrypt(b)
#	if(a == c):
#		print "RC4 is awesome"
#	else:
#		print "Hmm, Somethign seems fishy!"

from copy import deepcopy
from BitVector import BitVector
import os

class RC4():
	def __init__(self, key):
		self.K = [ord(k) for k in key]
		self.S = range(256)
		self.T = range(256)
		for i in range(256):
			self.T[i] = self.K[i % 16]
		j = 0
		for i in range(256):
			j = ( j + self.S[i] + self.T[i] ) % 256
			self.S[i], self.S[j] = self.S[j], self.S[i]
	
	def loadFile(self, name):
		self.img = []
		os.system("convert %s -compress None temp.ppm" % (name))
		f = open("temp.ppm", "r")
		self.img = f.readlines()
		self.header =  self.img[0:5]
		self.img = self.img[5:]
		self.name = name	
		s = None
		for a in self.img:
			if s == None:
				s = [int(k) for k in a.split()]	
			else:
				s = s + [int(k) for k in a.split()]			
		f.close()
		os.system("rm temp.ppm")
		return s
	
	def encrypt(self, img):
		i = 0
		j = 0
		S = deepcopy(self.S)
		d_img = []
		
		for m in img:
			i = ( i + 1 ) % 256
			j = ( j + S[i] ) % 256
			S[i], S[j] = S[j], S[i]
			k = ( S[i] + S[j] ) % 256
			bv1 = BitVector(intVal = S[k], size = 8)
			bv2 = BitVector(intVal = m, size = 8)
			c = (int(str(bv1 ^ bv2), 2))
			d_img = d_img + [c]
			#print m, c
		f = open("Encrypted" + self.name, 'w')
		for l in self.header:
			f.write(l)
		for m in d_img:
			f.write(str(m))
			f.write('\n')
		f.close()
		return d_img

	def decrypt(self, img):
		i = 0
		j = 0
		S = deepcopy(self.S)
		d_img = []
		
		for m in img:
			i = ( i + 1 ) % 256
			j = ( j + S[i] ) % 256
			S[i], S[j] = S[j], S[i]
			k = ( S[i] + S[j] ) % 256
			bv1 = BitVector(intVal = S[k], size = 8)
			bv2 = BitVector(intVal = m, size = 8)
			c = (int(str(bv1 ^ bv2), 2))
			d_img = d_img + [c]
		
		f = open("Decrypted" + self.name, 'w')
		for l in self.header:
			f.write(l)
		for m in d_img:
			f.write(str(m))
			f.write('\n')
		f.close()
		return d_img

def main():
	rc4 = RC4('qwerasdfzxcvtyui')
	a = rc4.loadFile("Tiger2.ppm")
	b = rc4.encrypt(a)
	c = rc4.decrypt(b)
	if(a == c):
		print "RC4 is awesome"
	else:
		print "Hmm, Somethign seems fishy!"
if __name__ == "__main__":
	main()
		
