"""
HW #: HW 3 Programming Problem 1 (ECE 404 Spring 2015)
Name: Sthitapragyan Parida
ECN Login: sparida
Due Date: 2/5/2015

Python Version: 2.7
To execute script:
python Parida_Field.py
"""

def isPrime(n):
	
	if(n <= 1):
		return False
	if (n == 2):
		return True
	for i in range(2, int(n**0.5) + 2):
		if (n % i == 0):
			return False
	return True

def main():
	n = int(raw_input("Enter a number:"))
	f = open('output.txt','w')
	if(isPrime(n)):
		f.write("field")
	else:
		f.write("ring")
	f.close()		
main()
