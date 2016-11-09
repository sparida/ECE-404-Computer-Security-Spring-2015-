#!/usr/bin/env/python

#HW #: HW 2 Problem 1 (ECE 404 Spring 2015)
#Name: Sthitapragyan Parida
#ECN Login: sparida
#Due Date: 1/29/2015
### DES_parida.py

import sys
import BitVector
import string
from BitVector import BitVector
################################   Initial setup  ################################

# Expansion permutation (See Section 3.3.1):
expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 
9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 
20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

# P-Box permutation (the last step of the Feistel function in Figure 4):
p_box_permutation = [15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,
1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24]

# Initial permutation of the key (See Section 3.3.6):
key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,
50,42,34,26,18,10,2,59,51,43,35,62,54,46,38,30,22,14,6,61,53,45,37,
29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3]

# Contraction permutation of the key (See Section 3.3.7):
key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,
7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,
33,52,45,41,49,35,28,31]

# Each integer here is the how much left-circular shift is applied
# to each half of the 56-bit key in each round (See Section 3.3.5):
shifts_key_halvs = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] 




###################################   S-boxes  ##################################

# Now create your s-boxes as an array of arrays by reading the contents
# of the file s-box-tables.txt:
with open('s-box-tables.txt') as f:
    arrays = []
    for line in f.readlines():
	    line = line.split()  
	    if len(line) > 5: 
            	line = [int(i) for i in line]
            	arrays.append(line)
s_box = []
for i in range(0,32, 4):
    s_box.append([arrays[k] for k in range(i, i+4)]) # S_BOX
#print s_box[0][0][7]


#######################  Get encryptin key from user and generat eround key ###########################

def get_encryption_key(): # key                                                              
    ## ask user for input
    user_supplied_key = raw_input("Enter a key:")
    ## make sure it satisfies any constraints on the key
    printset = set(string.printable)
    isprintable = set(user_supplied_key).issubset(printset)
    if isprintable and len(user_supplied_key) == 8:
    	## next, construct a BitVector from the key    
    	user_key_bv = BitVector(textstring = user_supplied_key)
	key_bv = user_key_bv.permute( key_permutation_1 )        ## permute() is a BitVector function
    	round_keys = []
    	key = key_bv
    	for i in range(16):
	    [left,right] = key_bv.divide_into_two()   ## divide_into_two() is a BitVector function
            left<<shifts_key_halvs[i]
	    right<<shifts_key_halvs[i]
            key = left + right
	    key = key.permute( key_permutation_2 )
	    round_keys = round_keys + [key]
    	return key_bv, round_keys
    else:
	    print "Invalid Key (8 printable characters allowed)"
	    return None

################################# Get round keys  ########################
def extract_round_key(round_keys, r_num, step='encrypt'): # round key                                                   
    print r_num
    if step == "encrypt":
	return round_keys[r_num]
    elif step == "decrypt":
	return round_keys[15 - r_num]
    


########################## encryption and decryption #############################

def des(input_file, output_file, round_keys, step = 'encrypt'): 
    result = None
    blocks = []
    bv = BitVector( filename = input_file )
    c = 0
    while (bv.more_to_read or (c == 0)):
    	bitvec = bv.read_bits_from_file( 64 )
	if step == 'encrypt':
    		bitvec.pad_from_right(64 - len(bitvec))
    	blocks = blocks + [bitvec]
    	c = 1

    for i in range(16):
	round_key = extract_round_key(round_keys, i, step)
	for b in range(len(blocks)):
		
		#Expansion Permutation	
		LE,RE = blocks[b].divide_into_two()
		LE2,RE2 = blocks[b].divide_into_two()	
		nRE = RE.permute(expansion_permutation)
		b_cipher = nRE ^ round_key
		
		# Substition Boxes
		final_b_cipher = ""
		
		for s in range(8):
			b_string = b_cipher[s*6: (s+1)*6]
			
			row = int(str(b_string[0]) + str(b_string[5]), 2)
			col = int(str(b_string[1]) + str(b_string[2]) + str(b_string[3]) + str(b_string[4]), 2)
			s_string = s_box[s][row][col]
			final_b_cipher = final_b_cipher + ('{:04b}'.format(int(s_string)))
			
		fbv = BitVector(bitstring = final_b_cipher)
		
		# Permutation Box
		fbv = fbv.permute(p_box_permutation)
		
		# XOR With left side
		fbv = fbv ^ LE
		blocks[b] =  RE2 + fbv
	
    for b in range(len(blocks)):
	if b == 0:
		result = blocks[b]
	else:
		result = result + blocks[b]		
    
    r_text = result.get_text_from_bitvector()
    with open(output_file, "w") as f:
    	f.write("%s" % r_text)  
    return result
#################################### main #######################################

def main():
    k, round_keys = get_encryption_key()
    print "hello"
    r = des('input', 'output', round_keys, 'encrypt')
    print "hello2"
    r = des('output', 'output5', round_keys, 'decrypt')
    print r.get_text_from_bitvector()


if __name__ == "__main__":
    main()

