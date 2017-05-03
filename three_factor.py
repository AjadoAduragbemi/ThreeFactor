#!/usr/bin/python
'''
   Copyright (C) 2016 Ajado Aduragbemi Joseph <agbemi19@gmail.com>
 
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
'''
 
from PIL import Image
import sys
from numpy import random
import optparse


class ThreeFactorStegAlgo:
	'''A stegnography algorithm that works by reading and writting 3bytes at a time hence the name'''
	
	def __init__(self, img_input, img_output="out.png", seed=1937007975, verbose=False):
		try:
			self.img_inst = Image.open(img_input)
			self.output_filename = img_output
			self.rand_gen = random.RandomState(seed)
			self.verbosity = verbose
			
			if self.img_inst.mode != "RGB":
				print("[!] Invalid Image: input image mode is not RGB, try again with an RGB image.")
				sys.exit(3)
				
		except IOError as io:
			sys.stderr.write("[!] 0x%08X: Could not find %s: %s.\n"%(io.errno, io.filename, io.strerror))
			sys.exit(io.errno)
		
		
	def write(self, msg):
		img_copy = self.img_inst.copy()
		msg_copy = msg
		msg_len = len(msg_copy)
		
		width, height = img_copy.size						#in terms of columns & rows
		
		self.wout("[+] Input image resolution: {}x{}".format(height, width))
		
		if(msg_len%3 != 0):
			to_add = 3-msg_len%3
			self.wout("[-] String length is not a multiple of three, padding with {} extra byte(s)".format(to_add))
			msg_len += to_add
			while to_add > 0: msg_copy += '$'; to_add -= 1
		
		msg_copy += "$$$"								   #this patched a bug

		try:
			tup, k = tuple(self.rand_gen.randint(0, min(height, width), 2)), 0
			 
			#Write string length to picture image.
			while k < 5:
				r, g, b = img_copy.getpixel(tup)	
				
				new_r = (r&0xFE)|(msg_len&1); msg_len >>= 1
				new_g = (g&0xFE)|(msg_len&1); msg_len >>= 1
				new_b = (b&0xFE)|(msg_len&1); msg_len >>= 1
				
				img_copy.putpixel(tup, (new_r, new_g, new_b))
				
				tup, k = tuple(self.rand_gen.randint(0, min(height, width), 2)), k+1
				
			self.wout("[+] Generating random positions from seed...")
			
			msg_stack = list(msg_copy)
			
			self.wout("[+] Writing {} bytes to picture image...".format(len(msg_stack)-3))
			
			# Write 24bits from supposed message stack at a time
			three_bytes = (ord(msg_stack.pop(0))<<16)|(ord(msg_stack.pop(0))<<8)|ord(msg_stack.pop(0))
			(i, j), k, l = self.rand_gen.randint(0, width, 2), 0, 0
			
			while msg_stack:
				r, g, b = img_copy.getpixel((j, i))
				
				new_r = (r&0xFE)|(three_bytes&1); three_bytes >>= 1
				new_g = (g&0xFE)|(three_bytes&1); three_bytes >>= 1
				new_b = (b&0xFE)|(three_bytes&1); three_bytes >>= 1
				k += 3
				
				img_copy.putpixel((j, i), (new_r, new_g, new_b))
				
				j = (j+3)%width
				
				if(k%24 == 0): 
					three_bytes = (ord(msg_stack.pop(0))<<16)|(ord(msg_stack.pop(0))<<8)|ord(msg_stack.pop(0))
					i = (i+1)%height
				
			self.wout("[+] {} bytes written successfully to '{}'.".format(len(msg_copy)-3, self.output_filename))
			            
			img_copy.save(self.output_filename)
			img_copy.close()
			self.img_inst.close()
			
		except Exception as e:
			sys.stderr.write("[!] Somehow the algorithm failed to write to the picture image.\n")
			sys.stderr.write("    Reason: %s.\n"%(e.message))
			

	def read(self):
		img_copy = self.img_inst.copy()
		width, height = img_copy.size
		self.wout("[+] Input image resolution: {}x{}".format(height, width))
	
		msg_len = 0
		
		try:
			tup, k, l = tuple(self.rand_gen.randint(0, min(width, height), 2)), 0, 0
			
			#Read string length from picture image.
			while k < 5:
				r, g, b = img_copy.getpixel(tup)	
				
				msg_len |= (r&1) << l
				msg_len |= (g&1) << l+1
				msg_len |= (b&1) << l+2
				
				tup, k, l = tuple(self.rand_gen.randint(0, min(height, width), size=2)), k+1, l+3

			self.wout("[+] Reading {} bytes from picture image...".format(msg_len))
			
			(i, j), k, l = self.rand_gen.randint(0, width, 2), 0, 0
			
			three_bytes = 0
			msg = ''
			
			while len(msg) < msg_len:
				r, g, b = img_copy.getpixel((j, i))	
				
				three_bytes |= (r&1) << l+0; k += 1 
				three_bytes |= (g&1) << l+1; k += 1
				three_bytes |= (b&1) << l+2; k += 1
				l += 3
				
				if(k%24 == 0): 
					byte00 = (three_bytes&0x00FF0000) >> 16
					byte01 = (three_bytes&0x0000FF00) >> 8
					byte02 = (three_bytes&0x000000FF)
					msg += chr(byte00) + chr(byte01) + chr(byte02)
					three_bytes, l  = 0, 0
					i = (i+1)%height
				
				j = (j+3)%width
				
			self.wout("[+] All bytes have been read successfully.")
			msg_list = list(msg)
			while msg_list[-1:] == ['$']: msg_list.pop()
			msg = ''
			for s in msg_list: msg += s
			return msg

		except Exception as e:
			sys.stderr.write("[!] Somehow the algorithm failed to read from the picture image.\n")
			sys.stderr.write("    Reason: %s.\n"%(e.message))
			
			
	def wout(self, output_string):
			if(self.verbosity):
				print output_string


def main(opts):
	USAGE = "usage: %prog [options] image_filename"
	parser = optparse.OptionParser(usage=USAGE, description='''A stegnography algorithm that works by reading and writting 3bytes at a time
									 hence the name''')
	parser.add_option('-w', '--write', action='store_true', help='Write message data to image file.')
	parser.add_option('-f', '--file', dest='FN', help='File to read message data from.')
	parser.add_option('-o', '--output', dest='out', type=str, default='./out.png', help='Output filename to write new image in write mode.')
	parser.add_option('-r', '--read', action='store_true', help='Read message data from image file to stdout   (redirect to file a if you want).')
	parser.add_option('-v', '--verbosity', action='store_true', help='Set verbosity.')
	parser.add_option('-p', '--paranoid', action='store_true', help='Performs a read operation after writting to check if message data was written correctly.')
	parser.add_option('-s', '--seed', default=1937007975, type=int, help='The seed for the algo\'s PRNG default=1937007975.')
	(options, args) = parser.parse_args()
	
	if(len(args) == 0) or (options.write == None and  options.read == None):
		parser.print_help()
		sys.exit(1)
	
	if(options.write and  options.read):
		print("[!] Cannot have both read and write options passed at once.")
		sys.exit(2)
		
	if(options.read and options.paranoid):
		print("[-] Option paranoia would have not effect on a read operation.")
	
	prog_inst = ThreeFactorStegAlgo(args[0], options.out, options.seed, options.verbosity)
	
	if(options.write):
		try:
			with open(options.FN, 'r') as msg_file:
				data = msg_file.read()
				prog_inst.write(data)
			
				if(options.paranoid):
					prog_inst.wout("[+] Paranoia mode: Checking to see if message data was written correctly.")
					
					prog_inst.img_inst = Image.open(options.out)
					prog_inst.rand_gen = random.RandomState(options.seed)
					prog_inst.verbosity = False

					msg = prog_inst.read()
					
					check = cmp(msg, data)
					
					if(check == 0):
						print("[+] Message data was written correctly")
						return 0
					else:
						print("[-] Message data was not written correctly,")
						print("    try changing a few parameters like seed or better still use a larger image")
						return -1
		except IOError as io:
			sys.stderr.write("[!] 0x%08X: Could not find %s: %s.\n"%(io.errno, io.filename, io.strerror))
			sys.exit(io.errno)
			
	if(options.read):
		print prog_inst.read()

if __name__ == '__main__':
	main(sys.argv[1:])
