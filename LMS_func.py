#!/usr/bin/python

import math
import random
import binascii
#from hashlib import sha256 as SHA256


def Byteprint(caption, hexstr, linelen=16):
   '''Byteprint pretty prints hex strings with leading caption'''
   lines = int(math.ceil(len(hexstr.digest())/float(linelen)))
   print(caption)
   for i in range (0, lines):
      start = 0+i*linelen
      end = i*linelen+linelen
      print("   ",' '.join(x.encode('hex')for x in hexstr.digest()[start:end]))

def bytstr(x, bytlen=4):
  '''bytstr returns the binary rep'n of x in bytlen bytes with 0s prefixed'''
  bits = binascii.a2b_hex('{0:064x}'.format(x))
  return bits[-bytlen:]

def calc_p(MHWD, MSLC):
  ''' calc the number of w-bit substrings in the message hash + checksum'''
  u = math.ceil(8 * MHWD / MSLC)
  v = math.ceil((math.floor(math.log((2**MSLC - 1) * u, 2)) + 1) / MSLC)
  p = u+v
  return int(p)

def calc_ls(MHWD, MSLC, sumbits):
  '''Calc number of left shift bits for checksum'''
  u = math.ceil(8 * MHWD / MSLC)
  v = math.ceil((math.floor(math.log((2**MSLC - 1) * u, 2)) + 1) / MSLC)
  shftl = sumbits - (v*MSLC)
  return int(shftl)

