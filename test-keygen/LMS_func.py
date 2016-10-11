#!/usr/bin/python

import math
import random
import binascii


def Byteprint(caption, hexstr, linelen=16):
   '''Byteprint pretty prints hex strings with leading caption'''
   lines = int(math.ceil(len(hexstr)/float(linelen)))
   print caption
   for i in range (0, lines):
      start = 0+i*linelen
      end = i*linelen+linelen
      print "   ",' '.join(x.encode('hex')for x in hexstr[start:end])

def bytstr(x, bytlen=4):
  '''bytstr returns the binary rep'n of x in bytlen bytes with 0s prefixed'''
  bits = binascii.a2b_hex('{:064x}'.format(x))
  return bits[-bytlen:]

def calc_p(n, w):
  ''' calc the number of w-bit substrings in the message hash + checksum'''
  u = math.ceil(8 * n / w)
  v = math.ceil((math.floor(math.log((2**w - 1) * u, 2)) + 1) / w)
  p = u+v
  return int(p)

def calc_ls(n, w, sum):
  '''Calc number of left shift bits for checksum'''
  u = math.ceil(8 * n / w)
  v = math.ceil((math.floor(math.log((2**w - 1) * u, 2)) + 1) / w)
  shftl = sum - (v*w)
  return int(shftl)

