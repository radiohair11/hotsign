#!/usr/bin/python

import math

def Byteprint(caption, hexstr, linelen=16):
   '''Pretty print hex strings with leading caption.'''
   lines = int(math.ceil(len(hexstr)/float(linelen)))
   print caption
   for i in range (0, lines):
      start = 0+i*linelen
      end = i*linelen+linelen
      print "   ",' '.join(x.encode('hex')for x in hexstr[start:end])


def bytstr(num, bytlen=4):
   '''Return the binary rep'n of num in bytlen bytes with 0s prefixed.'''
   bits = binascii.a2b_hex('{0:064x}'.format(num))
   return bits[-bytlen:]


def calc_p(n, w):
   '''Calculate the number of w-bit substrings in the message hash + checksum.'''
   u = math.ceil(8 * n / w)
   v = math.ceil((math.floor(math.log((2**w - 1) * u, 2)) + 1) / w)
   p = u+v
   return int(p)


def LMS_read_sig(p):

   import struct

   sigfile = open("sigfile", "rb")

   sigtype = sigfile.read(4)
   Byteprint("Signature type: ", sigtype)     # debug
   divstring = sigfile.read(32)
   Byteprint("Diversification string: ", divstring)     # debug
   MNUM = struct.unpack('>I', sigfile.read(4))[0]
   print "Message number: ", MNUM     # debug

   S = []
   for i in xrange(0,p):
      S.append(sigfile.read(32))

   T = []
   tmp = sigfile.read(32)
   while tmp != "":
      T.append(tmp)
      tmp = sigfile.read(32)

   sigfile.close()

   return [sigtype, divstring, MNUM, S, T]

# ===== BEGIN MAIN PROGRAM =====

from LMOTS_SHA256_N32_W4 import *

p = calc_p(n, w)
LMS_sig = LMS_read_sig(p)
