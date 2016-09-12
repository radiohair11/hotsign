#!/usr/bin/python


'''   hot_sign.py
      
      Python implementation of "Hash Based Signatures", McGrew et al.
      draft-mcgrew-hash-sigs.txt
      This line last updated 05 SEP 2016

      LMSprvkey: The ur-key, read from file (one n-byte bitstring)
      LMSpubkey: The root of the Merkle tree (one n-byte bitstring)
      LMOTSprvkey: Private key (p-long list of n-byte bitstrings) for one OTS
      LMOTSpubkey: Public key (one n-byte bitstring) for one OTS
      OTSpubkeys: List of LMOTSpubkeys, before conversion to leaf node values
      
'''

import math
import random
# import bitstring  -- yeah, learn this sometime
from hashlib import sha256 as SHA256
import hmac as HMAC
import binascii

# import LMS_func  -- not sure how handy this is yet
from LMOTS_SHA256_N32_W4 import *


def Byteprint(caption, hexstr, linelen=16):
   '''Pretty print hex strings with leading caption.'''
   lines = int(math.ceil(len(hexstr)/float(linelen)))
   print caption
   for i in range (0, lines):
      start = 0+i*linelen
      end = i*linelen+linelen
      print "   ",' '.join(x.encode('hex')for x in hexstr[start:end])


def bytstr(x, bytlen=4):
   '''Return the binary rep'n of x in bytlen bytes with 0s prefixed.'''
   bits = binascii.a2b_hex('{:064x}'.format(x))
   return bits[-bytlen:]


def calc_p(n, w):
   '''Calculate the number of w-bit substrings in the message hash + checksum.'''
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


def calc_LMOTSpubkey(LMSprvkey, ID, q):
   '''Calculate one LMOTS public key from the LMS private key (seed).'''

   # Generate LMOTS seed

   string = "LMOTS"+bytstr(0,1)+ID+bytstr(q,4)+bytstr(n*8,2)
   OTSprvseed = HMAC.new(LMSprvkey, string, SHA256).digest()
   Byteprint("\nLMOTS seed: ", OTSprvseed)     # debug

   # Generate LMOTS private key

   p = calc_p(n, w)

   LMOTSprvkey = []
   for i in xrange(0, p):
     string = bytstr(i,4)+"LMS"+bytstr(0,1)+ID+bytstr(q,4)+bytstr(n*8,2)
     LMOTSprvkey.append(SHA256(OTSprvseed+string).digest())
     Byteprint("\nX["+str(i)+"] = ", LMOTSprvkey[i])     # debug

   # Generate LMOTS public key

   y = []
   for i in xrange(0, p):
     tmp = LMOTSprvkey[i]
     for j in xrange(0, 2**w-1):
       tmp = SHA256(tmp+ID+bytstr(q,4)+bytstr(i,2)+bytstr(j,2)+D_ITER).digest()
     y.append(tmp)

   Y = SHA256()
   Y.update(ID+bytstr(q,4))
   for i in xrange(0, p):
     Y.update(y[i])
   Y.update(D_PBLC)
   return Y.digest()


def calc_LMS_pub(h, ID, OTSpubkeys):
   '''Calculate the LMS public key from a set of leaf node values.'''

   D = []   # data stack
   I = []   # integer stack

   for i in xrange(0, 2**h, 2):
      print "i = ",i     # debug
      level = 0
      for j in xrange(0, 2):
         print "j = ",j     # debug
         r = i+j+1
         D.append(SHA256(OTSpubkeys[i+j]+ID+bytstr(r)+D_LEAF).digest())
         print "   Leaf ",i+j," pushed onto data stack."     #debug
         I.append(level)
         print "j loop: I, len(I) = ",I, len(I)     # debug
      while len(I) >= 2:
         if I[-2] == I[-1]:
            TMP = SHA256()
            siblings = ""
            for k in (1, 2):
               siblings = D.pop()+siblings
               print "Child value popped from data stack."     #debug
               level = I.pop()
               print "I = ",I     # debug
            TMP.update(siblings)
            r = r + 1
            TMP.update(ID+bytstr(r)+D_INTR)
            D.append(TMP.digest())
            print "Two child values hashed and pushed on data stack."     # debug
            I.append(level+1)
            print "while loop: I, len(I) = ", I, len(I)     # debug
         else:
            break
   return D.pop()



# ===== BEGIN MAIN PROGRAM =====

# Signature inputs

ID = "LMS_SHA256_N32_W4_H5\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
q = 6 # message number
h = 4 # height (num of levels - 1) of tree


# Read LMS private key from storage

keyfile = open("keyfile", "rb")
LMSprvkey = keyfile.read(32)

#---------- Print statements for debug ----------
print "\nLMS private key: "        # potential endian problem!!!
for i in range (0, 2):
   start = 0+i*16
   end = i*16+16
   print "   ",' '.join(x.encode('hex')for x in LMSprvkey[start:end])
#---------- Print statements for debug ----------


# Compute 2**h LMOTS public keys

OTSpubkeys = []

for i in xrange(0, 2**h):
  OTSpubkeys.append(calc_LMOTSpubkey(LMSprvkey, ID, i))

#---------- Print statements for debug ----------
for i in xrange(0, 2**h):
   Byteprint("\nLMOTS public key ["+str(i)+"] = ", OTSpubkeys[i])
#---------- Print statements for debug ----------


# Generate LMS public key (calc hash tree)

LMS_pubkey = calc_LMS_pub(h, ID, OTSpubkeys)

Byteprint("\nLMS public key: ",LMS_pubkey)

# ===== END MAIN PROGRAM =====
