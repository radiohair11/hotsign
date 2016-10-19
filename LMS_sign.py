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


def calc_ls(n, w, sumbits):
   '''Calc number of left shift bits for checksum'''
   u = math.ceil(8 * n / w)
   v = math.ceil((math.floor(math.log((2**w - 1) * u, 2)) + 1) / w)
   shftl = sumbits - (v*w)
   return int(shftl)


def calc_LMOTSprvkey(LMSprvkey, LMID, n, MPRT, MNUM):
   '''Calculate one LMOTS private key (list) from the LMS private key (seed)'''

   # Generate per-message LMOTS seed from LMS private key

   string = "LMOTS"+bytstr(0,1)+LMID+bytstr(MNUM,4)+bytstr(n*8,2)
   OTSprvseed = HMAC.new(LMSprvkey, string, SHA256).digest()
   Byteprint("\nLMOTS seed: ", OTSprvseed)     # debug

   # Generate per-message p-element LMOTS private key

   LMOTSprvkey = []
   for i in xrange(0, MPRT):
     string = bytstr(i,4)+"LMS"+bytstr(0,1)+LMID+bytstr(MNUM,4)+bytstr(n*8,2)
     LMOTSprvkey.append(SHA256(OTSprvseed+string).digest())
     Byteprint("\nX["+str(i)+"] = ", LMOTSprvkey[i])     # debug

   return LMOTSprvkey


def update_state(req_MNUM):
   '''Get current state and store new state'''

   import struct

   statefile = open("statefile", "r+b")
   current_state = struct.unpack('>I', statefile.read(4))[0]

   if req_MNUM < 0:
      statefile.write(bytstr(current_state+1, 4))
      return current_state
   elif req_MNUM < current_state:
      print "Your attempt to sign with a used key has been reported to the authorities."
   elif req_MNUM == current_state:
      statefile.write(bytstr(current_state+1, 4))
      return current_state
   elif req_MNUM > current_state:
      statefile.write(bytstr(req_MNUM+1, 4))
      return req_MNUM
      

def coef(string, index, w):
   '''Calculate the 'i'th w-bit slice of string'''
   import array

   bytes = array.array('B', string)
   MASK = 2**w-1
   NBYT = int(index*w/8)
   OPND = bytes[NBYT]
   RSFT = 8 - (w*(index%(8/w))+w)
   return MASK&(OPND>>RSFT)


def cksm(MHSH, n, w):
   '''Calculate checksum (section 4.6)'''
   csum = 0
   u = int(math.ceil(8 * n / w))
   for i in xrange(0, u):
      csum = csum + (2**w-1) - coef(MHSH, i, w)
   return csum<<calc_ls(n, w, 16)


def LMS_calc_OTsig(message, LMSprvkey, LMID, MHWD, MSLC, MNUM):

   D_ITER = '\x00'
   D_MESG = '\x02'
   MPRT = calc_p(MHWD, MSLC)
  
   MSLT = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'     # debug
#  MSLT = bytstr(random.getrandbits(256), 32) # message salt (C)

   MHSH = SHA256(MSLT+LMID+bytstr(MNUM,4)+D_MESG+message).digest()
   MHCS = MHSH+bytstr(cksm(MHSH, MHWD, MSLC))

   LMOTSprvkey = calc_LMOTSprvkey(LMSprvkey, LMID, MHWD, MPRT, MNUM)

   s = []
   for i in xrange(0, MPRT):
      a = coef(MHCS, i, MSLC)
      tmp = LMOTSprvkey[i]
      for j in xrange(0, a):
         tmp = SHA256(tmp+LMID+bytstr(MNUM,4)+bytstr(i,2)+bytstr(j,2)+D_ITER).digest()
      s.append(tmp)

   return MSLT,s

def LMS_discover_path(h, MNUM):
   '''Create a list of off-branch node numbers'''
   PATH = []
   node_num = 2**h+MNUM
   while node_num > 1:
      if node_num % 2 == 0:
         node_num = node_num + 1
      else:
         node_num = node_num - 1
      print "node_num: ", node_num     # debug
      PATH.append(node_num)
      node_num = node_num//2
   return PATH

def LMS_retrieve_node_vals(PATH):
   '''Read the node values from file saved at key-gen'''
   nodefile = open("nodefile", "rb", 0)

   TVECT = []
   for i in PATH:
      nodefile.seek((i-1)*34+2)
      TVECT.append(nodefile.read(32))
   nodefile.close()
   return TVECT


# ===== MAIN FUNCTION ===== # ===== MAIN FUNCTION ===== #

# from LMOTS_SHA256_N32_W4 import *

# Signature inputs

# LMID = "LMS_SHA256_N32_W4_H4\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
# MNUM = 6 # message number (q)
# THGT = 4 # height (num of levels - 1) of tree; NUMS = 2^h
# message = "draft-mcgrew-hash-sigs-04"

def LMS_sign(msgfn):

   import struct
   from typecode_registry import *

# Read typecode and LMS private key from storage

   keyfile = open("prvkeyfile", "rb")
   LMOTS_typecode = struct.unpack('>I', keyfile.read(4))[0]   # need this to look up 'w'
   LMSprvkey = keyfile.read(32)
   keyfile.close()

# Retrieve typecode and LMID from public key file

   keyfile = open("pubkeyfile", "rb")
   LMS_typecode = struct.unpack('>I', keyfile.read(4))[0]     # need this to look up 'h'
   LMID = keyfile.read(31)
   keyfile.close()

   Byteprint("\nLMS private key: ", LMSprvkey)

# Read message

   msgfile = open(msgfn, "rb")
   message = msgfile.read()
   msgfile.close()

   MHWD = LMOTS_parms[LMOTS_typecode][0]
   MSLC = LMOTS_parms[LMOTS_typecode][1]
   THGT = LMS_parms[LMS_typecode][1]

   MNUM = update_state(-1)

# Generate an LMOTS signature

   MSLT, LMS_OTsig = LMS_calc_OTsig(message, LMSprvkey, LMID, MHWD, MSLC, MNUM)

# Generate Merkle tree off-branch path

   PATH = LMS_discover_path(THGT, MNUM)
   TVECT = LMS_retrieve_node_vals(PATH)

#---------- Print statements for debug ----------
   Byteprint("\nLMS typecode: ", bytstr(LMS_typecode, 4))
   Byteprint("\nLMOTS typecode: ", bytstr(LMOTS_typecode, 4))
   Byteprint("\nDiversification string: ",MSLT)
   Byteprint("\nMessage number: ", bytstr(MNUM, 4))
   j = 0
   for i in LMS_OTsig:
      Byteprint("\nSignature part "+str(j)+": ",i)
      j = j+1
   j = 0
   for i in TVECT:
      Byteprint("\nPath part "+str(j)+": ",i)
      j = j + 1
#---------- Print statements for debug ----------

# Store signature

   sigfile = open("sig."+msgfn, "wb")
   sigfile.write(bytstr(LMS_typecode, 4))
   sigfile.write(bytstr(LMOTS_typecode, 4))
   sigfile.write(MSLT)
   sigfile.write(bytstr(MNUM,4))
   j = 0
   for i in LMS_OTsig:
      sigfile.write(i)
      j = j+1
   j = 0
   for i in TVECT:
      sigfile.write(i)
      j = j + 1
   sigfile.close()

# ===== END MAIN FUNCTION =====
