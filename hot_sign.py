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


def calc_LMOTSpubkey(LMSprvkey, LMID, n, w, MNUM):
   '''Calculate one LMOTS public key from the LMS private key (seed).'''

   D_ITER = '\x00'
   D_PBLC = '\x01'

   # Generate per-message LMOTS seed from LMS private key

   MPRT = calc_p(n, w)
   LMOTSprvkey = calc_LMOTSprvkey(LMSprvkey, LMID, n, MPRT, MNUM)

   # Generate per-message p-element LMOTS public key vector

   y = []
   for i in xrange(0, MPRT):
     tmp = LMOTSprvkey[i]
     for j in xrange(0, 2**w-1):
       tmp = SHA256(tmp+LMID+bytstr(MNUM,4)+bytstr(i,2)+bytstr(j,2)+D_ITER).digest()
     y.append(tmp)

   # Generate per-message n-byte LMOTS public key

   Y = SHA256()
   Y.update(LMID+bytstr(MNUM,4))
   for i in xrange(0, MPRT):
     Y.update(y[i])
   Y.update(D_PBLC)
   return Y.digest()


def calc_LMS_pub(h, LMID, OTSpubkeys):
   '''Calculate the n-byte LMS public key from a set n-byte LMOTS public keys.'''

   nodefile = open("nodefile", "wb", 0)

   D_LEAF = '\x03'
   D_INTR = '\x04'

   D = []   # data stack
   I = []   # integer stack
   NODES = []

   for i in xrange(0, 2**h, 2):
      level = 0
      for j in xrange(0, 2):
         NODN = 2**h+i+j
         print "\ni = ", i,"j = ",j,"Leaf node number = ", NODN     # debug
         NODV = SHA256(OTSpubkeys[i+j]+LMID+bytstr(NODN)+D_LEAF).digest()
         Byteprint("NODV: ",NODV)     # debug
         NODES.append([NODN, NODV])
         D.append(NODV)
         print "   Leaf ",i+j," pushed onto data stack."     # debug
         
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
               print "I = ",I, "level = ", level     # debug
            TMP.update(siblings)
            NODN = (2**h+i)/(2**(level+1))
            print "Tree node number: ", NODN     # debug
            TMP.update(LMID+bytstr(NODN)+D_INTR)
            NODV = TMP.digest()
            NODES.append([NODN, NODV])
            D.append(NODV)
            print "Two child values hashed and pushed on data stack."     # debug
            I.append(level+1)
            print "while loop: I, len(I) = ", I, len(I)     # debug
         else:
            break
   NODES.sort()
   for i in NODES:
      nodefile.write(bytstr(i[0],1)+':'+i[1])
   nodefile.close()
   return D.pop()


def update_state(req_MNUM):
   '''Get current state and store new state'''

   statefile = open("statefile", "rb")
   current_state = int(statefile.read(1))

   if req_MNUM < 0:
      statefile.write(str(current_state+1))
      return current_state
   elif req_MNUM < current_state:
      print "Your attempt to sign with a used key has been reported to the authorities."
   elif req_MNUM == current_state:
      statefile.write(str(current_state+1))
      return current_state
   elif req_MNUM > current_state:
      statefile.write(str(req_MNUM+1))
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


def LMS_calc_OTsig(message, LMSprvkey, LMID, MNUM):

   D_ITER = '\x00'
   D_MESG = '\x02'
   MPRT = calc_p(n, w)
   TYPE = typecode
  
#   C = bytstr(random.getrandbits(256), 32)
   C = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'     # debug

   MHSH = SHA256(C+LMID+bytstr(MNUM,4)+D_MESG+message).digest()
   MHCS = MHSH+bytstr(cksm(MHSH, n, w))

   LMOTSprvkey = calc_LMOTSprvkey(LMSprvkey, LMID, n, MPRT, MNUM)

   s = []
   for i in xrange(0, MPRT):
      a = coef(MHCS, i, w)
      tmp = LMOTSprvkey[i]
      for j in xrange(0, a):
         tmp = SHA256(tmp+LMID+bytstr(MNUM,4)+bytstr(i,2)+bytstr(j,2)+D_ITER).digest()
      s.append(tmp)

   return [TYPE,C,MNUM,s]

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


# ===== BEGIN MAIN PROGRAM =====

from LMOTS_SHA256_N32_W4 import *

# Signature inputs

LMID = "LMS_SHA256_N32_W4_H5\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
MNUM = 6 # message number (q)
h = 4 # height (num of levels - 1) of tree; NUMS = 2^h

message = "draft-mcgrew-hash-sigs-04"


# Read LMS private key from storage

keyfile = open("keyfile", "rb")
LMSprvkey = keyfile.read(32)
keyfile.close()

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
  OTSpubkeys.append(calc_LMOTSpubkey(LMSprvkey, LMID, n, w, i))

#---------- Print statements for debug ----------
for i in xrange(0, 2**h):
   Byteprint("\nLMOTS public key ["+str(i)+"] = ", OTSpubkeys[i])
#---------- Print statements for debug ----------


# Generate LMS public key (calc hash tree)

LMS_pubkey = calc_LMS_pub(h, LMID, OTSpubkeys)

Byteprint("\nLMS public key: ",LMS_pubkey)     # debug


# Generate an LMOTS signature

LMS_OTsig = LMS_calc_OTsig(message, LMSprvkey, LMID, MNUM)

# Generate Merkle tree off-branch path

PATH = LMS_discover_path(h, MNUM)
TVECT = LMS_retrieve_node_vals(PATH)

#---------- Print statements for debug ----------
Byteprint("\nTypecode: ",LMS_OTsig[0])
Byteprint("\nDiversification string: ",LMS_OTsig[1])
print "\nMessage number: ",LMS_OTsig[2]
j = 0
for i in LMS_OTsig[3]:
   Byteprint("\nSignature part "+str(j)+": ",i)
   j = j+1
j = 0
for i in TVECT:
   Byteprint("\nPath part "+str(j)+": ",i)
   j = j + 1
#---------- Print statements for debug ----------

# Store signature

sigfile = open("sigfile", "wb")
sigfile.write(LMS_OTsig[0])
sigfile.write(LMS_OTsig[1])
sigfile.write(bytstr(LMS_OTsig[2],4))
j = 0
for i in LMS_OTsig[3]:
   sigfile.write(i)
   j = j+1
j = 0
for i in TVECT:
   sigfile.write(i)
   j = j + 1
sigfile.close()


# ===== END MAIN PROGRAM =====
