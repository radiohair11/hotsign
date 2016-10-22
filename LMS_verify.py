#!/usr/bin/python

import math
from hashlib import sha256 as SHA256
import hmac as HMAC
import binascii

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


def LMS_read_pubkey():

   from struct import unpack

   pubkeyfile = open("pubkeyfile", "rb")
   pubtype = unpack('>I', pubkeyfile.read(4))[0]
   LMID = pubkeyfile.read(31)
   LMSpubkey = pubkeyfile.read(32)
   return pubtype, LMID, LMSpubkey


def LMS_read_sig(sigfn):

   from struct import unpack
   import typecode_registry

   sigfile = open(sigfn, "rb")

   LMS_typecode = unpack('>I', sigfile.read(4))[0]
   LMOTS_typecode = unpack('>I', sigfile.read(4))[0]
   MSLT = sigfile.read(32)
   MNUM = unpack('>I', sigfile.read(4))[0]

   MHWD = typecode_registry.LMOTS_parms[LMOTS_typecode][0]
   MSLC = typecode_registry.LMOTS_parms[LMOTS_typecode][1]
   MPRT = calc_p(MHWD, MSLC)

   S = []
   for i in xrange(0,MPRT):
      S.append(sigfile.read(32))

   T = []
   tmp = sigfile.read(32)
   while tmp != "":
      T.append(tmp)
      tmp = sigfile.read(32)

   sigfile.close()

   return LMS_typecode, MSLT, MNUM, S, T, MHWD, MSLC, MPRT

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


def LMS_verify_LMOTS_sig(message, MHWD, MSLC, MPRT, LMID, MSLT, MNUM, S):

   D_ITER = '\x00'
   D_PBLC = '\x01'
   D_MESG = '\x02'

   MHSH = SHA256(MSLT+LMID+bytstr(MNUM,4)+D_MESG+message).digest()
   MHCS = MHSH+bytstr(cksm(MHSH, MHWD, MSLC))

   z = []
   for i in xrange(0, MPRT):
      a = coef(MHCS, i, MSLC)
      tmp = S[i]
      for j in xrange(a, 2**MSLC-1):
         tmp = SHA256(tmp+LMID+bytstr(MNUM,4)+bytstr(i,2)+bytstr(j,2)+D_ITER).digest()
         Byteprint("Chain "+str(i)+", element "+str(j)+": ", tmp)
      z.append(tmp)

   Z = SHA256()
   Z.update(LMID+bytstr(MNUM,4))
   for i in xrange(0, MPRT):
     Z.update(z[i])
   Z.update(D_PBLC)
   return Z.digest()
   

def LMS_calc_root(cand_node, LMID, NODN, T):
   '''Hash path to putative root node value'''
   D_INTR = '\x04'
   T.reverse()
   tmp = cand_node
   while NODN > 1:
      print "Node number: ", NODN     #debug
      if NODN % 2 == 0:
         tmp = SHA256(tmp+T.pop()+LMID+bytstr(NODN//2, 4)+D_INTR).digest()
      else:
         tmp = SHA256(T.pop()+tmp+LMID+bytstr(NODN//2, 4)+D_INTR).digest()
      NODN = NODN//2
      Byteprint("Node "+str(NODN)+": ", tmp)
   return tmp

# ===== MAIN FUNCTION ===== # ===== MAIN FUNCTION ===== #
def LMS_verify(msgfn, sigfn):

   import struct

# Retrieve typecode, LMID, and public key from public key file

   LMS_typecode_key, LMID, LMS_pubkey = LMS_read_pubkey()

   print "Public key type: ", LMS_typecode_key      # debug
   Byteprint("LMID: ",LMID)     # debug
   Byteprint("LMS public key: ", LMS_pubkey)     # debug

# Read message

   msgfile = open(msgfn, "rb")
   message = msgfile.read()
   msgfile.close()

# Read signature: 0:LMS_typecode, 1:MSLT, 2:MNUM, 3:S, 4:T

   LMS_typecode_sig, MSLT, MNUM, S, T, MHWD, MSLC, MPRT= LMS_read_sig(sigfn)

   print "\nLMS typecode: ", LMS_typecode_sig #LMS_typecode     # debug
#   print "LMOTS typecode: ", LMOTS_typecode     # debug
   Byteprint("Message salt: ", MSLT)     # debug
   print "Message number: ", MNUM     # debug

   THGT = len(T)

   if LMS_typecode_sig != LMS_typecode_key:
      print "\nIncorrect typecode. Signature is not valid."
      os._exit(1)
   else:                            # debug
      print "\nTypecode matches."     # debug

   candidate = LMS_verify_LMOTS_sig(message, MHWD, MSLC, MPRT, LMID, MSLT, MNUM, S)
   Byteprint("\nCandidate LMOTS pub key: ", candidate)

   cand_node = SHA256(candidate+LMID+bytstr(2**THGT+MNUM)+'\x03').digest() # D_LEAF = '\x03'
   Byteprint("\nCandidate node value: ", cand_node)

   T1 = LMS_calc_root(cand_node, LMID, 2**THGT+MNUM, T)
   Byteprint("\nCandidate root (pub key): ", T1)
   Byteprint("\nTrue public key: ", LMS_pubkey)

   if T1 == LMS_pubkey:
      print "\nSignature is valid."
   else:
      print "\nYou're being had."
# ===== END MAIN FUNCTION ===== # ===== END MAIN FUNCTION ===== #
