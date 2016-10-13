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
   pubtype = pubkeyfile.read(4)
   Byteprint("Public key type: ",pubtype)     # debug
   LMID = pubkeyfile.read(31)
   Byteprint("LMID: ",LMID)     # debug
   LMSpubkey = pubkeyfile.read(32)
   Byteprint("LMS public key: ", LMSpubkey)     # debug
   return [pubtype, LMID, LMSpubkey]


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


def LMS_verify_LMOTS_sig(message, MPRT, LMID, divstring, MNUM, S):

   D_ITER = '\x00'
   D_PBLC = '\x01'
   D_MESG = '\x02'

   MHSH = SHA256(divstring+LMID+bytstr(MNUM,4)+D_MESG+message).digest()
   MHCS = MHSH+bytstr(cksm(MHSH, n, w))

   z = []
   for i in xrange(0, MPRT):
#      a = (2**w-1) - coef(MHCS, i, w)
      a = coef(MHCS, i, w)
      tmp = S[i]
      for j in xrange(a, 2**w-1):
         tmp = SHA256(tmp+LMID+bytstr(MNUM,4)+bytstr(i,2)+bytstr(j,2)+D_ITER).digest()
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

# ===== BEGIN MAIN PROGRAM =====

from LMOTS_SHA256_N32_W4 import *

message = "draft-mcgrew-hash-sigs-04"

MPRT = calc_p(n, w)
LMS_pubkey = LMS_read_pubkey()     # 0:typecode, 1:LMID, 2:LMSpubkey
LMS_sig = LMS_read_sig(MPRT)          # 0:typecode, 1:divstring, 2:MNUM, 3:S, 4:T
h = len(LMS_sig[4])

if LMS_sig[0] != LMS_pubkey[0]:
   print "Incorrect typecode. Signature is not valid."
   os._exit(1)
else:                            # debug
   print "Typecode matches."     # debug

candidate = LMS_verify_LMOTS_sig(message, MPRT, LMS_pubkey[1], LMS_sig[1], LMS_sig[2], LMS_sig[3])

Byteprint("\nCandidate LMOTS pub key: ", candidate)

cand_node = SHA256(candidate+LMS_pubkey[1]+bytstr(2**h+LMS_sig[2])+'\x03').digest()
Byteprint("\nCandidate node value: ", cand_node)

T1 = LMS_calc_root(cand_node, LMS_pubkey[1], 2**h+LMS_sig[2], LMS_sig[4])
Byteprint("\nCandidate root (pub key): ", T1)
Byteprint("\nTrue public key: ", LMS_pubkey[2])

if T1 == LMS_pubkey[2]:
   print "\nSignature is valid."
else:
   print "\nYou're being had."

