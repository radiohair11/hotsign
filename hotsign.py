#!/usr/bin/python
'''
hotsign [COMMAND]

COMMAND:     keygen [-n <hash width>] [-w <part width>] [-h <tree height>]
             sign <message filename>
             verify <message filename> <signature filename>
'''
'''
Dave Changelog
- Changing print statements to python3 syntax
- xrange() => range for python3
- input() => input() for py3
- HMAC objects need to have .digest() run on them so that they can be printed, concat'd with strings, etc. this turns them into byte objects
- HMAC.digest() returns a "bytes object". use .hex() on a bytes object to print it as hex
- Byteprint() seems unnecessary. you need to convert the keys to hex anyway, and python can just print hex. use print("caption" + <hex_representation_of_key>) instead or rewrite Byteprint to .hex() the second arg
- calc_LMS_pub() needs work. i'm not sure what i did is working
'''


import sys
from os import _exit as EXIT
from os import path

args = sys.argv[1:]

try:
   if args[0] == "keygen":

      if path.exists("keyfile") or path.exists("statefile"):
         print("\nSignature scheme already initialized.\n")
         EXIT(1)

      print("\nGenerating key...")
      MHWD = 32; MSLC = 4; THGT = 5     # Set defaults
      for i in range(1, len(args), 2):
         if args[i] == '-n':
            if args[i+1] == '16' or args[i+1] == '32':
               MHWD = int(args[i+1])
            else:
               print("\nHash width 'n' must be 16 or 32 bytes.")
               EXIT(1)
         elif args[i] == '-w':
            if (args[i+1] == '1' or args[i+1] == '2' or
                args[i+1] == '4' or args[i+1] == '8'):
               MSLC = int(args[i+1])
            else:
               print("\nPartition width 'w' must be 1, 2, 4, or 8.")
               EXIT(1)
         elif args[i] == '-h':
            if args[i+1] == '5' or args[i+1] == '10' or args[i+1] == '20':
               THGT = int(args[i+1])
            else:
               print("\nTree height 'h' must be 5, 10, or 20.")
               EXIT(1)
         else:
            print("Unrecognized parameter.")
            
      from LMS_keygen import LMS_keygen
      LMS_keygen(MHWD, MSLC, THGT)
      print("\n... Done.")

   elif args[0] == "sign":

      if path.exists("sig."+args[1]):
         do_anyway = input('Signature file exists; type "yes" to overwrite: ')
         if do_anyway != "yes":
            print("No signature created.")
            EXIT(1)
      if not path.exists(args[1]):
         print("\nMessage file does not exist."); EXIT()
#      elif !path.exists(args[2]):
#        print "\nPublic key file does not exist."; EXIT()
      else:
         print("\nSigning...")
         from LMS_sign import LMS_sign
         LMS_sign(args[1])
         print("\n... Done.")

   elif sys.argv[1] == "verify":
      if not path.exists(args[1]):
         print("\nMessage file does not exist."); EXIT()
      elif not path.exists(args[2]):
         print("\nSignature file does not exist."); EXIT()
      else:
         print("\nVerifying...")
         from LMS_verify import LMS_verify
         LMS_verify(args[1], args[2])
         print("\n... Done.")
   else:
      print("Unknown option")
except IndexError:
   print(__doc__)
