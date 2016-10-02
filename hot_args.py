#!/usr/bin/python
'''
hot_args [COMMAND]

COMMAND:     --keygen
             --sign
             ---validate
'''

import sys

try:
   if sys.argv[1] == "--keygen":
      print "Generating key..."
   elif sys.argv[1] == "--sign":
      print "Signing..."
   elif sys.argv[1] == "--validate":
      print "Validating..."
   else:
      print "Unknown option"
except IndexError:
   print __doc__
