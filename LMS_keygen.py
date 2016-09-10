#!/usr/bin/python

import os.path
import random
from LMS_func import *

if os.path.exists("keyfile") or os.path.exists("statefile"):
  print "\nSignature scheme already initialized. "
  
else:

# Generate LMS private key
  keyfile = open("keyfile","wb",0)
  keyfile.write(bytstr(random.getrandbits(256),32))

# Initialize state file
  statefile = open("statefile","w",0)
  statefile.write('\x00')

  keyfile.close()
  statefile.close()

