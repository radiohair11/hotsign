#!/usr/bin/python

# Each node has a [label, value] pair. The object is to compute the value of the node at input_label, which is the hash of the concatenation of the nodes at l_input_label and r_input_label, in that order.

# input_label is a string of '0's and '1's. The root node is labeled 1; left child nodes append a '0' to the parent label, right child nodes append a '1' to the parent label.

# tree_height is the number of layers in the tree.

# Leaf nodes (the list Y) always have values. Intermediate and root nodes may be calculated; only the requested node value is returned.

import random
import hashlib
import binascii


def compute_node(input_label, Y, tree_height):
  result = hashlib.sha256()
  print "input_label = ", input_label, "  tree_height = ", tree_height
  if len(input_label) == tree_height:
    return Y[int(input_label[-tree_height:])]
  else:
    l_input_label = input_label + '0'
    print "l_input_label = ", l_input_label
    r_input_label = input_label + '1'
    print "r_input_label = ", r_input_label
    value.update = compute_node(l_input_label, Y, tree_height)
    value.update = compute_node(r_input_label, Y, tree_height)
    return value.digest()

keyfile = open("keyfile", "rb")
seed = keyfile.read(32)

print "\nSeed: "        # potential endian problem!!!
for i in range (0, 2):
   start = 0+i*16
   end = i*16+16
   print "   ",' '.join(x.encode('hex')for x in seed[start:end])

y = []

value = hashlib.sha256(seed)
print "\nValue: "        # potential endian problem!!!
for i in range (0, 2):
   start = 0+i*16
   end = i*16+16
   print "   ",' '.join(x.encode('hex')for x in value.hexdigest()[start:end])


for i in range(0,8):
  value.update(value.digest())
  y.append(value.hexdigest())
  print "\n"+y[i]


nodevalue = compute_node('1',y,3)

