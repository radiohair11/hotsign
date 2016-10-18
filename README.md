# hot_sign
hot_sign is a poor but possibly correct Python implementation of the LMS hash-based signature scheme described in the Internet-Draft "Hash Based Signatures" <draft-mcgrew-hash-sigs>.

NOTE: This README describes an objective for the code in this repository. The code as it currently exists will not perform what is described here. If you are reading this, it means you're being paid to do so, or have stumbled onto an unfortunate part of the Internet. Curiosity killed the cat; go outside and get some fresh air, why don'cha.

Manifest:

hot_sign.py          - The main attraction.
LMS_keygen.py        - Generates an LMS keypair and associated data.
LMS_sign.py          - Signs a message (contained in a file).
LMS_verify.py        - Verifies the putative signature (sigfile)
typecode_registry.py - A typecode registry.
prvkeyfile           - The LMS private key.
statefile            - The current message number, initialized to 0.
nodefile             - A list of Merkle tree nodes, number and value pairs.
pubkeyfile           - The LMS public key.
sigfile              - The message signature.
message              - The message to be signed.

Usage: 

hot_sign.py keygen [-n <16|32>] [-w <1|2|4|8>] [-h <5|10|20>]
            sign <message fn> <private key fn>
            verify <message fn> <public key fn>
