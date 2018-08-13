# hotsign
**hotsign** is a Python implementation of the LMS hash-based signature scheme described in the Internet-Draft ["Hash Based Signatures"] (https://www.ietf.org/archive/id/draft-mcgrew-hash-sigs-04.txt)<draft-mcgrew-hash-sigs>.

Manifest:

* hotsign.py          - The main attraction.
* LMS_keygen.py        - Generates an LMS keypair and associated data.
* LMS_sign.py          - Signs a message (contained in a file).
* LMS_verify.py        - Verifies the putative signature (contained in a different file)
* typecode_registry.py - A... typecode registry. Read the draft.
* message              - The message to be signed.

Files that will be created when **hotsign** is run:

* prvkeyfile           - The LMS private key.
* statefile            - The current message number, initialized to 0.
* nodefile             - A list of Merkle tree nodes, number and value pairs.
* pubkeyfile           - The LMS public key.
* sig.message          - The message signature.

Usage: 
```
hotsign.py keygen [-n <16|32>] [-w <1|2|4|8>] [-h <5|10|20>]
           sign <message fn> <private key fn>
           verify <message fn> <public key fn>
```
