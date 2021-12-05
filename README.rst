=========
ham_ident
=========
amateur radio operator cryptographic identity and addressing
============================================================

Copyright 2017 Dean Hall.  See LICENSE for details.

ham_ident_ is a Python_ 3 module to create a `cryptographic credential`_
for identification and authentication that includes the individual's `amateur radio`_
callsign and generates a special asymmetric keypair to assist with `cryptographic addressing`_.

.. _ham_ident: https://github.com/dwhall/ham_ident
.. _Python: https://www.python.org
.. _`cryptographic credential`: https://en.wikipedia.org/wiki/X.509
.. _`amateur radio`: https://life.itu.int/radioclub/ars.htm
.. _`cryptographic addressing`: https://en.wikipedia.org/wiki/Cryptographically_Generated_Address

WARNING: This tool does not protect the private key!
You should not use this credential for meaningful cryptographic security!
In this project, we are using the credential to authenticate
messages for amateur radio communication.

References:

- https://cryptography.io/en/latest/
- https://github.com/andrivet/python-asn1/blob/master/examples/dump.py
