## Cryptography {#cryptography}

Cryptography is also an indicator we need to consider when we design a proper solution. Choosing the right cryptographic algorithm is important. A checksum or CRC value is no longer considered to be strong protection. Cryptographic key management must be considered as part of a complete security solution.

**Previous Vulnerabilities:**

In [BlackHat 2009](https://www.blackhat.com/presentations/bh-usa-09/CHEN/BHUSA09-Chen-RevAppleFirm-SLIDES.pdf), Chen demonstrated how to add a rootkit to Apple Keyboard firmware via a firmware update.

In [2010](https://media.ccc.de/v/27c3-4174-en-the_hidden_nemesis/related), Weinmann demonstrated how to add a rootkit to ThinkPad embedded controller (EC) firmware via update.

In [2011](https://academiccommons.columbia.edu/doi/10.7916/D8QJ7RG3), Cui demonstrated how to add a rootkit to HP printer firmware via update.

All of the cases above demonstrate the need for firmware locking and authenticated updates.