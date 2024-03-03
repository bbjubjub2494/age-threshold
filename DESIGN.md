# Design
## Why not a plugin?
The project started as a plugin.
I eventually realized that the plugin system was too restrictive for my design.
Encryption can be made to work,
but to support decryption as a plugin,
we need to wrap multiple arbitrary identities into a threshold identity, which I found unwieldly.
`age-plugin-sss` does implement it this way though.

## More complex conditions?
We may want two identities to receive the same share so that they are substitutable.
I am not completely sure how to handle that yet.

## What secret sharing scheme to use?
The natural candidate is the well known Shamir's.
It works very naturally with age file keys,
but the resulting protocol is insecure in the chosen ciphertext setting:
since recipients need to communicate to decrypt messages,
a malicious recipient could craft a ciphertext
that contain an existing encrypted secret share from a different ciphertext
and submit it for decryption, such that an honest recipient will reveal it
and allow the decryption of a completely different message.
This something that always comes up when threshold decryption is discussed.

One way to combat that is Feldman's 1987 verifiable secret sharing scheme,
which allows recipients to check the consistency of the shares.
The issue with it is that it is not quantum-secure:
if a quantum computer shows up, it can just perform discrete logarithm on the commitment without compromising any recipients.
In some scenarios, recipients themselves could be quantum-secure, e.g. passphrases or some of the PQC plugins,
so it's not acceptable to introduce this vulnerability.

[Pedersen's 1991 paper](https://link.springer.com/chapter/10.1007/3-540-46766-1_9) improves Feldman's scheme with perfectly hiding commitments.
This means that we don't immediately lose confidentiality once a quantum computer appears.
The verifiability does become suspect in that scenario, but that's still an improvement over plain Shamir.
