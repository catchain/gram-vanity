# Security

Gram Vanity makes wallet keys. Treat any bug that can leak words 13–24, or let somebody else take an address, as critical.

## Report a problem

Do not open a public issue. Use GitHub private reporting: **Security → Report a vulnerability** in this repository.

Give:

- what an attacker can do;
- the steps to reproduce;
- the version (commit hash).

## Scope

In scope:

- leak of words 13–24 or of the signing key (network, disk, logs, other browser origins);
- a key change that an attacker can replay, change or front-run;
- a wrong address or key from words (derivation bugs);
- local API access from other sites (CSRF, DNS rebinding).

Known and accepted (see README):

- A GPU server learns words 1–12. Until the key change, its owner can take the address, but not funds.
- Copies of the words in HTTP buffers are not zeroized.
