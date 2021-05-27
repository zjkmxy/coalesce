# pyCertCoalesce

## Super Simplified Design with RBAC (Role-Based Access Control)

- Preparation
    - Let `N` and `G` be the elliptic curve arguments.
    - Let key expansion function `f(role,i) = HKDF(seed, sha256(role)^i)`.
    - A trust schema that decides the roles/scopes binding to each device.
- Bootstrapping
    - DEVICE generates a master ECC key `(a,A)`.
    - DEVICE proves its identity to CA and sends `A` to CA.
    - CA generates an 128-bit AES key `seed`.
    - CA encrypts `seed` with `A` and sends back to DEVICE.
    - DEVICE decrypts `seed` with `a`.
    - DEVICE only needs to store `seed` and `a` in its storage.
- Private Key Derivation
    - DEVICE infers the roles/scopes it has access to and the `i` set from the trust schema.
    - For each role/scope name `role` and time-related number `i` (<=128-bit),
      DEVICE computes `f(role,i)`.
    - The corresponding private key is `b_{role,i} = (a+f(role,i))%N`.
- Public Key Derivation
    - CA infers the roles/scopes DEVICE has access to and the `i` set from the trust schema.
    - For each role/scope name `role` and time-related number `i` (<=128-bit),
      CA computes `f(role,i)`.
    - The corresponding public key is `B_{role,i} = A+f(role,i)*G`.

## Hackathon Demo

[High level description of CertCoalesce](https://named-data.net/publications/certcoalesce-efficient-certificate-pool-for-ndn-based-systems/).

To install the package

```bash
python3 setup.py install
```

## Running the demo

Run `demo.py`:

```bash
python3 examples/demo.py
```
