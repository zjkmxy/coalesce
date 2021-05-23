# pyCertCoalesce

TBD

## New example:

Run `demo.py`:
```bash
python3 examples/demo.py
```

## OBSOLETED

Note: old python-ndn had a bug that prevents registering multiple prefixes.
I just uploaded a deployment to fix this so you may need to upgrade: `pip3 install -U python-ndn`.

First start NFD:
```bash
nfd-start
```

Make sure there is no `temp-caterpillar.dat` in the search path.
Start the combined CA server:
```bash
python3 example/combined_ca.py
```

In another terminal, start the device:
```bash
python3 example/device.py
```

Confirm that the device generated a new caterpillar, bootstrapped with the CA, and received a certificate.

In another terminal, start the consumer:
```bash
python3 example/consumer.py
```

Confirm that the consumer recieved the content and validated the signature.

Shutdown the device (`Ctrl+C`) and restart it:
```bash
python3 example/device.py
```

Verify that the device loaded the caterpillar key from `temp-caterpillar.dat`,
and got a certificate without bootstrapping.

Restart the consumer and confirm the consumer can validate the signature:
```bash
python3 example/consumer.py
```
