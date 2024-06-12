# HULA hoop

Implementation of the [HULA](https://conferences.sigcomm.org/sosr/2016/papers/sosr_paper67.pdf) algorithm.

## Requirements

- `bmv2`
- `mininet`
- p4 16 compiler

## Building and running

- Generate topology using `topology-generation/fattree.py` script or use the default one.
- Run `make` and wait for mininet to start up.
- Run `./controller.py` to configure the data plane.
- Run
```bash
h16 ./CAVER_receiver.py >h16.log 2>&1 &
h1 ./CAVER_sender.py h16 1 >h1_1.log 2>&1 &
h1 ./CAVER_sender.py h16 2 >h1_2.log 2>&1 & 
```
and check switch's log file to check function
