ConFuzzius
===========

<img src="https://thumbs.dreamstime.com/b/confucius-vector-portrait-line-art-illustration-confucius-line-art-portrait-138676693.jpg" width="200">

A data dependency-aware hybrid fuzzer for Ethereum smart contracts. Our paper can be found [here](https://arxiv.org/pdf/2005.12156.pdf).

## Quick Start

A container with the dependencies set up can be found [here](https://hub.docker.com/r/christoftorres/confuzzius/).

To open the container, install docker and run:

```
docker pull christoftorres/confuzzius && docker run -i -t christoftorres/confuzzius
```

To evaluate a simple contract inside the container, run:

```
python3 fuzzer/main.py -s examples/TokenSale/contracts/TokenSale.sol -c TokenSale --solc v0.4.26 --evm byzantium -t 10
```

and you are done!

## Custom Docker image build

```
docker build -t confuzzius .
docker run -it confuzzius:latest
```

## Installation Instructions

### 1. Install Requirements

#### 1.1 Solidity Compiler

``` shell
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```

#### 1.2 Z3 Prover

Download the [source code of version z3-4.8.5](https://github.com/Z3Prover/z3/releases/tag/Z3-4.8.5)

Install z3 using Python bindings

``` shell
python scripts/mk_make.py --python
cd build
make
sudo make install
```

### 2. Install Fuzzer

``` shell
cd fuzzer
pip install -r requirements.txt
```

## Running Instructions

#### Local Fuzzing (Off-Chain)

``` shell
python3 fuzzer/main.py -s examples/RemiCoin/contracts/RemiCoin.sol -c RemiCoin --solc v0.4.26 --evm byzantium -g 20
```

#### Remote Fuzzing (On-Chain)

``` shell
python3 fuzzer/main.py -a examples/RemiCoin/abi.json -c 0x7dc4f41294697a7903c4027f6ac528c5d14cd7eb -b 5752250 --evm byzantium -g 20 --rpc-host <RPC-HOST> --rpc-port <RPC-PORT>
```
