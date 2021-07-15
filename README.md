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

``` 
     ______            ______                _           
    / ____/___  ____  / ____/_  __________  (_)_  _______
   / /   / __ \/ __ \/ /_  / / / /_  /_  / / / / / / ___/
  / /___/ /_/ / / / / __/ / /_/ / / /_/ /_/ / /_/ (__  ) 
  \____/\____/_/ /_/_/    \__,_/ /___/___/_/\__,_/____/  

usage: main.py [-h] (-s SOURCE | -a ABI) [-c CONTRACT] [-b BLOCKCHAIN_STATE]
               [--solc SOLC_VERSION] [--evm EVM_VERSION]
               [-g GENERATIONS | -t GLOBAL_TIMEOUT] [-n POPULATION_SIZE]
               [-pc PROBABILITY_CROSSOVER] [-pm PROBABILITY_MUTATION]
               [-r RESULTS] [--seed SEED] [--cfg] [--rpc-host RPC_HOST]
               [--rpc-port RPC_PORT] [--data-dependency DATA_DEPENDENCY]
               [--constraint-solving CONSTRAINT_SOLVING]
               [--environmental-instrumentation ENVIRONMENTAL_INSTRUMENTATION]
               [-v]

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Solidity smart contract source code file (.sol).
  -a ABI, --abi ABI     Smart contract ABI file (.json).
  -c CONTRACT, --contract CONTRACT
                        Contract name to be fuzzed (if Solidity source code
                        file provided) or blockchain contract address (if ABI
                        file provided).
  -b BLOCKCHAIN_STATE, --blockchain-state BLOCKCHAIN_STATE
                        Initialize fuzzer with a blockchain state by providing
                        a JSON file (if Solidity source code file provided) or
                        a block number (if ABI file provided).
  --solc SOLC_VERSION   Solidity compiler version (default
                        '0.7.6+commit.7338295f.Linux.gpp'). Installed compiler
                        versions: ['v0.4.26', 'v0.7.6'].
  --evm EVM_VERSION     Ethereum VM (default 'petersburg'). Available VM's:
                        'homestead', 'byzantium' or 'petersburg'.
  -g GENERATIONS, --generations GENERATIONS
                        Number of generations (default 10).
  -t GLOBAL_TIMEOUT, --timeout GLOBAL_TIMEOUT
                        Number of seconds for fuzzer to stop.
  -n POPULATION_SIZE, --population-size POPULATION_SIZE
                        Size of the population.
  -pc PROBABILITY_CROSSOVER, --probability-crossover PROBABILITY_CROSSOVER
                        Size of the population.
  -pm PROBABILITY_MUTATION, --probability-mutation PROBABILITY_MUTATION
                        Size of the population.
  -r RESULTS, --results RESULTS
                        Folder or JSON file where results should be stored.
  --seed SEED           Initialize the random number generator with a given
                        seed.
  --cfg                 Build control-flow graph and highlight code coverage.
  --rpc-host RPC_HOST   Ethereum client RPC hostname.
  --rpc-port RPC_PORT   Ethereum client RPC port.
  --data-dependency DATA_DEPENDENCY
                        Disable/Enable data dependency analysis: 0 - Disable,
                        1 - Enable (default: 1)
  --constraint-solving CONSTRAINT_SOLVING
                        Disable/Enable constraint solving: 0 - Disable, 1 -
                        Enable (default: 1)
  --environmental-instrumentation ENVIRONMENTAL_INSTRUMENTATION
                        Disable/Enable environmental instrumentation: 0 -
                        Disable, 1 - Enable (default: 1)
  -v, --version         show program's version number and exit
```

#### Local Fuzzing (Off-Chain)

``` shell
python3 fuzzer/main.py -s examples/RemiCoin/contracts/RemiCoin.sol -c RemiCoin --solc v0.4.26 --evm byzantium -g 20
```

#### Remote Fuzzing (On-Chain)

``` shell
python3 fuzzer/main.py -a examples/RemiCoin/abi.json -c 0x7dc4f41294697a7903c4027f6ac528c5d14cd7eb -b 5752250 --evm byzantium -g 20 --rpc-host <RPC-HOST> --rpc-port <RPC-PORT>
```
