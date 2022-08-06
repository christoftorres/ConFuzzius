FROM ubuntu:18.04

MAINTAINER Christof Torres (christof.torres@uni.lu)

SHELL ["/bin/bash", "-c"]
RUN apt-get update
RUN apt-get install -y sudo wget tar unzip pandoc python-setuptools python-pip python-dev python-virtualenv git build-essential software-properties-common python3-pip

# Install solidity
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.26/solc-static-linux && chmod +x solc-static-linux && mv solc-static-linux /usr/local/bin/solc
# Install z3
RUN wget https://github.com/Z3Prover/z3/archive/Z3-4.8.5.zip && unzip Z3-4.8.5.zip && rm Z3-4.8.5.zip && cd z3-Z3-4.8.5 && python scripts/mk_make.py --python && cd build && make && sudo make install && cd ../.. && rm -r z3-Z3-4.8.5

WORKDIR /root
COPY examples examples
COPY fuzzer fuzzer
RUN cd fuzzer && pip3 install -r requirements.txt
