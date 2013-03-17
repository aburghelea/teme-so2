#!/bin/bash

make clean && make
cd  tema1-checker-lin
make -f Makefile.checker clean
make -f Makefile.checker
cp ../sci.ko .
cd ../
./tema1-checker-lin/test
