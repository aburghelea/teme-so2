#!/bin/bash

make clean && make
cd  tema1-checker-lin
make -f Makefile.checker clean
make -f Makefile.checker
rm sci.ko
cp ../sci.ko .
./test
cd ../
