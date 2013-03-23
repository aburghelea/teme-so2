#!/bin/bash

make clean && make
cd  checker
make -f Makefile.checker clean
make -f Makefile.checker
rm sci.ko -rf
cp ../sci.ko .
./test
cd ../
