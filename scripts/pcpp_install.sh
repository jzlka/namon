#!/bin/sh

HOME="$(pwd)/.."

cd "$HOME/"
echo Clonning PcapPlusPlus repository...
git clone https://github.com/seladb/PcapPlusPlus
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building..
cd PcapPlusPlus
./configure-linux.sh --default && make # make install? TODO
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK
