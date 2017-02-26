#!/bin/sh

HOME=$(pwd)/..

cd "$HOME/libs/"
echo Clonning netmap repo...
git clone https://github.com/luigirizzo/netmap 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building...
cd netmap
./configure && make && sudo make install 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

git clone https://github.com/luigirizzo/netmap-libpcap
cd netmap-libpcap
./configure && make #&& sudo make install 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

cd "$HOME/libs/netmap"
ln -s netmap-libpcap libpcap

#echo Modprobe netmap
# modprobe netmap
# modinfo netmap
#lsmod
