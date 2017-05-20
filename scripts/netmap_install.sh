#!/bin/sh

HOME="$(pwd)/.."

cd "$HOME/libs/"

echo Downloading kernel sources...
sudo apt-get update
sudo apt-get source linux-headers-$(uname -r)
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Clonning netmap repository...
git clone https://github.com/luigirizzo/netmap 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building...
cd netmap
./configure --kernel-sources=../linux-hwe-4.8.0 && make && sudo make install 
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

echo Modprobe netmap
modprobe netmap
modinfo netmap
#lsmod
