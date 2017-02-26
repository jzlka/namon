#!/bin/sh

HOME=$(pwd)/..

echo Installing deps...
sudo apt-get install -y build-essential bison flex linux-headers-$(uname -r) #dkms
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

cd "$HOME/libs"
wget http://apt.ntop.org/16.04/all/apt-ntop.deb 
echo Adding ntop repo...
sudo dpkg -i apt-ntop.deb 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK
rm apt-ntop.deb

sudo apt-get clean all 
sudo apt-get update  
echo Installing pfring...
sudo apt-get install -y pfring 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Clonning pfring repo...
git clone https://github.com/ntop/PF_RING.git 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building..
cd PF_RING/userland/
./configure && make     # make install? TODO
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building libpcap...
cd libpcap && ./configure && make # && sudo make install 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building tcpdump...
cd ../tcpdump && ./configure && make # && sudo make install 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

cd "$HOME/libs/PF_RING"
ln -s userland/libpcap libpcap

# modprobe pf_ring
# modinfo pf_ring
# lsmod
