#!/bin/sh

HOME="$(pwd)/.."

echo Installing deps...
#apt-get install -y software-properties-common 
#add-apt-repository -y ppa:hvr/ghc 
sudo apt-get update 
#apt-get install -y cabal-install-1.20 ghc-7.8.4 
sudo apt-get install -y cabal-install ghc autoconf
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Setting PATH var and installing sth...
#echo 'export PATH=~/.cabal/bin:/opt/cabal/1.20/bin:/opt/ghc/7.8.4/bin:$PATH' >> ~/.bashrc
#export PATH=~/.cabal/bin:/opt/cabal/1.20/bin:/opt/ghc/7.8.4/bin:$PATH 
cabal update 
cabal install alex happy 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Clonning PFQ repo...
cd "$HOME/libs" 
git clone https://github.com/pfq/PFQ.git 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

cd PFQ 
echo Installing PFQ...
cabal install --only-dep --allow-newer pfq-framework.cabal
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building kernel module?
runhaskell Build.hs install pfq.ko
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

echo Building libpcap...
cd user/libpcap/libpcap* 
autoconf 
./configure && make # && sudo make install 
if [ $? -ne 0 ]; then
	echo FAIL
	exit 1
fi
echo OK

cd "$HOME/libs/PFQ"
ls -s user/libpcap/libpcap* libpcap

# modprobe pfq? TODO
