#!/bin/bash

mkdir -p ../libs

read -p "Download & Install PF_RING? [N/y]: " PFRING
if [ "$PFRING" == "y" ]; then
    ./pfring_install.sh
    if [ $? -ne 0 ]; then echo; echo "***** PF_RING error *****"; exit 1; fi
fi

read -p "Download & Install PFQ? [N/y]: " PFQ
if [ "$PFQ" == "y" ]; then
    ./pfq_install.sh
    if [ $? -ne 0 ]; then echo; echo "***** PFQ error *****"; exit 1; fi
fi

read -p "Download & Install Netmap? [N/y]: " NETMAP
if [ "$NETMAP" == "y" ]; then
    ./netmap_install.sh
    if [ $? -ne 0 ]; then echo; echo "***** Netmap error *****"; exit 1; fi
fi

read -p "Download & Install PcapPlusPlus? [N/y]: " PCAPPP
if [ "$PCAPPP" == "y" ]; then
    ./pcpp_install.sh
    if [ $? -ne 0 ]; then echo; echo "***** PcapPlusPlus error *****"; exit 1; fi
fi


echo "Starting benchmarks"
cd ../
#make
#TODO
