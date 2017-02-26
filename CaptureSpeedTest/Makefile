CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Wextra
LDFLAGS=-lpcap -lpthread -lrt -ldl -lpfring 

SHELL:=/bin/bash
SRC_DIR=src
LIBS_DIR=libs
BIN_DIR=bin
SCRIPTS_DIR=scripts

PCAPPPLUSPLUS_HOME := PcapPlusPlus
PCAPPP_INCLUDES := -I$(PCAPPPLUSPLUS_HOME)/Dist/header
PCAPPP_LIBS_DIR := -L$(PCAPPPLUSPLUS_HOME)/Dist
PCAPPP_LDFLAGS := -lPcap++ -lPacket++ -lCommon++

LIBS:=$(wildcard $(LIBS_DIR)/*)
BENCHMARKS:=$(patsubst $(LIBS_DIR)/%, %_benchmark, $(LIBS))
PCAPPP_BENCHMARKS=
ifneq	($(wildcard $(PCAPPPLUSPLUS_HOME)),)
PCAPPP_BENCHMARKS:=$(patsubst %, pcpp_%, $(BENCHMARKS))
endif



all: directories libpcap_benchmark $(BENCHMARKS) $(PCAPPP_BENCHMARKS)



libpcap_benchmark: $(SRC_DIR)/libpcap_benchmark.cpp
	$(CXX) $(CXXFLAGS) $< -o $(BIN_DIR)/$@ $(LDFLAGS)

pcpp_benchmark: $(SRC_DIR)/pcpp_benchmark.cpp
	$(CXX) $(CXXFLAGS) $(PCAPPP_INCLUDES) $(PCAPPP_LIBS_DIR) $< -o $(BIN_DIR)/$@ $(PCAPPP_LDFLAGS) $(LDFLAGS)

pfring_pcpp_benchmark: $(SRC_DIR)/pfring_pcpp_benchmark.cpp
	$(CXX) $(CXXFLAGS) -DUSE_PF_RING $(PCAPPP_INCLUDES) $(PCAPPP_LIBS_DIR) -Llibs/PF_RING/userland -Llibs/PF_RING/userland/lib  -Ilibs/PF_RING/userland/lib $< -o $(BIN_DIR)/$@ $(PCAPPP_LDFLAGS) $(LDFLAGS)

$(BENCHMARKS): %: $(SRC_DIR)/libpcap_benchmark.cpp 
	$(eval TMP:=$(shell echo $@ | tr A-Z a-z))
	$(eval LIB:=$(patsubst %_benchmark,%,$@))
	$(CXX) $(CXXFLAGS) -I$(LIBS_DIR)/$(LIB)/libpcap -L$(LIBS_DIR)/$(LIB)/libpcap -I$(LIBS_DIR)/$(LIB)/lib -L$(LIBS_DIR)/$(LIB)/lib $< -o $(BIN_DIR)/$(TMP) $(LDFLAGS) 

$(PCAPPP_BENCHMARKS): %: pcpp_benchmark pfring_pcpp_benchmark $(SRC_DIR)/pcpp_benchmark.cpp
	$(eval TMP:=$(shell echo $@ | tr A-Z a-z))
	$(eval LIB:=$(patsubst pcpp_%_benchmark,%,$@))
	$(CXX) $(CXXFLAGS) $(PCAPPP_INCLUDES) $(PCAPPP_LIBS_DIR) -I$(LIBS_DIR)/$(LIB)/libpcap -L$(LIBS_DIR)/$(LIB)/libpcap -I$(LIBS_DIR)/$(LIB)/lib -L$(LIBS_DIR)/$(LIB)/lib $(lastword $^) -o $(BIN_DIR)/$(TMP) $(PCAPPP_LDFLAGS) $(LDFLAGS)



directories:
	mkdir -p bin


clean:
	rm -rf $(BIN_DIR)
clean_libs:
	for library in $(LIBS); do\
		cd ./$$library && make clean;\
		cd -;\
	done
ifneq	($(wildcard $(PCAPPPLUSPLUS_HOME)),)
	cd $(PCAPPPLUSPLUS_HOME) && make clean;
	cd ../ 
	rm -rf $(PCAPPLUSPLUS_HOME)
endif
	rm -rf $(LIBS_DIR)
clean_all: clean_libs clean
