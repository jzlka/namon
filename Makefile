# @file       Makefile
# @brief      Makefile
# @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
# @date
#  - Created: 08.02.2017
#  - Edited:  11.04.2017 10:53
# @version    1.0.0
# @par        make: GNU Make 3.81

######################## Compiler & flags  ##########################
CXX=g++
CXXFLAGS=-std=c++14 -O3 -Wall -Wextra -pedantic
LDFLAGS=-lpcap -pthread


########################     Variables     ##########################
SHELL:=/bin/bash
SRCDIR=src
OBJDIR=obj
TESTSDIR=tests
BIN=tool
SRC_TMP=$(wildcard $(SRCDIR)/*.cpp)
SRC=$(filter-out src/tool%,$(SRC_TMP))

ifeq ($(OS),Windows_NT)
	SRC += $(SRCDIR)/tool_win.cpp
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		SRC += $(SRCDIR)/tool_linux.cpp
	endif
	ifeq ($(UNAME_S),Darwin)
		SRC += $(SRCDIR)/tool_apple.cpp
	endif
endif

OBJ=$(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRC))
TESTS=$(patsubst %.cpp, %, $(wildcard $(TESTSDIR)/*.cpp))
#if [ "$(uname -a | grep -i "Darwin")" == "" ]; then
#	setcap cap_net_raw ./$(BIN)
#else
#	chmod +r /dev/bpf*


.PHONY: test, clean, pack, doxygen, debug, unit-tests, directories

######################    #######################
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

all: directories $(BIN)

$(BIN): $(OBJ) 
	$(CXX) -o $@ $^ $(LDFLAGS)

directories:
	@mkdir -p $(OBJDIR)


debug: TMP := $(CXXFLAGS)
debug: CXXFLAGS = $(filter-out -O3,$(TMP)) -O0 -g -DDEBUG_BUILD
debug: clean all

tests: CXXFLAGS += -I./src/ -DDEBUG_BUILD -g
#tests: clean-tests $(TESTS)
tests: $(TESTS)
$(TESTS): %: %.cpp $(filter-out src/main.cpp,$(SRC))
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)


# -------------------------------------
libs:
	@mkdir -p libs
	@cd scripts && ./install_libs.sh
	
pf_ring: CXXFLAGS += -I./libs/PF_RING/libpcap -I./libs/PF_RING/lib
pf_ring: LDFLAGS += -lpfring -L./libs/PF_RING/libpcap -L./libs/PF_RING/lib
pf_ring: debug

netmap: CXXFLAGS += -I./libs/netmap/libpcap -I./libs/netmap/lib
netmap: LDFLAGS += -L./libs/netmap/libpcap -L./libs/netmap/lib
netmap: debug

pfq: CXXFLAGS += -I./libs/PFQ/libpcap -I./libs/PFQ/lib
pfq: LDFLAGS += -L./libs/PFQ/libpcap -L./libs/PFQ/lib
pfq: debug

# -------------------------------------
test: all
	#valgrind --tool=callgrind ./$(BIN)
	@echo
	-$(shell echo "# CppCheck test..."; cppcheck -v --enable=all --language=c++ -f --std=c++11 --error-exitcode=10 $(SRCDIR)/*.cpp >/dev/null 2>&1; if [ $$? -eq 10 ]; then echo "# ERROR"; else "# OK"; fi)
	-$(shell echo "# Valgrind test..."; valgrindResult=$$(valgrind ./$(BIN) 2>&1 >/dev/null) ; if [ $$(echo $$valgrindResult | grep "ERROR SUMMARY: 0 errors from 0 contexts" | wc -l) = "1" ]; then echo "# OK" ; else /bin/echo '#'; echo "$$valgrindResult" | grep "ERROR SUMMARY:" ; fi)



# -------------------------------------
pack: clean
	tar czf xzuzel00.tar.gz src/ tests/ Makefile README.md doxygen.conf
#	zip -r

doxygen:
	doxygen doxygen.conf

clean: 
	rm -f  $(BIN) xzuzel00.tar.gz .fuse_hidden*
	rm -rf *.dSYM $(OBJDIR)
clean-tests:
	rm -f $(TESTS)
	rm -rf $(TESTSDIR)/*.dSYM
clean-all: clean clean-tests
	rm -rf doc/
