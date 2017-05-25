# @file       Makefile
# @brief      Makefile
# @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
# @date
#  - Created: 08.02.2017
#  - Edited:  25.05.2017 17:03
# @version    1.0.0
# @par        make: GNU Make 3.81

######################## Compiler & flags  ##########################
#CXX=g++
CXXFLAGS=-std=c++14 -O3 -Wall -Wextra -pedantic
LDFLAGS=-lpcap -pthread


########################     Variables     ##########################
SHELL:=/bin/bash
SRCDIR=src
OBJDIR=obj
TESTSDIR=tests
BINDIR=bin
BIN=tool
SRC_TMP=$(wildcard $(SRCDIR)/*.cpp)
SRC=$(filter-out src/tool_%,$(SRC_TMP))

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


.PHONY: test, clean, pack, doxygen, debug, unit-tests, directories, pf_ring, libs, netmap

######################    #######################
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(LDFLAGS)

all: directories $(BIN)

$(BIN): $(OBJ) 
	$(CXX) $(CXXFLAGS) -o $(BINDIR)/$@ $^ $(LDFLAGS)

directories:
	@mkdir -p $(BINDIR) $(OBJDIR)


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
	
pf_ring: CXXFLAGS += -I./libs/PF_RING/libpcap -I./libs/PF_RING/userland/lib
pf_ring: LDFLAGS += -L./libs/PF_RING/libpcap -L./libs/PF_RING/userland/lib #-lpfring 
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
	tar czf bp.tar.gz src/ tests/ win32/ docs/*.pdf docs/mainpage.dox docs/doxygen.conf Makefile README.md LICENSE appveyor.yml .travis.yml
#	zip -r

doxygen:
	doxygen docs/doxygen.conf

clean: 
	rm -f xzuzel00.tar.gz .fuse_hidden*
	rm -rf *.dSYM $(OBJDIR) $(BINDIR)
clean-tests:
	rm -f $(TESTS)
	rm -rf $(TESTSDIR)/*.dSYM
clean-doc:
	rm -rf docs/latex docs/html
clean-all: clean clean-tests clean-doc
