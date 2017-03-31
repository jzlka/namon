# @file		Makefile
# @author  Jozef Zuzelka (xzuzel00)
# @date    8.2.2017
# @brief   Makefile

######################## Compiler & flags  ##########################
CXX=g++
CXXFLAGS=-std=c++14 -Wall -Wextra -pedantic -g
LDFLAGS=-lpcap -pthread


########################     Variables     ##########################
SHELL:=/bin/bash
SRCDIR=src
OBJDIR=obj
TESTSDIR=tests
BIN=tool
SRC=$(wildcard $(SRCDIR)/*.cpp)
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

debug: CXXFLAGS += -O0 -g -DDEBUG_BUILD
debug: clean all

unit-tests: CXXFLAGS += -I./src/ -DDEBUG_BUILD -g
#unit-tests: clean-tests $(TESTS)
unit-tests: $(TESTS)
$(TESTS): %: %.cpp $(filter-out src/main.cpp,$(SRC))
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	

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
