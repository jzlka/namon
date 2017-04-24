# @file       Makefile
# @brief      Brief description
# @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
# @date
#  - Created: 24.04.2017 04:50
#  - Edited:  24.04.2017 05:18
# @version    1.0.0
# @par        make: GNU Make 3.81
# @bug
# @todo


SRC=$(wildcard udp_*.cpp)
SRC+=$(wildcard tcp_*.cpp)
TARGETS=$(patsubst %.cpp, %, $(SRC))

CXX=g++
CXXFLAGS=-std=c++14 -pedantic -Wall -Wextra -g -O2
LDFLAGS=
.PHONY: clean

#$(TARGET): $(TARGET).o
#	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

#%: %.cpp
#	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

all : $(TARGETS)

clean:
	-rm $(TARGETS) $(TARGETS).o
	-rm -rf *.dSYM
