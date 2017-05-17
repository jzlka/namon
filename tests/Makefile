# @file       Makefile
# @brief      Brief description
# @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
# @date
#  - Created: 24.04.2017 04:50
#  - Edited:  12.05.2017 17:59
# @version    1.0.0
# @par        make: GNU Make 3.81
# @bug
# @todo


SRC=$(wildcard udp_*.cpp)
SRC+=$(wildcard tcp_*.cpp)
TARGETS=$(patsubst %.cpp, %, $(SRC))

CXX=g++
CXXFLAGS=-pedantic -Wall -Wextra -g -O0 -std=c++11
LDFLAGS=
.PHONY: clean

#$(TARGET): $(TARGET).o
#	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

#%: %.cpp
#	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

all : $(TARGETS)

clean:
	-rm $(TARGETS)
	-rm -rf *.dSYM
