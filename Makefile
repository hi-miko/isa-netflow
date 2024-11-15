CXX = g++
CC = $(CXX)
LDLIBS= -lpcap
CXXFLAGS = -Wall -Wextra -Wpedantic -std=c++11 -g
VPATH = src

EXECUTABLE = p2nprobe

SRC = p2nprobe.cpp client-args.cpp flow.cpp flow-manager.cpp debug-info.cpp

OBJECTS = $(SRC:.cpp=.o)

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)

.PHONY: clean

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)
