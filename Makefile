CXX = g++
CXX_FLAGS = -Wall -Wextra -Werror -pedantic -lpcap -std=gnu++2a -O3 -g

TARGET = ipk-sniffer
SRC = $(wildcard src/*.cpp)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXX_FLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)