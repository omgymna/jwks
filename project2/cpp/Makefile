# Variables
CXX = g++
CXXFLAGS = -std=c++11 -I./httplib -I./jwt-cpp/include
LDFLAGS =  -lssl -lcrypto
TARGET = jwks_server
SOURCES = main.cpp

# Get the path to the OpenSSL installation from Homebrew
OPENSSL_PREFIX := $(shell brew --prefix openssl)

# Add the path to the OpenSSL headers to the CXXFLAGS variable
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
CXXFLAGS += -I$(OPENSSL_PREFIX)/include

# Default target
all: fetch $(TARGET)

# Target to build the program
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

# Target to fetch the required libraries
fetch:
	# Check if httplib directory exists, if not fetch it
	@if [ ! -d "httplib" ]; then \
		git clone https://github.com/yhirose/cpp-httplib.git httplib; \
	fi

	# Check if jwt-cpp directory exists, if not fetch it
	@if [ ! -d "jwt-cpp" ]; then \
		git clone https://github.com/Thalhammer/jwt-cpp.git; \
	fi

clean:
	rm -rf $(TARGET) httplib jwt-cpp

.PHONY: all fetch clean
