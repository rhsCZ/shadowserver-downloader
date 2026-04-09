CXX ?= g++
BASE_CXXFLAGS ?= -std=c++17 -Wall -Wextra -pedantic
DEBUG_CXXFLAGS ?= -O0 -g
RELEASE_CXXFLAGS ?= -O3
LDFLAGS ?=
LDLIBS ?= -lcurl -lsqlite3 -lssl -lcrypto

TARGET = shadowserver-downloader
DEBUG_TARGET = shadowserver-downloader-debug
SRC = main.cpp

all: release

debug: CXXFLAGS = $(BASE_CXXFLAGS) $(DEBUG_CXXFLAGS)
debug: $(DEBUG_TARGET)

release: CXXFLAGS = $(BASE_CXXFLAGS) $(RELEASE_CXXFLAGS)
release: $(TARGET)
	strip $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

$(DEBUG_TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET) $(DEBUG_TARGET)

.PHONY: all debug release clean
