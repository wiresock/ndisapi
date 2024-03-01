# Compiler settings
CC = g++
CFLAGS = -I$(INCDIR) -Wall -std=c++11 -D_LIB -DCYGWIN_BUILD -D_UNICODE -DUNICODE

# Build configuration
ARCH ?= x64
CONFIG ?= Release

# Set architecture and configuration specific flags
ifeq ($(ARCH),x86)
	CFLAGS += -m32
	OUTPUT_DIR = bin/x86
else
	CFLAGS += -m64
	OUTPUT_DIR = bin/x64
endif

ifeq ($(CONFIG),Debug)
	CFLAGS += -g
	OUTPUT_DIR := $(OUTPUT_DIR)/Debug
else
	CFLAGS += -O2
	OUTPUT_DIR := $(OUTPUT_DIR)/Release
endif

# Directories
SRCDIR = ../ndisapi
INCDIR = ../include

# Source and header files for the library
LIB_SOURCES = $(SRCDIR)/ndisapi.cpp
LIB_HEADERS = $(INCDIR)/Common.h $(INCDIR)/ndisapi.h $(SRCDIR)/iphlp.h $(SRCDIR)/precomp.h $(SRCDIR)/resource.h
LIB_OBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(OUTPUT_DIR)/%.o, $(LIB_SOURCES))
LIBRARY = $(OUTPUT_DIR)/libndisapi.a  # Renaming library file

# Source files for the listadapters example
LISTADAPTERS_SRCS = ../examples/legacy/MSVC/listadapters/listadapters.cpp ../examples/legacy/MSVC/listadapters/StdAfx.cpp
LISTADAPTERS_OBJS = $(patsubst ../examples/legacy/MSVC/listadapters/%.cpp, $(OUTPUT_DIR)/%.o, $(LISTADAPTERS_SRCS))
LISTADAPTERS_EXE = $(OUTPUT_DIR)/listadapters

# Source files for the packthru example
PACKTHRU_SRCS = ../examples/legacy/MSVC/packthru/packthru.cpp ../examples/legacy/MSVC/packthru/StdAfx.cpp
PACKTHRU_OBJS = $(patsubst ../examples/legacy/MSVC/packthru/%.cpp, $(OUTPUT_DIR)/%.o, $(PACKTHRU_SRCS))
PACKTHRU_EXE = $(OUTPUT_DIR)/packthru

# Source files for the filter example
FILTER_SRCS = ../examples/legacy/MSVC/filter/filter.cpp ../examples/legacy/MSVC/filter/StdAfx.cpp
FILTER_OBJS = $(patsubst ../examples/legacy/MSVC/filter/%.cpp, $(OUTPUT_DIR)/%.o, $(FILTER_SRCS))
FILTER_EXE = $(OUTPUT_DIR)/filter

# Source files for the filterstats example
FILTERSTATS_SRCS = ../examples/legacy/MSVC/filterstats/filterstats.cpp ../examples/legacy/MSVC/filterstats/StdAfx.cpp
FILTERSTATS_OBJS = $(patsubst ../examples/legacy/MSVC/filterstats/%.cpp, $(OUTPUT_DIR)/%.o, $(FILTERSTATS_SRCS))
FILTERSTATS_EXE = $(OUTPUT_DIR)/filterstats

# Source files for the gretunnel example
GRETUNNEL_SRCS = ../examples/legacy/MSVC/gretunnel/gretunnel.cpp ../examples/legacy/MSVC/gretunnel/StdAfx.cpp
GRETUNNEL_OBJS = $(patsubst ../examples/legacy/MSVC/gretunnel/%.cpp, $(OUTPUT_DIR)/%.o, $(GRETUNNEL_SRCS))
GRETUNNEL_EXE = $(OUTPUT_DIR)/gretunnel

# Source files for the ndisrequest example
NDISREQUEST_SRCS = ../examples/legacy/MSVC/ndisrequest/ndisrequest.cpp ../examples/legacy/MSVC/ndisrequest/StdAfx.cpp
NDISREQUEST_OBJS = $(patsubst ../examples/legacy/MSVC/ndisrequest/%.cpp, $(OUTPUT_DIR)/%.o, $(NDISREQUEST_SRCS))
NDISREQUEST_EXE = $(OUTPUT_DIR)/ndisrequest

# Source files for the packetsniffer example
PACKETSNIFFER_SRCS = ../examples/legacy/MSVC/packetsniffer/packetsniffer.cpp ../examples/legacy/MSVC/packetsniffer/StdAfx.cpp
PACKETSNIFFER_OBJS = $(patsubst ../examples/legacy/MSVC/packetsniffer/%.cpp, $(OUTPUT_DIR)/%.o, $(PACKETSNIFFER_SRCS))
PACKETSNIFFER_EXE = $(OUTPUT_DIR)/packetsniffer

# Source files for the passthru example
PASSTHRU_SRCS = ../examples/legacy/MSVC/passthru/passthru.cpp ../examples/legacy/MSVC/passthru/StdAfx.cpp
PASSTHRU_OBJS = $(patsubst ../examples/legacy/MSVC/passthru/%.cpp, $(OUTPUT_DIR)/%.o, $(PASSTHRU_SRCS))
PASSTHRU_EXE = $(OUTPUT_DIR)/passthru

# Source files for the wwwcensor example
WWWCENSOR_SRCS = ../examples/legacy/MSVC/wwwcensor/wwwcensor.cpp ../examples/legacy/MSVC/wwwcensor/StdAfx.cpp
WWWCENSOR_OBJS = $(patsubst ../examples/legacy/MSVC/wwwcensor/%.cpp, $(OUTPUT_DIR)/%.o, $(WWWCENSOR_SRCS))
WWWCENSOR_EXE = $(OUTPUT_DIR)/wwwcensor

# Targets
all: $(LIBRARY) $(LISTADAPTERS_EXE) $(PACKTHRU_EXE) $(FILTER_EXE) $(FILTERSTATS_EXE) $(GERTUNNEL_EXE) $(NDISREQUEST_EXE) $(PACKETSNIFFER_EXE) $(PASSTHRU_EXE) $(WWWCENSOR_EXE)

# Library compilation
$(LIBRARY): $(LIB_OBJECTS)
	ar rcs $(LIBRARY) $(LIB_OBJECTS)

$(OUTPUT_DIR)/%.o: $(SRCDIR)/%.cpp $(LIB_HEADERS)
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Listadapters example compilation
$(LISTADAPTERS_EXE): $(LISTADAPTERS_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi  # Updated linker flag

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/listadapters/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# PackThru example compilation
$(PACKTHRU_EXE): $(PACKTHRU_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi  # Updated linker flag

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/packthru/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Filter example compilation
$(FILTER_EXE): $(FILTER_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/filter/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# FilterStats example compilation
$(FILTERSTATS_EXE): $(FILTERSTATS_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/filterstats/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# GRETunnel example compilation
$(GRETUNNEL_EXE): $(GRETUNNEL_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/gertunnel/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# NdisRequest example compilation
$(NDISREQUEST_EXE): $(NDISREQUEST_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/ndisrequest/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# PacketSniffer example compilation
$(PACKETSNIFFER_EXE): $(PACKETSNIFFER_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/packetsniffer/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# PassThru example compilation
$(PASSTHRU_EXE): $(PASSTHRU_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/passthru/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# WWWCensor example compilation 	
$(WWWCENSOR_EXE): $(WWWCENSOR_OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) $^ -o $@ -L$(OUTPUT_DIR) -lndisapi

$(OUTPUT_DIR)/%.o: ../examples/legacy/MSVC/wwwcensor/%.cpp
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf bin




