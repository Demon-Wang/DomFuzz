#
# american fuzzy lop - LLVM instrumentation
# -----------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# LLVM integration design comes from Laszlo Szekeres.
#
# Copyright 2015, 2016 Google LLC All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
HELPER_PATH ?= $(PREFIX)/lib/afl
BIN_PATH    ?= $(PREFIX)/bin
DOC_PATH    ?= $(PREFIX)/share/doc/afl
MISC_PATH   ?= $(PREFIX)/share/afl
MAN_PATH    ?= $(PREFIX)/share/man/man8

BUILD_DATE  ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

LLVM_CONFIG ?= llvm-config

LLVMVER  = $(shell $(LLVM_CONFIG) --version 2>/dev/null | sed 's/git//' | sed 's/svn//' )
LLVM_MAJOR = $(shell $(LLVM_CONFIG) --version 2>/dev/null | sed 's/\..*//' )
LLVM_MINOR = $(shell $(LLVM_CONFIG) --version 2>/dev/null | sed 's/.*\.//' | sed 's/git//' | sed 's/svn//' | sed 's/ .*//' )
LLVM_UNSUPPORTED = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^[0-2]\.|^3.[0-7]\.' && echo 1 || echo 0 )
LLVM_TOO_NEW = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[4-9]' && echo 1 || echo 0 )
LLVM_NEW_API = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[0-9]' && echo 1 || echo 0 )
LLVM_10_OK = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[1-9]|^10\.[1-9]|^10\.0.[1-9]' && echo 1 || echo 0 )
LLVM_HAVE_LTO = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[1-9]' && echo 1 || echo 0 )
LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
LLVM_LIBDIR = $(shell $(LLVM_CONFIG) --libdir 2>/dev/null)
LLVM_STDCXX = gnu++11
LLVM_APPLE_XCODE = $(shell $(CC) -v 2>&1 | grep -q Apple && echo 1 || echo 0)
LLVM_LTO   = 0

ifeq "$(LLVMVER)" ""
  $(warning [!] llvm_mode needs llvm-config, which was not found. Set LLVM_CONFIG to its path and retry.)
endif

ifeq "$(LLVM_UNSUPPORTED)" "1"
  $(error llvm_mode only supports llvm from version 3.8 onwards)
endif

ifeq "$(LLVM_TOO_NEW)" "1"
  $(warning you are using an in-development llvm version - this might break llvm_mode!)
endif

LLVM_TOO_OLD=1

ifeq "$(LLVM_MAJOR)" "9"
  $(info [+] llvm_mode detected llvm 9, enabling neverZero implementation)
  LLVM_TOO_OLD=0
endif

ifeq "$(LLVM_NEW_API)" "1"
  $(info [+] llvm_mode detected llvm 10+, enabling neverZero implementation and c++14)
  LLVM_STDCXX = c++14
  LLVM_TOO_OLD=0
endif

ifeq "$(LLVM_TOO_OLD)" "1"
  $(info [!] llvm_mode detected an old version of llvm, upgrade to at least 9 or preferable 11!)
  $(shell sleep 1)
endif

ifeq "$(LLVM_HAVE_LTO)" "1"
  $(info [+] llvm_mode detected llvm 11+, enabling afl-lto LTO implementation)
  LLVM_LTO = 1
  #TEST_MMAP = 1
endif

ifeq "$(LLVM_LTO)" "0"
  $(info [+] llvm_mode detected llvm < 11, afl-lto LTO will not be build.)
endif

ifeq "$(LLVM_APPLE_XCODE)" "1"
  $(warning llvm_mode will not compile with Xcode clang...)
endif

CC         = $(LLVM_BINDIR)/clang
CXX        = $(LLVM_BINDIR)/clang++

# llvm-config --bindir may not providing a valid path, so ...
ifeq "$(shell test -e $(CC) || echo 1 )" "1"
  # however we must ensure that this is not a "CC=gcc make"
  ifeq "$(shell command -v $(CC) 2> /dev/null)" ""
    # we do not have a valid CC variable so we try alternatives
    ifeq "$(shell test -e '$(BIN_DIR)/clang' && echo 1)" "1"
      # we found one in the local install directory, lets use these
      CC         = $(BIN_DIR)/clang
    else
      # hope for the best
      $(warning we have trouble finding clang - llvm-config is not helping us)
      CC         = clang
    endif
  endif
endif

# llvm-config --bindir may not providing a valid path, so ...
ifeq "$(shell test -e $(CXX) || echo 1 )" "1"
  # however we must ensure that this is not a "CXX=g++ make"
  ifeq "$(shell command -v $(CXX) 2> /dev/null)" ""
    # we do not have a valid CXX variable so we try alternatives
    ifeq "$(shell test -e '$(BIN_DIR)/clang++' && echo 1)" "1"
      # we found one in the local install directory, lets use these
      CXX        = $(BIN_DIR)/clang++
    else
      # hope for the best
      $(warning we have trouble finding clang++ - llvm-config is not helping us)
      CXX        = clang++
    endif
  endif
endif

# sanity check.
# Are versions of clang --version and llvm-config --version equal?
CLANGVER = $(shell $(CC) --version | sed -E -ne '/^.*version\ (1?[0-9]\.[0-9]\.[0-9]).*/s//\1/p')

# I disable this because it does not make sense with what we did before (marc)
# We did exactly set these 26 lines above with these values, and it would break
# "CC=gcc make" etc. usages
ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  CC_SAVE := $(LLVM_BINDIR)/clang
else
  CC_SAVE := $(CC)
endif
ifeq "$(findstring clang, $(shell $(CXX) --version 2>/dev/null))" ""
  CXX_SAVE := $(LLVM_BINDIR)/clang++
else
  CXX_SAVE := $(CXX)
endif

CLANG_BIN := $(CC_SAVE)
CLANGPP_BIN := $(CXX_SAVE)

ifeq "$(CC_SAVE)" "$(LLVM_BINDIR)/clang"
  USE_BINDIR = 1
else
  ifeq "$(CXX_SAVE)" "$(LLVM_BINDIR)/clang++"
    USE_BINDIR = 1
  else
    USE_BINDIR = 0
  endif
endif

ifneq "$(REAL_CC)" ""
  CC  = $(REAL_CC)
endif
ifneq "$(REAL_CXX)" ""
  CXX = $(REAL_CXX)
endif

ifeq "$(shell command -v $(CC) 2>/dev/null)" ""
  CC = cc
endif
ifeq "$(shell command -v $(CXX) 2>/dev/null)" ""
  CXX = c++
endif
#ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
#	CFLAGS_OPT = -march=native
#endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto=full
else
 ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto=thin
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto
  endif
 endif
endif

# ifeq "$(LLVM_LTO)" "1"
#   ifneq "$(AFL_CLANG_FLTO)" ""
#     ifeq "$(AFL_REAL_LD)" ""
#       ifneq "$(shell readlink $(LLVM_BINDIR)/ld.lld 2>&1)" ""
#         AFL_REAL_LD = $(LLVM_BINDIR)/ld.lld
#       else
#         $(warning ld.lld not found, cannot enable LTO mode)
#         LLVM_LTO = 0
#       endif
#     endif
#   else
#     $(warning clang option -flto is not working - maybe LLVMgold.so not found - cannot enable LTO mode)
#     LLVM_LTO = 0
#   endif
# endif

AFL_CLANG_FUSELD=
ifeq "$(LLVM_LTO)" "1"
  ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -fuse-ld=`command -v ld` -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
    AFL_CLANG_FUSELD=1
    ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -fuse-ld=ld.lld --ld-path=$(LLVM_BINDIR)/ld.lld -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
      AFL_CLANG_LDPATH=1
    endif
  else
    $(warning -fuse-ld is not working, cannot enable LTO mode)
    LLVM_LTO = 0
  endif
endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CLANG_BIN) -x c - -fdebug-prefix-map=$(CURDIR)=llvm_mode -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_DEBUG_PREFIX = -fdebug-prefix-map="$(CURDIR)=llvm_mode"
else
        AFL_CLANG_DEBUG_PREFIX =
endif

# CFLAGS      ?= -O3 -funroll-loops
# CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
#                -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
#                -DVERSION=\"$(VERSION)\" 
# ifdef AFL_TRACE_PC
#   CFLAGS    += -DUSE_TRACE_PC=1
# endif

# CXXFLAGS    ?= -O3 -funroll-loops
# CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
#                -DVERSION=\"$(VERSION)\" -Wno-variadic-macros

CFLAGS          ?= -O3 -funroll-loops -fPIC -D_FORTIFY_SOURCE=2
CFLAGS_SAFE     := -Wall -g -Wno-cast-qual -Wno-variadic-macros -Wno-pointer-sign -I ./include/ -I ./llvm_mode/ \
                   -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
                   -DLLVM_BINDIR=\"$(LLVM_BINDIR)\" -DVERSION=\"$(VERSION)\" \
                   -DLLVM_LIBDIR=\"$(LLVM_LIBDIR)\" -DLLVM_VERSION=\"$(LLVMVER)\" \
                   -Wno-deprecated -DAFL_CLANG_FLTO=\"$(AFL_CLANG_FLTO)\" \
                   -DAFL_REAL_LD=\"$(AFL_REAL_LD)\" \
                   -DAFL_CLANG_LDPATH=\"$(AFL_CLANG_LDPATH)\" \
                   -DAFL_CLANG_FUSELD=\"$(AFL_CLANG_FUSELD)\" \
                   -DCLANG_BIN=\"$(CLANG_BIN)\" -DCLANGPP_BIN=\"$(CLANGPP_BIN)\" -DUSE_BINDIR=$(USE_BINDIR) -Wno-unused-function \
                   $(AFL_CLANG_DEBUG_PREFIX)
override CFLAGS += $(CFLAGS_SAFE)

ifdef AFL_TRACE_PC
  $(info Compile option AFL_TRACE_PC is deprecated, just set AFL_LLVM_INSTRUMENT=PCGUARD to activate when compiling targets )
endif

CXXFLAGS          ?= -O3 -funroll-loops -fPIC -D_FORTIFY_SOURCE=2
override CXXFLAGS += -Wall -g -I ./include/ \
                     -DVERSION=\"$(VERSION)\" -Wno-variadic-macros \
                     -DLLVM_MINOR=$(LLVM_MINOR) -DLLVM_MAJOR=$(LLVM_MAJOR)

ifneq "$(shell $(LLVM_CONFIG) --includedir) 2> /dev/null" ""
  CLANG_CFL  = -I$(shell $(LLVM_CONFIG) --includedir)
endif
ifneq "$(LLVM_CONFIG)" ""
  CLANG_CFL += -I$(shell dirname $(LLVM_CONFIG))/../include
endif
CLANG_CPPFL  = `$(LLVM_CONFIG) --cxxflags` -fno-rtti -fPIC $(CXXFLAGS) -Wno-deprecated-declarations
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

CLANG_CPPFL += -Wl,-znodelete


PROGS_ALWAYS = ./afl-cc ./afl-compiler-rt.o ./afl-compiler-rt-32.o ./afl-compiler-rt-64.o 
PROGS        = $(PROGS_ALWAYS)  ./split-compares-pass.so ./split-switches-pass.so ./afl-llvm-dict2file.so ./compare-transform-pass.so ./afl-ld-lto ./SanitizerCoverageLTO.so


TARGETS = $(PROGS) all_done

.PHONY: all
all: $(TARGETS)


llvm_mode/afl-common.o: ./llvm_mode/afl-common.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ $(LDFLAGS)

./afl-cc: llvm_mode/afl-clang-lto.c llvm_mode/afl-common.o
	$(CC) $(CLANG_CFL) $(CFLAGS) $(CPPFLAGS) $< llvm_mode/afl-common.o -o $@ -DLLVM_MINOR=$(LLVM_MINOR) -DLLVM_MAJOR=$(LLVM_MAJOR) $(LDFLAGS) -DCFLAGS_OPT=\"$(CFLAGS_OPT)\" -lm
ifneq "$(AFL_CLANG_FLTO)" ""
ifeq "$(LLVM_LTO)" "1"
	@ln -sf afl-cc ./afl-clang-lto
	@ln -sf afl-cc ./afl-clang-lto++
endif

llvm_mode/afl-llvm-common.o: llvm_mode/afl-llvm-common.cc llvm_mode/afl-llvm-common.h
	$(CXX) $(CFLAGS) $(CPPFLAGS) `$(LLVM_CONFIG) --cxxflags` -fno-rtti -fPIC -std=$(LLVM_STDCXX) -c $< -o $@ 


./afl-ld-lto: llvm_mode/afl-ld-lto.c
ifeq "$(LLVM_LTO)" "1"
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@
endif

./SanitizerCoverageLTO.so: llvm_mode/SanitizerCoverageLTO.so.cc
ifeq "$(LLVM_LTO)" "1"
	$(CXX) $(CLANG_CPPFL) -Wno-writable-strings -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< -o $@ $(CLANG_LFL) llvm_mode/afl-llvm-common.o
	$(CLANG_BIN) $(CFLAGS_SAFE) $(CPPFLAGS) -Wno-unused-result -O0 $(AFL_CLANG_FLTO) -fPIC -c llvm_mode/afl-llvm-rt-lto.o.c -o ./afl-llvm-rt-lto.o
	@$(CLANG_BIN) $(CFLAGS_SAFE) $(CPPFLAGS) -Wno-unused-result -O0 $(AFL_CLANG_FLTO) -m64 -fPIC -c llvm_mode/afl-llvm-rt-lto.o.c -o ./afl-llvm-rt-lto-64.o 2>/dev/null; if [ "$$?" = "0" ]; then : ; fi
	@$(CLANG_BIN) $(CFLAGS_SAFE) $(CPPFLAGS) -Wno-unused-result -O0 $(AFL_CLANG_FLTO) -m32 -fPIC -c llvm_mode/afl-llvm-rt-lto.o.c -o ./afl-llvm-rt-lto-32.o 2>/dev/null; if [ "$$?" = "0" ]; then : ; fi
endif

# laf
./split-switches-pass.so:	llvm_mode/split-switches-pass.so.cc llvm_mode/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) llvm_mode/afl-llvm-common.o
./compare-transform-pass.so:	llvm_mode/compare-transform-pass.so.cc llvm_mode/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) llvm_mode/afl-llvm-common.o
./split-compares-pass.so:	llvm_mode/split-compares-pass.so.cc llvm_mode/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) llvm_mode/afl-llvm-common.o
# /laf

afl-llvm-dict2file.so:	llvm_mode/afl-llvm-dict2file.so.cc llvm_mode/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) llvm_mode/afl-llvm-common.o

./afl-compiler-rt.o: llvm_mode/afl-compiler-rt.o.c
	$(CC) $(CLANG_CFL) $(CFLAGS_SAFE) $(CPPFLAGS) -O3 -Wno-unused-result -fPIC -c $< -o $@

./afl-compiler-rt-32.o: llvm_mode/afl-compiler-rt.o.c
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CC) $(CLANG_CFL) $(CFLAGS_SAFE) $(CPPFLAGS) -O3 -Wno-unused-result -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; ln -sf afl-compiler-rt-32.o afl-llvm-rt-32.o; else echo "failed (that's fine)"; fi

./afl-compiler-rt-64.o: llvm_mode/afl-compiler-rt.o.c
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CC) $(CLANG_CFL) $(CFLAGS_SAFE) $(CPPFLAGS) -O3 -Wno-unused-result -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; ln -sf afl-compiler-rt-64.o afl-llvm-rt-64.o; else echo "failed (that's fine)"; fi

.PHONY: clean
clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* .test2 test-instr .test-instr0 .test-instr1 *.dwo
	rm -f $(PROGS) afl-common.o ./afl-c++ ./afl-lto ./afl-lto++ ./afl-clang-lto* ./afl-clang-fast* ./afl-clang*.8 ./ld ./afl-ld ./afl-llvm-rt*.o llvm_mode/*.o
