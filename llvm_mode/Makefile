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
HELPER_PATH  = $(PREFIX)/lib/afl
BIN_PATH     = $(PREFIX)/bin

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

LLVM_CONFIG ?= llvm-config

CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
               -DVERSION=\"$(VERSION)\" 
ifdef AFL_TRACE_PC
  CFLAGS    += -DUSE_TRACE_PC=1
endif

CXXFLAGS    ?= -O3 -funroll-loops
CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -DVERSION=\"$(VERSION)\" -Wno-variadic-macros

# Mark nodelete to work around unload bug in upstream LLVM 5.0+
CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS)
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

LLVM_STDCXX  = gnu++11
LLVM_NEW_API = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[0-9]' && echo 1 || echo 0 )
ifeq "$(LLVM_NEW_API)" "1"
  $(info [+] llvm_mode detected llvm 10+, enabling neverZero implementation and c++14)
  LLVM_STDCXX = c++14
endif

CLANG_CPPFL  = `$(LLVM_CONFIG) --cxxflags` -fno-rtti -fPIC $(CXXFLAGS) -Wno-deprecated-declarations

# User teor2345 reports that this is required to make things work on MacOS X.

ifeq "$(shell uname)" "Darwin"
  CLANG_LFL += -Wl,-flat_namespace -Wl,-undefined,suppress
endif

# We were using llvm-config --bindir to get the location of clang, but
# this seems to be busted on some distros, so using the one in $PATH is
# probably better.

ifeq "$(origin CC)" "default"
  CC         = clang
  CXX        = clang++
endif

ifndef AFL_TRACE_PC
  PROGS      = ../afl-clang-fast ../afl-llvm-pass.so ../afl-llvm-rt.o ../afl-llvm-rt-32.o ../afl-llvm-rt-64.o ../afl-llvm-common.o ../afl-llvm-dict2file.so
else
  PROGS      = ../afl-clang-fast ../afl-llvm-rt.o ../afl-llvm-rt-32.o ../afl-llvm-rt-64.o 
endif

all: test_deps $(PROGS) test_build all_done

test_deps:
ifndef AFL_TRACE_PC
	@echo "[*] Checking for working 'llvm-config'..."
	@which $(LLVM_CONFIG) >/dev/null 2>&1 || ( echo "[-] Oops, can't find 'llvm-config'. Install clang or set \$$LLVM_CONFIG or \$$PATH beforehand."; echo "    (Sometimes, the binary will be named llvm-config-3.5 or something like that.)"; exit 1 )
else
	@echo "[!] Note: using -fsanitize=trace-pc mode (this will fail with older LLVM)."
endif
	@echo "[*] Checking for working '$(CC)'..."
	@which $(CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(CC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
	@echo "[*] Checking for '../afl-showmap'..."
	@test -f ../afl-showmap || ( echo "[-] Oops, can't find '../afl-showmap'. Be sure to compile AFL first."; exit 1 )
	@echo "[+] All set and ready to build."

../afl-clang-fast: afl-clang-fast.c | test_deps
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf afl-clang-fast ../afl-clang-fast++

../afl-llvm-pass.so: afl-llvm-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

../afl-llvm-rt.o: afl-llvm-rt.o.c | test_deps
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

../afl-llvm-rt-32.o: afl-llvm-rt.o.c | test_deps
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CC) $(CFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

../afl-llvm-rt-64.o: afl-llvm-rt.o.c | test_deps
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

../afl-llvm-common.o: afl-llvm-common.cc afl-llvm-common.h | test_deps
	$(CXX) $(CFLAGS) $(CPPFLAGS) `$(LLVM_CONFIG) --cxxflags` -fno-rtti -fPIC -std=$(LLVM_STDCXX) -c $< -o $@ 

../afl-llvm-dict2file.so:	afl-llvm-dict2file.so.cc ../afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL)  -shared $< -o $@ $(CLANG_LFL) ../afl-llvm-common.o

../afl-ld-lto: afl-ld-lto.c
ifeq "$(LLVM_LTO)" "1"
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@
endif

./SanitizerCoverageLTO.so: instrumentation/SanitizerCoverageLTO.so.cc
ifeq "$(LLVM_LTO)" "1"
	$(CXX) $(CLANG_CPPFL) -Wno-writable-strings -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< -o $@ $(CLANG_LFL) instrumentation/afl-llvm-common.o
	$(CLANG_BIN) $(CFLAGS_SAFE) $(CPPFLAGS) -Wno-unused-result -O0 $(AFL_CLANG_FLTO) -fPIC -c instrumentation/afl-llvm-rt-lto.o.c -o ./afl-llvm-rt-lto.o
	@$(CLANG_BIN) $(CFLAGS_SAFE) $(CPPFLAGS) -Wno-unused-result -O0 $(AFL_CLANG_FLTO) -m64 -fPIC -c instrumentation/afl-llvm-rt-lto.o.c -o ./afl-llvm-rt-lto-64.o 2>/dev/null; if [ "$$?" = "0" ]; then : ; fi
	@$(CLANG_BIN) $(CFLAGS_SAFE) $(CPPFLAGS) -Wno-unused-result -O0 $(AFL_CLANG_FLTO) -m32 -fPIC -c instrumentation/afl-llvm-rt-lto.o.c -o ./afl-llvm-rt-lto-32.o 2>/dev/null; if [ "$$?" = "0" ]; then : ; fi
endif

# laf
./split-switches-pass.so:	instrumentation/split-switches-pass.so.cc instrumentation/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) instrumentation/afl-llvm-common.o
./compare-transform-pass.so:	instrumentation/compare-transform-pass.so.cc instrumentation/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) instrumentation/afl-llvm-common.o
./split-compares-pass.so:	instrumentation/split-compares-pass.so.cc instrumentation/afl-llvm-common.o | test_deps
	$(CXX) $(CLANG_CPPFL) -shared $< -o $@ $(CLANG_LFL) instrumentation/afl-llvm-common.o
# /laf

test_build: $(PROGS)
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	unset AFL_USE_ASAN AFL_USE_MSAN AFL_INST_RATIO; AFL_QUIET=1 AFL_PATH=. AFL_CC=$(CC) ../afl-clang-fast $(CFLAGS) ../test-instr.c -o test-instr $(LDFLAGS)
# Use /dev/null to avoid problems with optimization messing up expected
# branches. See https://github.com/google/AFL/issues/30.
	../afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ../afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please ping <lcamtuf@google.com> to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! You can now use '../afl-clang-fast' to compile programs."

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* test-instr .test-instr0 .test-instr1 
	rm -f $(PROGS) ../afl-clang-fast++
