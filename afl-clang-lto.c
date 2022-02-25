/*
   american fuzzy lop++ - compiler instrumentation wrapper
   -------------------------------------------------------

   Written by Michal Zalewski, Laszlo Szekeres and Marc Heuse

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <assert.h>

#if (LLVM_MAJOR - 0 == 0)
  #undef LLVM_MAJOR
#endif
#if !defined(LLVM_MAJOR)
  #define LLVM_MAJOR 0
#endif
#if (LLVM_MINOR - 0 == 0)
  #undef LLVM_MINOR
#endif
#if !defined(LLVM_MINOR)
  #define LLVM_MINOR 0
#endif

static u8 * obj_path;                  /* Path to runtime libraries         */
static u8 **cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   clang_mode;                /* Invoked as afl-clang*?            */
static u8   llvm_fullpath[PATH_MAX];
static u8   instrument_mode, instrument_opt_mode, ngram_size, ctx_k, lto_mode;
static u8   compiler_mode, plusplus_mode, have_instr_env = 0;
static u8   have_gcc, have_llvm, have_gcc_plugin, have_lto, have_instr_list = 0;
static u8 * lto_flag = AFL_CLANG_FLTO, *argvnull;
static u8   debug;
static u8   cwd[4096];
static u8   cmplog_mode;
u8          use_stdin;                                             /* dummy */
// static u8 *march_opt = CFLAGS_OPT;

u8 *getthecwd() {

  if (getcwd(cwd, sizeof(cwd)) == NULL) {

    static u8 fail[] = "";
    return fail;

  }

  return cwd;

}

/* Try to find a specific runtime we need, returns NULL on fail. */

/*
  in find_object() we look here:

  1. if obj_path is already set we look there first
  2. then we check the $AFL_PATH environment variable location if set
  3. next we check argv[0] if it has path information and use it
    a) we also check ../lib/afl
  4. if 3. failed we check /proc (only Linux, Android, NetBSD, DragonFly, and
     FreeBSD with procfs)
    a) and check here in ../lib/afl too
  5. we look into the AFL_PATH define (usually /usr/local/lib/afl)
  6. we finally try the current directory

  if all these attempts fail - we return NULL and the caller has to decide
  what to do.
*/

static u8 *find_object(u8 *obj, u8 *argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash = NULL, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/%s", afl_path, obj);

    if (debug) DEBUGF("Trying %s\n", tmp);

    if (!access(tmp, R_OK)) {

      obj_path = afl_path;
      return tmp;

    }

    ck_free(tmp);

  }

  if (argv0) {

    slash = strrchr(argv0, '/');

    if (slash) {

      u8 *dir = ck_strdup(argv0);

      slash = strrchr(dir, '/');
      *slash = 0;

      tmp = alloc_printf("%s/%s", dir, obj);

      if (debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        obj_path = dir;
        return tmp;

      }

      ck_free(tmp);
      tmp = alloc_printf("%s/../lib/afl/%s", dir, obj);

      if (debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        u8 *dir2 = alloc_printf("%s/../lib/afl", dir);
        obj_path = dir2;
        ck_free(dir);
        return tmp;

      }

      ck_free(tmp);
      ck_free(dir);

    }


  }

  tmp = alloc_printf("%s/%s", AFL_PATH, obj);

  if (debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) {

    obj_path = AFL_PATH;
    return tmp;

  }

  ck_free(tmp);

  tmp = alloc_printf("./%s", obj);

  if (debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) {

    obj_path = ".";
    return tmp;

  }

  ck_free(tmp);

  if (debug) DEBUGF("Trying ... giving up\n");

  return NULL;

}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char **argv, char **envp) {

  u8 fortify_set = 0, asan_set = 0, x_set = 0, bit_mode = 0, shared_linking = 0,
     preprocessor_only = 0, have_unroll = 0, have_o = 0, have_pic = 0,
     have_c = 0, partial_linking = 0;

  cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

  if (lto_mode) {
    if (lto_flag[0] != '-')
      FATAL(
          "Using afl-clang-lto is not possible because Makefile magic did not "
          "identify the correct -flto flag");
  }

    u8 *alt_cc = getenv("AFL_CC");

    if (!alt_cc) {

      alt_cc = "clang";

      }

    cc_params[0] = alt_cc;

    cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";


    if (getenv("AFL_LLVM_DICT2FILE")) {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/afl-llvm-dict2file.so", obj_path);

    }

    // laf
    if (getenv("LAF_SPLIT_SWITCHES") || getenv("AFL_LLVM_LAF_SPLIT_SWITCHES")) {

      if (lto_mode && !have_c) {

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/split-switches-pass.so", obj_path);

      } else {

        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] = "-load";
        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/split-switches-pass.so", obj_path);

      }

    }

    if (getenv("LAF_TRANSFORM_COMPARES") ||
        getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES")) {

      if (lto_mode && !have_c) {

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/compare-transform-pass.so", obj_path);

      } else {

        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] = "-load";
        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/compare-transform-pass.so", obj_path);

      }

    }

    if (getenv("LAF_SPLIT_COMPARES") || getenv("AFL_LLVM_LAF_SPLIT_COMPARES") ||
        getenv("AFL_LLVM_LAF_SPLIT_FLOATS")) {

      if (lto_mode && !have_c) {

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/split-compares-pass.so", obj_path);

      } else {

        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] = "-load";
        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/split-compares-pass.so", obj_path);

      }

    }

    // /laf

    unsetenv("AFL_LD");
    unsetenv("AFL_LD_CALLER");


#if LLVM_MAJOR >= 13
    // fuck you llvm 13
    cc_params[cc_par_cnt++] = "-fno-experimental-new-pass-manager";
#endif

    if (lto_mode && !have_c) {

      u8 *ld_path = NULL;
      if (getenv("AFL_REAL_LD")) {

        ld_path = strdup(getenv("AFL_REAL_LD"));

      } else {

        ld_path = strdup(AFL_REAL_LD);

      }

      if (!ld_path || !*ld_path) { ld_path = strdup("ld.lld"); }
      if (!ld_path) { PFATAL("Could not allocate mem for ld_path"); }
#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 12
      cc_params[cc_par_cnt++] = alloc_printf("--ld-path=%s", ld_path);
#else
      cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", ld_path);
#endif
      free(ld_path);

      cc_params[cc_par_cnt++] = "-Wl,--allow-multiple-definition";
      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/SanitizerCoverageLTO.so", obj_path);
      cc_params[cc_par_cnt++] = lto_flag;

    }
    // cc_params[cc_par_cnt++] = "-Qunused-arguments";

    // in case LLVM is installed not via a package manager or "make install"
    // e.g. compiled download or compiled from github then its ./lib directory
    // might not be in the search path. Add it if so.

    if (lto_mode && argc > 1) {

      u32 idx;
      for (idx = 1; idx < argc; idx++) {

        if (!strncasecmp(argv[idx], "-fpic", 5)) have_pic = 1;

      }

      if (!have_pic) cc_params[cc_par_cnt++] = "-fPIC";

    }


  /* Detect stray -v calls from ./configure scripts. */

  u8 skip_next = 0, non_dash = 0;
  while (--argc) {

    u8 *cur = *(++argv);

    if (skip_next) {

      skip_next = 0;
      continue;

    }

    if (cur[0] != '-') { non_dash = 1; }
    if (!strncmp(cur, "--afl", 5)) continue;
    if (lto_mode && !strncmp(cur, "-fuse-ld=", 9)) continue;
    if (lto_mode && !strncmp(cur, "--ld-path=", 10)) continue;
    if (!strncmp(cur, "-fno-unroll", 11)) continue;
    if (strstr(cur, "afl-compiler-rt") || strstr(cur, "afl-llvm-rt")) continue;
    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined") ||
        !strcmp(cur, "--no-undefined")) {

      continue;

    }

    if (!strcmp(cur, "-z") || !strcmp(cur, "-Wl,-z")) {

      u8 *param = *(argv + 1);
      if (!strcmp(param, "defs") || !strcmp(param, "-Wl,defs")) {

        skip_next = 1;
        continue;

      }

    }

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-x")) x_set = 1;
    if (!strcmp(cur, "-E")) preprocessor_only = 1;
    if (!strcmp(cur, "-shared")) shared_linking = 1;
    if (!strcmp(cur, "-dynamiclib")) shared_linking = 1;
    if (!strcmp(cur, "-Wl,-r")) partial_linking = 1;
    if (!strcmp(cur, "-Wl,-i")) partial_linking = 1;
    if (!strcmp(cur, "-Wl,--relocatable")) partial_linking = 1;
    if (!strcmp(cur, "-r")) partial_linking = 1;
    if (!strcmp(cur, "--relocatable")) partial_linking = 1;
    if (!strcmp(cur, "-c")) have_c = 1;

    if (!strncmp(cur, "-O", 2)) have_o = 1;
    if (!strncmp(cur, "-funroll-loop", 13)) have_unroll = 1;

    cc_params[cc_par_cnt++] = cur;

  }

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set) cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN")) FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN")) FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";

    }

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    if (!have_o) cc_params[cc_par_cnt++] = "-O3";
    if (!have_unroll) cc_params[cc_par_cnt++] = "-funroll-loops";

  }

  if (getenv("AFL_NO_BUILTIN") || getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES") ||
      getenv("LAF_TRANSFORM_COMPARES") || getenv("AFL_LLVM_LAF_ALL") ||
      lto_mode) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-bcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }


  cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";
  cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
  cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by afl-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __afl_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  if (x_set) {

    cc_params[cc_par_cnt++] = "-x";
    cc_params[cc_par_cnt++] = "none";

  }


  if (preprocessor_only || have_c || !non_dash) {

    /* In the preprocessor_only case (-E), we are not actually compiling at
       all but requesting the compiler to output preprocessed sources only.
       We must not add the runtime in this case because the compiler will
       simply output its binary content back on stdout, breaking any build
       systems that rely on a separate source preprocessing step. */
    cc_params[cc_par_cnt] = NULL;
    return;

  }



    switch (bit_mode) {

      case 0:
        if (!shared_linking && !partial_linking)
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-compiler-rt.o", obj_path);
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto.o", obj_path);
        break;

      case 32:
        if (!shared_linking && !partial_linking) {

          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-compiler-rt-32.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m32 is not supported by your compiler");

        }


          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto-32.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m32 is not supported by your compiler");


        break;

      case 64:
        if (!shared_linking && !partial_linking) {

          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-compiler-rt-64.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m64 is not supported by your compiler");

        }


          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto-64.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m64 is not supported by your compiler");


        break;

  }


  cc_params[cc_par_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char **argv, char **envp) {

  int   i;
  char *ptr = NULL;

  if (getenv("AFL_DEBUG")) {

    debug = 1;
    if (strcmp(getenv("AFL_DEBUG"), "0") == 0) unsetenv("AFL_DEBUG");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

    lto_mode = 1;


#ifndef AFL_CLANG_FLTO
    FATAL(
        "instrumentation mode LTO specified but LLVM support not available "
        "(requires LLVM 11 or higher)");
#endif

  u8 *ptr2;

  if ((ptr2 = getenv("AFL_LLVM_DICT2FILE")) != NULL && *ptr2 != '/')
    FATAL("AFL_LLVM_DICT2FILE must be set to an absolute file path");

  if ((isatty(2) && !be_quiet) || debug) {

    SAYF(cCYA
         "afl-cc" VERSION cRST
         " by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-LTO\n"
         );

  }


  if (getenv("AFL_LLVM_LAF_ALL")) {

    setenv("AFL_LLVM_LAF_SPLIT_SWITCHES", "1", 1);
    setenv("AFL_LLVM_LAF_SPLIT_COMPARES", "1", 1);
    setenv("AFL_LLVM_LAF_SPLIT_FLOATS", "1", 1);
    setenv("AFL_LLVM_LAF_TRANSFORM_COMPARES", "1", 1);

  }

  ptr = find_object("afl-llvm-rt.o", argv[0]);

  if (!ptr) {

    FATAL(
        "Unable to find 'afl-llvm-rt.o'. Please set the AFL_PATH "
        "environment variable.");

  }

  if (debug) { DEBUGF("rt=%s obj_path=%s\n", ptr, obj_path); }

  ck_free(ptr);

  edit_params(argc, argv, envp);

  if (debug) {

    DEBUGF("cwd: '%s';", getthecwd());
    for (i = 0; i < (s32)cc_par_cnt; i++)
      SAYF(" '%s'", cc_params[i]);
    SAYF("\n");
    fflush(stdout);
    fflush(stderr);

  }

    execvp(cc_params[0], (char **)cc_params);


  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}

