/*------------------------------------------------------------------
 * safe_config.h -- Safe C Lib configs
 *
 * August 2017, Reini Urban
 *
 * Copyright (c) 2017 by Reini Urban
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *------------------------------------------------------------------
 */

#ifndef __SAFE_LIB_CONFIG_H__
#define __SAFE_LIB_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MINGW32__
# if defined __MINGW64_VERSION_MAJOR && defined __MINGW64_VERSION_MINOR
#   define HAVE_MINGW64  /* mingw-w64 (either 32 or 64bit) */
# else
#   define HAVE_MINGW32  /* old mingw */
# endif
#endif

/*
 * Safe Lib specific configuration values.
 */

/*
 * We depart from the C11 standard and allow memory and string
 * operations to have different max sizes. See the respective
 * safe_mem_lib.h or safe_str_lib.h files.
 */

#ifndef RSIZE_MAX_MEM
/* maximum buffer length. default: 256UL << 20 (256MB) */
#define RSIZE_MAX_MEM (256UL << 20)  /* 256MB */
#endif

#ifndef RSIZE_MAX_STR
/* maximum string length. default: 4UL << 10 (4KB) */
#define RSIZE_MAX_STR 50UL<<10
#endif

/* null out the remaining part of a string buffer if it is not completely used */
#undef SAFECLIB_STR_NULL_SLACK

/* Define to 1 to include some additional unsafe C11 functions:
   snprintf_s, vsnprintf_s, tmpnam_s */
#undef SAFECLIB_ENABLE_UNSAFE

/* Define to 1 to disable additional functions not defined
   in the C11 appendix K specification */
#undef SAFECLIB_DISABLE_EXTENSIONS

/* Define to 1 to disable new multibyte and wchar support */
#define SAFECLIB_DISABLE_WCHAR 1

/* Define to 1 to disable linking with dllimport, only relevant to windows.
 * Defined with a static libsafec.
 */
#undef DISABLE_DLLIMPORT

/*
 * The spec does not call out a maximum len for the strtok src
 * string (the max delims size), so one is defined here.
 */
#ifndef STRTOK_DELIM_MAX_LEN
#define  STRTOK_DELIM_MAX_LEN  16
#endif

#ifdef __cplusplus
}
#endif

#endif /* __SAFE_LIB_CONFIG_H__ */
