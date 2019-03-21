#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mastik], [0.02], [yval@cs.adelaide.edu.au])
AC_CONFIG_SRCDIR([src/symbol.c])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([bfd], [bfd_init])
AC_CHECK_LIB([elf], [elf_version])
AC_CHECK_LIB([dwarf], [dwarf_init])



# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h strings.h unistd.h sched.h sys/prctl.h])
AC_CHECK_HEADERS([bfd.h])

mastik_have_dwarf="no"
if test "x$ac_cv_header_bfd_h" = x"yes" ; then 
  SYMBOL_SRCS=symbol_bfd.c
  AC_DEFINE([HAVE_SYMBOLS], [1], [Have support for parsing loader symbol table])
  AC_CHECK_HEADERS([libdwarf.h libdwarf/libdwarf.h], [mastik_have_dwarf="yes"])
  if test x"$mastik_have_dwarf" = x"yes" ; then
    AC_DEFINE([HAVE_DWARF], [1], [Have support for dwarf])
  fi
else
  AC_CHECK_HEADERS([mach-o/loader.h])
  if test x"$ac_cv_header_mach_o_loader_h" = x"yes"; then
    SYMBOL_SRCS=symbol_mach.c 
    AC_DEFINE([HAVE_SYMBOLS], [1], [Have support for parsing loader symbol table])
  fi
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero memset munmap strchr strdup strtoul strtoull uname])
AC_CHECK_FUNCS([mmap64 sched_setaffinity])

AC_SUBST(SYMBOL_SRCS, ["$SYMBOL_SRCS"])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([demo/Makefile])
AC_OUTPUT
