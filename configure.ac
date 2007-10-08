#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(squid-gsb, 0.1, alexott@gmail.com)
AM_INIT_AUTOMAKE(squid-gsb, 0.1)
# AC_CONFIG_SRCDIR([acconfig.h])
AM_CONFIG_HEADER([config.h])

AC_CACHE_LOAD

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# AM_GNU_GETTEXT([external])

AC_CACHE_SAVE

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T
AC_C_VOLATILE
AC_C_INLINE
AC_TYPE_PID_T
AC_HEADER_TIME
AC_STRUCT_TM

AC_ARG_WITH(boost-includes,
[  --with-boost-includes      directory with boost include files],
[if test "${withval}" != "" ; then
  CPPFLAGS="-I${withval} ${CPPFLAGS}"
fi])

AC_ARG_WITH(boost-libs,
[  --with-boost-libs      directory with boost library files],
[if test "${withval}" != "" ; then
  LDFLAGS="-I${withval} ${LDFLAGS}"
fi])

AC_FINALIZE_VAR(CONFDIR,"${sysconfdir}")
AC_SUBST(CONFDIR)
AC_FINALIZE_VAR(LSTATEDIR,"${localstatedir}/${PACKAGE_NAME}")
AC_SUBST(LSTATEDIR)

AC_CONFIG_FILES([Makefile 
                 src/Makefile
                 src/gsb-conf.h
                 etc/Makefile
                 etc/squid-gsb.conf
	])
AC_OUTPUT

