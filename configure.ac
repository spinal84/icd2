AC_INIT([Internet Connectivity daemon 2], [0.87+fremantle10+0m5], [], icd2)
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])

AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_LIBTOOL

AC_HEADER_STDC

AC_PATH_X
AC_PATH_XTRA
AC_SUBST(X_CFLAGS)

AM_GCONF_SOURCE_2
AC_PATH_PROG(GCONFTOOL, gconftool-2)

PKG_PROG_PKG_CONFIG

#+++++++++++++++
# Misc programs 
#+++++++++++++++


AC_SUBST(CFLAGS)

PKG_CHECK_MODULES(ICD,
			[glib-2.0 dnl
			gtk+-2.0 dnl
			dbus-glib-1 dnl
			gconf-2.0])

AC_SUBST(ICD_LIBS)
AC_SUBST(ICD_CFLAGS)

#+++++++++++++++++++
# Directories setup
#+++++++++++++++++++

AC_OUTPUT([
Makefile
support/Makefile
])

