# SPDX-License-Identifier: CC0-1.0
#
# Copyright (C) 2019 Western Digital Corporation or its affiliates.

AC_INIT([dm-zoned-tools], [2.2.1], [damien.lemoal@wdc.com])

AC_PREFIX_DEFAULT(/usr)
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_GNU_SOURCE

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
m4_pattern_allow([AM_PROG_AR])
LT_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for header files.
AC_CHECK_HEADER(libgen.h, [],
		[AC_MSG_ERROR([Couldn't find libgen.h])])
AC_CHECK_HEADER(mntent.h, [],
		[AC_MSG_ERROR([Couldn't find mntent.h])])
AC_CHECK_HEADER(linux/fs.h, [],
		[AC_MSG_ERROR([Couldn't find linux/fs.h])])
AC_CHECK_HEADER(linux/blkzoned.h, [],
		[AC_MSG_ERROR([Couldn't find linux/blkzoned.h])])

AC_CHECK_MEMBER([struct blk_zone.capacity],
		[AC_DEFINE(HAVE_BLK_ZONE_REP_V2, [1],
			   [report zones includes zone capacity])],
		[], [[#include <linux/blkzoned.h>]])

# Checks for libraries.
PKG_CHECK_MODULES([blkid], [blkid])
PKG_CHECK_MODULES([kmod], [libkmod])
PKG_CHECK_MODULES([libudev], [libudev])
PKG_CHECK_MODULES([uuid], [uuid])
PKG_CHECK_MODULES([devmapper], [devmapper])

# Checks for rpm package builds
AC_PATH_PROG([RPMBUILD], [rpmbuild], [notfound])
AC_PATH_PROG([RPM], [rpm], [notfound])
AM_CONDITIONAL([BUILD_RPM],
		[test "x$RPMBUILD" != xnotfound && test "x$RPM" != xnotfound])

AC_CONFIG_FILES([
	Makefile
	man/Makefile
        src/Makefile
])

AC_OUTPUT

