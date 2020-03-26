AC_INIT([dm-zoned tools], [1.1.0], [damien.lemoal@wdc.com])

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
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADER(libgen.h, [],
		[AC_MSG_ERROR([Couldn't find libgen.h])])
AC_CHECK_HEADER(mntent.h, [],
		[AC_MSG_ERROR([Couldn't find mntent.h])])
AC_CHECK_HEADER(linux/fs.h, [],
		[AC_MSG_ERROR([Couldn't find linux/fs.h])])
AC_CHECK_HEADER(blkid/blkid.h, [],
		[AC_MSG_ERROR([Couldn't find blkid/blkid.h])])
AC_CHECK_HEADER(linux/blkzoned.h, [],
		[AC_MSG_ERROR([Couldn't find linux/blkzoned.h])])
AC_CHECK_HEADER(libdevmapper.h, [],
		[AC_MSG_ERROR([Couldn't find libdevmapper.h])])

# Checks for libraries.
AC_SEARCH_LIBS([blkid_do_fullprobe], [blkid], [],
	       [AC_MSG_ERROR([Couldn't find libblkid])])

AC_SEARCH_LIBS([dm_task_run], [devmapper], [],
		[AC_MSG_ERROR([Couldn't find libdevmapper])])

AC_CONFIG_FILES([
	Makefile
	man/Makefile
	src/Makefile
])

AC_OUTPUT

