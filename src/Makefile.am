# SPDX-License-Identifier: CC0-1.0
#
# Copyright (C) 2020 Western Digital Corporation or its affiliates.

AM_CPPFLAGS = -O2 -Wall -Wextra -Wno-unused-parameter \
	      $(kmod_CFLAGS) $(blkid_CFLAGS) $(uuid_CFLAGS) $(devmapper_CFLAGS) \
	      $(libudev_CFLAGS)

sbin_PROGRAMS = dmzadm

CFILES = dmz_dev.c \
	dmz_lib.c \
	dmz_format.c \
	dmz_check.c \
	dmz_devmapper.c \
	dmzadm.c
HFILES = dmz.h

dmzadm_SOURCES = ${CFILES} ${HFILES}
dmzadm_LDADD =
dmzadm_LDFLAGS = $(blkid_LIBS) $(uuid_LIBS) $(devmapper_LIBS) $(kmod_LIBS) \
		 $(libudev_LIBS)
