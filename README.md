Copyright (C) 2016, Western Digital.

# <p align="center">dm-zoned Device Mapper Userspace Tool</p>


# Introduction

The *dm-zoned* device mapper target provides random write access to zoned
block devices (ZBC and ZAC compliant devices). It hides to the device user
(a file system or an application doing raw block device accesses) the
sequential write constraint of host-managed zoned block devices, allowing the
use of applications and file systems that do not have native zoned block
device support.

File systems or applications that can natively support host-managed zoned
block devices (e.g. the f2fs file system since kernel 4.10) do not need to use
the *dm-zoned* device mapper target.

For a more detailed description of the zoned block device models and
their constraints see the
[T10 ZBC specification](http://www.t10.org/drafts.htm#ZBC_Family)
for SCSI devices, and the
[T13 ZAC specification](http://www.t13.org/Documents/UploadedDocuments/docs2015/di537r05-Zoned_Device_ATA_Command_Set_ZAC.pdf) for ATA devices.

*dm-zoned* implementation focuses on simplicity and on minimizing resource
usage overhead (CPU, memory and storage overhead). For a 10TB host-managed disk
with 256 MB zones, *dm-zoned* memory usage per disk instance is at most 4.5 MB
and as little as 5 zones will be used internally for storing metadata and
performaing reclaim operations.

See the section [*dm-zoned* Internals](#dm-zoned-Internals) for more details.

# *dm-zoned* Userspace Tool

The *dmzadm* utility allows formating backend devices for use with the
*dm-zoned* device mapper target driver. This utility will inspect the device
verifying that it is a zoned block device and will prepare and write on-disk
*dm-zoned* metadata according to the device capacity, zone size, etc.

## License

The *dm-zoned-tools* project source code is distributed under the terms of the
GNU General Public License v3.0 or later
([GPL-v3](https://opensource.org/licenses/GPL-3.0)).
A copy of this license with *dm-zoned-tools* copyright can be found in the
files [LICENSES/GPL-3.0-or-later.txt] and [COPYING.GPL].

*dm-zoned-tools* and all its applications are distributed "as is", without
technical support, and WITHOUT ANY WARRANTY, without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

All source files in *dm-zoned-tools* contain the GPL-3.0-or-later license SPDX
short identifier in place of the full license text.

```
SPDX-License-Identifier: GPL-3.0-or-later
```

Some files such as the `Makefile.am` files and the `.gitignore` file are public
domain specified by the CC0 1.0 Universal (CC0 1.0) Public Domain Dedication.
These files are identified with the following SPDX header.

```
SPDX-License-Identifier: CC0-1.0
```

See the file [LICENSES/CC0-1.0.txt] for the full text of this license.

## Requirements

The following packages must be installed prior to compiling.

* pkg-config (pkgconf)
* m4
* autoconf
* automake
* libtool
* libuuid library and its development headers (*libuuid* and *libuuid-devel*
  packages)
* libblkid library and its development headers (*libblkid* and *libblkid-devel*
  packages)
* libudev library and its development headers (*systemd* and *systemd-devel*
  packages)
* device-mapper libraries and development headers (*device-mapper-libs* and
  *device-mapper-devel* packages)
* Linux kernel module management libraries and development headers (*kmod* and
  *kmod-devel* packages)

## Compilation

The following commands will compile the *dmzadm* tool.

```
$ sh ./autogen.sh
$ ./configure
$ make
```

## Installation

To install the compiled *dmzadm* executable file, simply execute as root the
following command.

```
$ make install
```

The default installation directory is `/usr/sbin`. This default location can be
changed using the configure script. Executing the following command displays
the options used to control the installation path.

```
$ ./configure --help
```

## Building RPM Packages

The *rpm* and *rpmbuild* utilities are necessary to build *dm-zoned-tools* RPM
packages. Once these utilities are installed, the RPM packages can be built
using the following command.

```
$ sh ./autogen.sh
$ ./configure
$ make rpm
```

Four RPM packages are built: a binary package providing *dmmzadm* executable
and its documentation and license files, a source RPM package, a *debuginfo*
RPM package and a *debugsource* RPM package.

The source RPM package can be used to build the binary and debug RPM packages
outside of *dm-zoned-tools* source tree using the following command.

```
$ rpmbuild --rebuild dm-zoned-tools-<version>.src.rpm
```

## Usage

The *dm-zoned* device mapper is included with the mainline Linux kernel code
since kernel version 4.13.0. *dm-zoned* compilation must be enabled in the
kernel configuration. This can be done by setting the *CONFIG_DM_ZONED*
configuration option to "y" or "m" in the menu: Device Drivers ->
Multiple devices driver support (RAID and LVM) ->
Drive-managed zoned block device target support.

### Requirements

Since kernel 4.16.0, using the *deadline* or *mq-deadline* block I/O scheduler
with zoned block devices is also necessary to avoid write request reordering
leading to write I/O errors. A zoned block device must be setup with this
scheduler before executing the *dmzadm* tool. This can be done using the
following command.

```
# echo deadline > /sys/block/<disk name>/queue/scheduler
```

Alternatively, a udev rule can also be defined to force the use of the deadline
scheduler on a particular disk or on all disk. An example of such rule is shown
below.

```
ACTION=="add|change", KERNEL=="sd*[!0-9]", ATTRS{queue/zoned}=="host-managed", \
        ATTR{queue/scheduler}="deadline"
```

### Command Line Syntax

*dmzadm* detailed usage is as follows.

```
> dmzadm --help
dmzadm allows formatting, checking and repairing
a zoned block device for use with the dm-zoned
device mapper.
Usage: dmzadm <operation> <device(s)> [options]
Operations
  --version | -v : Print version number and exit
  --help | -h	 : General help message
  --format	 : Format a block device metadata
  --check	 : Check a block device metadata
  --repair	 : Repair a block device metadata
  --relabel	 : Change the device label
  --start	 : Start the device-mapper target
  --stop	 : Stop the device-mapper target
Devices
  For a single device target, a zoned block device
  must be specified. For a multi-device target, a
  a list of block devices must be specified, with
  a regular block device as the first device specified,
  followed by one or more zoned block devices
General options
  --verbose	: Verbose output
  --vverbose	: Very verbose output
Format operation options
  --force	: Force overwrite of existing content
  --label=<str> : Set the target label name to <str>
  --seq=<num>	: Number of sequential zones reserved
                  for reclaim. The minimum is 1 and the
                  default is 16
Relabel operation options
  --label=<str> : Set the target new label name to <str>
```

### Creating a Target Device

To create a *dm-zoned* target device, a zoned block device must first be
formatted using the *dmzadm* tool. This tool will analyze the zone
configuration of the device, determine where to place the metadata sets and
initialize on disk the metadata used by the *dm-zoned* target driver.

Formatting a single device target is done using the command.

```
> dmzadm --format /dev/sdX
```

where `/dev/sdX` identifies the backend zoned block device to use.

Starting with Linux kernel v5.8.0, regular block devices such as SSDs can also
be used together with zoned block devices with *dm-zoned*. In this case,
conventional zones are emulated for the regular block device to hold *dm-zoned*
metadata and for buffering data. When a regular block device is used, the zone
reclaim process operates by copying data from emulated conventional zones on
the regular block device to zones of the zoned block device. This dual-drive
configuration can significantly increase performance of the target device
under write-intensive workloads.

To format a *dm-zoned* target device using an additional regular block device
and optionally several zoned block devices, the following commands can be used.

```
> dmzadm --format /dev/nvmeXnY /dev/sdZ /dev/sdZZ
```

Where `/dev/nvmeXnY` is in this example is a NVMe SSD and the scsi disks
`/dev/sdZ` and /dev/sdZZ` and zoned HDDs.

### Activating a Target Device

A formatted *dm-zoned* target device can be started by executing the
 following command.

```
> dmzadm --start /dev/sdX
```

For a multi-device target, the same list of devices as used for format
must be specified.

```
> dmzadm --start /dev/nvmen0p1 /dev/sdX /dev/sdY
```

Conversely, a *dm-zoned* target device can be disabled using the `--stop`
operation.

```
> dmzadm --stop /dev/sdX
```

## Contact and Bug Reports

To report problems, please contact:
* Damien Le Moal (damien.lemoal@wdc.com)

PLEASE DO NOT SUBMIT CONFIDENTIAL INFORMATION OR INFORMATION SPECIFIC
TO DRIVES THAT ARE VENDOR SAMPLES OR NOT PUBLICLY AVAILABLE.

## Submitting patches

Read the [CONTRIBUTING] file and send patches to:

	Damien Le Moal <damien.lemoal@wdc.com>
	Matias Bjørling <matias.bjorling@wdc.com>

If you believe your changes require kernel eyes or review, also Cc the device
mapper kernel development mailing list at:

	dm-devel@redhat.com

# *dm-zoned* Internals

*dm-zoned* implements an on-disk write buffering scheme to handle random
write accesses to sequential write required zones of a zoned block device.
Conventional zones of the backend device are used for buffering random
accesses, as well as for storing internal metadata.

Optionally, since Linux kernel version 5.8.0, an additional regular block
device can also be used to provide randomly writable storage used in place of
the conventional zones of the backend zoned block device for write buffering.
With this new version of *dm-zoned*, multiple zoned block devices can also be
used to increase performance.

All zones of the device(s) used to back a *dm-zoned* target are separated into
2 types:

1) Metadata zones: these are randomly writable zones used to store metadata.
Randomly writable zones may be conventional zones or sequential write
preferred zones (host-aware devices only). Metadata zones are not reported as
usable capacity to the user. If an additional regular block device is used for
write buffering, metadata zones are stored on this cache device.

2) Data zones: All remaining zones of the device. The majority of these zones
will be sequential zones which are used used exclusively for storing user data.
The conventional zones (or part of the sequential write preferred zones on a
host-aware device) may be used also for buffering user random writes.
User data may thus be stored either in conventional zone or in a sequential
zone.

*dm-zoned* exposes a logical device with a sector size of 4096 bytes,
irrespectively of the physical sector size of the backend zoned block device
being used. This allows reducing the amount of metadata needed to manage valid
blocks (blocks written). The on-disk metadata format is as follows:

1) The first block of the first randomly writable zone found contains the
super block which describes the amount and position on disk of metadata blocks.

2) Following the super block, a set of blocks is used to describe the mapping
of the logical chunks of the target logical device to data zones. The mapping
is indexed by logical chunk number and each mapping entry indicates the data
zone storing the chunk data and optionally the zone number of a random zone
used to buffer random modification to the chunk data.

3) A set of blocks used to store bitmaps indicating the validity of blocks in
the data zones follows the mapping table blocks. A valid block is a block that
was writen and not discarded. For a buffered data zone, a block can be valid
only in the data zone or in the buffer zone.

For a logical chunk mapped to a random data zone, all write operations are
processed by directly writing to the data zone. If the mapping zone is to a
sequential zone, the write operation is processed directly only and only if
the write offset within the logical chunk is equal to the write pointer offset
within of the sequential data zone (i.e. the write operation is aligned on the
zone write pointer). Otherwise, write operations are processed indirectly using
a buffer zone: a randomly writable free data zone is allocated and assigned
to the chunk being accessed in addition to the already mapped sequential data
zone. Writing block to the buffer zone will invalidate the same blocks in the
sequential data zone.

Read operations are processed according to the block validity information
provided by the bitmaps: valid blocks are read either from the data zone or,
if the data zone is buffered, from the buffer zone assigned to the data zone.

After some time, the limited number of random zones available may be exhausted
and unaligned writes to unbuffered zones become impossible. To avoid such
situation, a reclaim process regularly scans used random zones and try to
"reclaim" them by copying (sequentially) the valid blocks of the buffer zone
to a free sequential zone. Once the copy completes, the chunk mapping is
updated to point to the sequential zone and the buffer zone freed for reuse.

To protect internal metadata against corruption in case of sudden power loss or
system crash, 2 sets of metadata zones are used. One set, the primary set, is
used as the main metadata repository, while the secondary set is used as a log.
Modified metadata are first written to the secondary set and the log so created
validated by writing an updated super block in the secondary set. Once this log
operation completes, updates in place of metadata blocks can be done in the
primary metadata set, ensuring that one of the set is always correct.
Flush operations are used as a commit point: upon reception of a flush
operation, metadata activity is temporarily stopped, all dirty metadata logged
and updated and normal operation resumed. This only temporarily delays write
and discard requests. Read requests can be processed while metadata logging is
executed.
