Copyright (C) 2016, Western Digital.

# <p align="center">dm-zoned Device Mapper Userspace Tool</p>


## I. Introduction

### I.1. dm-zoned Device Mapper

The dm-zoned device mapper provides transparent write access to zoned block
devices (ZBC and ZAC compliant devices). It hides to the device user (a file
system or an application doing raw block device accesses) any sequential write
constraint on host-managed devices and can mitigate potential device-side
performance degradation with host-aware zoned devices.

File systems or applications that can natively support host-managed zoned block
devices (e.g. the f2fs file system since kernel 4.10) do not need to use the
dm-zoned device mapper.

For a more detailed description of the zoned block device models and
their constraints see (for SCSI devices):

http://www.t10.org/drafts.htm#ZBC_Family

and (for ATA devices):

http://www.t13.org/Documents/UploadedDocuments/docs2015/di537r05-Zoned_Device_ATA_Command_Set_ZAC.pdf

dm-zoned implementation focused on simplicity and on minimizing overhead (CPU,
memory and storage overhead). For a 10TB host-managed disk with 256 MB zones,
dm-zoned memory usage per disk instance is at most 4.5 MB and as little as 5
zones will be used internally for storing metadata and performaing reclaim
operations.

### I.2 dm-zoned Userspace Tool

The dmzadm utility formats backend devices used with the dm-zoned device mapper.
This utility will inspect the device verifying that the device is a zoned block
device and will prepare and write on-disk dm-zoned metadata according to the
device capacity, zone size, etc.

### I.3. License

dm-zoned-tools is distributed under the terms of the the terms of the GNU
General Public License version 3, or any later version. A copy of version 3 of
this license can be found in the COPYING.GPL file.

dm-zoned-tools and all its applications are distributed "as is", without
technical support, and WITHOUT ANY WARRANTY, without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Along with dm-zoned-tools, you should have received a copy of the GNU 
General Public License version 3. If not, see <http://www.gnu.org/licenses/>.

### I.4. Contact and Bug Reports

To report problems, please contact:
* Damien Le Moal  (damien.lemoal@wdc.com)

PLEASE DO NOT SUBMIT CONFIDENTIAL INFORMATION OR INFORMATION SPECIFIC
TO DRIVES THAT ARE VENDOR SAMPLES OR NOT PUBLICLY AVAILABLE.


## II. Algorithm

dm-zoned implements an on-disk buffering scheme to handle non-sequential write
accesses to a zoned device sequential zones. Conventional zones are used for
this, as well as for storing internal metadata.

The zones of the device are separated into 2 types:

1) Metadata zones: these are randomly writeable zones used to store metadata.
Randomly writeable zones may be conventional zones or sequential write
preferred zones (host-aware devices only). Metadata zones are not reported as
useable capacity to the user.

2) Data zones: All remaining zones, the majority of which will be sequential
zones. These are used exclusively to store user data. The conventional zones
(or part of the sequential write preferred zones on a host-aware device) may
be used also for buffering user random writes. Data in these zones may be
permanently mapped to the randomly writeable zone initially used, or moved
to a sequential zone after some time so that the random zone can be reused for
buffering new incoming random writes.

dm-zoned exposes a logical device with a sector size of 4096 bytes,
irrespectively of the physical sector size of the backend zoned device being
used. This allows reducing the amount of metadata needed to manage valid blocks
(blocks written). The on-disk metadata format is as follows:

1) The first block of the first randomly writeable zone found contains the
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
a buffer zone: a randomly writeable free data zone is allocated and assigned
to the chunk being accessed in addition to the already mapped sequential data
zone. Writing block to the buffer zone will invalidate the same blocks in the
sequential data zone.

Read operations are processed according to the block validity information
provided by the bitmaps: valid blocks are read either from the data zone or,
if the data zone is buffered, from the buffer zone assigned to the data zone.

After some time, the limited number of random zones available may be exhausted
and unaligned writes to unbuffered zones become impossible. To avoid such
situation, a reclaim process regularly scans used random zones and try to
"reclaim" them by rewriting (sequentially) the valid blocks of the buffer zone
to a free sequential zone. Once rewriting completes, the chunk mapping is
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
and updated and normal operation resumed. This only temporarily delays write and
discard requests. Read requests can be processed while metadata logging is
executed.


## III. Compilation and Installation

The following commands will compile the dmzadm tool (requires the autoconf,
automake and libtool packages).

```
> sh ./autogen.sh
> ./configure
> make
```

To install the compiled dmzadm executable file, simply execute as root the
following command.

```
> make install
```

The default installation directory is /usr/sbin. This default location can be
changed using the configure script. Executing the following command displays
the options used to control the installation path.

```
> ./configure --help
```


## IV. Usage

The dm-zoned device mapper is included with the mainline Linux kernel code
since version 4.13.0. dm-zoned compilation must be enabled in the kernel
configuration. This can be done by setting the CONFIG_DM_ZONED configuration
parameter to "y" or "m" (menu: Device Derivers -> Multiple devices driver
support (RAID and LVM) -> Drive-managed zoned block device target support).

Since kernel 4.16.0, using the deadline or mq-deadline scheduler with zoned
block devices is also necessary to avoid write request reordering leading to I/O
errors. A zoned block device must be setup with this scheduler before executing
the dmzadm tool.

```
# echo deadline > /sys/block/<disk name>/queue scheduler
```

Alternatively, a udev rule can also be defined to force the use of the deadline
scheduler on a particular disk or on all disk. An example of such rule is shown
below.

```
ACTION=="add|change", KERNEL=="sd*[!0-9]", ATTRS{queue/zoned}=="host-managed", \
        ATTR{queue/scheduler}="deadline"
```

To create a dm-zoned target device, a zoned block device must first be
formatted using the dmzadm tool. This tool will analyze the device zone
configuration, determine where to place the metadata sets and initialize on
disk the metadata used by the dm-zoned target driver.

```
> dmzadm --format /dev/sdxx
```

dmzadm detailed usage is as follows:

```
> dmzadm --help
Usage: dmzadm <operation> <device path> [options]
Operations:
	--help | -h	: General help message
	--format	: Format a block device metadata
	--check		: Check a block device metadata
	--repair	: Repair a block device metadata
Common options(all operations):
	--verbose	: Verbose output
	--vverbose	: Very verbose output
Format options:
	--seq <num>	: Number of sequential zones reserved for reclaim
			  (the minimum is 1 and the default is 16).
```

For a zoned block device alread formatted, the dm-zoned target can be created
normally with the dmsetup utility (see example script below).

The following options can be passed to dmsetup to initialize the target.

Option        | Description
--------------|-------------------------------------------------
rlow=int      | Start reclaiming random zones if the percentage of free random data zones falls below the specified percentage.
idle_rlow=int | When the disk is idle (no I/O activity), start reclaiming random zones if the percentage of free random data zones falls below the specified percentage.


## V. Example Setup Scripts

```
#!/bin/sh

if [ $# -lt 1 ]; then
	echo "Usage: $0 <Zoned device path> [Options]"
	echo "Options:"
	echo "  rlow=<perc>      : Start reclaiming random zones if the "
	echo "                     percentage of free random data zones falls "
	echo "                     below <perc>."
	echo "  idle_rlow=<perc> : When the disk is idle (no I/O activity), "
	echo "                     start reclaiming random zones if the "
	echo "                     percentage of free random data zones falls "
	echo "                     below <perc>."
	exit 1
fi

dev="${1}"
shift
options="$@"

modprobe dm-zoned

echo "0 `blockdev --getsize ${dev}` zoned ${dev} ${options}" | \
dmsetup create zoned-`basename ${dev}`
```

## VI. Submitting patches

Read CONTRIBUTING and send patches to:

	Damien Le Moal <damien.lemoal@wdc.com>
	Bart Van Assche <Bart.VanAssche@wdc.com>

If you believe this requires kernel eyes or review Cc the device mapper kernel
development mailing list:

	dm-devel@redhat.com
