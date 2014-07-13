#define _GNU_SOURCE
#include "config.h"
#include <sys/types.h>
#include "dat.h"

uchar	masks[Nmasks*Alen] = {0};
int	nmasks = 0;
uchar	srr[Nsrr*Alen] = {0};
int	nsrr = 0;
char	config[Nconfig] = {0};
int	nconfig = 0;
int	bufcnt = Bufcount;
int	shelf = 0, slot = 0;
unsigned int page_size = 0;
ushort  shelf_net = 0, type_net = 0;
int	bfd = -1;		// block file descriptors
#if !defined(MAX_NICS) || (MAX_NICS>1)
int	niccnt = 0;		// opened socket file descriptors count
#endif


#ifdef MAX_NICS
struct NIC nics[MAX_NICS] = {{0}};
#else
struct NIC *nics = 0;
#endif
int		curnic = 0;

vlong	size = 0;		// size of blade
char	*progname = 0;
char	serial[Nserial+1] = {0};
uchar   tags_tracking = 0;
uchar	coalesced_read = 0;
#ifdef SUPPORT_CRC
uchar	enable_crc = 0;
#endif
char	*freeeze_path = 0;
vlong	freeeze_size_limit = 0;
uchar	bfd_blocks_per_sector = 1;

#ifdef KEEP_STATS
vlong skipped_writes = 0;
vlong skipped_packets = 0;
#endif
