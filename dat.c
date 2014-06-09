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
ushort  shelf_net = 0, type_net = 0;
uchar	mac[6] = {0};
int	bfd = 0;		// block file descriptor
int	sfd = 0;		// socket file descriptor
vlong	size = 0;		// size of blade
char	*progname = 0;
char	serial[Nserial+1];
uchar   tags_tracking = 0;
uchar	coalesced_read = 0;
int	maxscnt = 0;
char	*ifname = 0;

#ifdef KEEP_STATS
vlong skipped_writes = 0;
vlong skipped_packets = 0;
#endif
