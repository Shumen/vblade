/*
  Copyright 2005-2014, CORAID.
  For contact information, see http://coraid.com/
  Copyright 2014, Killer{R}
  For contact information, see http://killprog.com/

  This file is part of AoEde.

  AoEde is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 2 of the License.

  AoEde is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with AoEde.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h> 
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <endian.h>
#include <fcntl.h>
#include <netinet/in.h>
#include "dat.h"
#include "fns.h"
#include <netinet/if_ether.h>

void
aoead(int fd)	// advertise the virtual blade
{
	update_maxscnt();
	uchar buf[2000];
	Conf *p;
	int i;

	p = (Conf *)buf;
	memset(p, 0, sizeof *p);
	memset(p->h.dst, 0xff, 6);
	memmove(p->h.src, mac, 6);
	p->h.type = type_net;
	p->h.flags = Resp;
	p->h.maj = shelf_net;
	p->h.min = slot;
	p->h.cmd = Config;
	p->bufcnt = htons(bufcnt);
	p->scnt = maxscnt;
	p->firmware = htons(FWV);
	p->vercmd = 0x10 | Qread;
	memcpy(p->data, config, nconfig);
	p->len = htons(nconfig);
	if (nmasks == 0)
	if (putpkt(fd, buf, sizeof *p - sizeof p->data + nconfig) == -1) {
		perror("putpkt aoe id");
		return;
	}
	for (i=0; i<nmasks; i++) {
		memcpy(p->h.dst, &masks[i*Alen], Alen);
		if (putpkt(fd, buf, sizeof *p - sizeof p->data + nconfig) == -1)
			perror("putpkt aoe id");
	}
}

void 
aoe(void) 
{
	int n;	
	uchar *buf;
	long pagesz;
#ifdef KEEP_STATS
	time_t tm_stats = time(0); 
#endif


	enum { bufsz = 1<<16, };

	if ((pagesz = sysconf(_SC_PAGESIZE)) < 0) {
		perror("sysconf");
		grace_exit(1);
	}        
	if ((buf = malloc(bufsz + pagesz)) == NULL) {
		perror("malloc");
		grace_exit(1);
	}
	n = (size_t) buf + sizeof(Ata);
	if (n & (pagesz - 1))
		buf += pagesz - (n & (pagesz - 1));

#ifdef SOCK_RXRING
	if (rxring_init()!=-1) {
		aoead(sfd);
		rxring_roll(buf);	
		rxring_deinit();
		grace_exit(1);
	}
	printf("Falling back to socket read\n");
#endif

	aoead(sfd);
	for (;;) {
		Aoehdr *p;
		n = getpkt(sfd, buf, bufsz);
		if (n < 0) {
			perror("read network");
			grace_exit(1);
		}
		p = (Aoehdr *) buf;
		int m = packet_check(p, n);
		if (m>=0) {
			if (tags_tracking==TAGS_INC_LE || tags_tracking==TAGS_INC_BE) 
				tagring_select(m);
			doaoe(p, (Aoehdr *)buf, n);
		}

#ifdef KEEP_STATS
		if (tags_tracking!=TAGS_ANY && skipped_writes) {
			time_t tm_now = time(0); 
			if ((tm_stats+60)<tm_now || tm_now<tm_stats) {
				printf("skipped_writes=%llu\n", skipped_writes);
				tm_stats = tm_now;
			}
		}
#endif
	}
}

void
usage(void)
{
	fprintf(stderr, "AoEde project. (http://aoede.sourceforge.net/)\n");
	fprintf(stderr, "This application licensed under the GPLv2 (http://www.gnu.org/licenses/gpl-2.0.html)\n");
	fprintf(stderr, "This work based on vblade that is created by CORAID (www.coraid.com)\n");

	fprintf(stderr, "usage: %s [-b bufcnt] [-d ] [-s] [-r] [-t] [-T] [ -m mac[,mac...] ] shelf slot netif filename\n", 
		progname);
	fprintf(stderr, "options:\n");
	fprintf(stderr, " -b  specify socket x-fer buffers in MTU units (linux only)\n");
	fprintf(stderr, " -r  give only read access to disk image\n");
	fprintf(stderr, " -m  restrict accessing disk only from specified mac address(es)\n");
	
	
	grace_exit(1);
}

/* parseether from plan 9 */
int
parseether(uchar *to, char *from)
{
	char nip[4];
	char *p;
	int i;

	p = from;
	for(i = 0; i < 6; i++){
		if(*p == 0)
			return -1;
		nip[0] = *p++;
		if(*p == 0)
			return -1;
		nip[1] = *p++;
		nip[2] = 0;
		to[i] = strtoul(nip, 0, 16);
		if(*p == ':')
			p++;
	}
	return 0;
}

void
setmask(char *ml)
{
	char *p;
	int n;

	for (; ml; ml=p) {
		p = strchr(ml, ',');
		if (p)
			*p++ = '\0';
		n = parseether(&masks[nmasks*Alen], ml);
		if (n < 0)
			fprintf(stderr, "ignoring mask %s, parseether failure\n", ml);
		else
			nmasks++;
	}
}

int
maskcheck(uchar *ea)
{	
	int i;
	if (!nmasks)
		return 0;

	for (i=0; i<nmasks; ++i)
	{
		if (memcmp(ea, &masks[i*Alen], Alen) == 0)
			return i;
	}
	return -1;
}

int
rrok(uchar *ea)
{
	int i, ok = 0;

	if (nsrr == 0)
		return 1;
	for (i=0; !ok && i<nsrr; i++)
		ok = memcmp(ea, &srr[i*Alen], Alen) == 0;
	return ok;
}

void
setserial(char *f, int sh, int sl)
{
	char h[32];

	h[0] = 0;
	gethostname(h, sizeof h);
	snprintf(serial, Nserial, "%d.%d:%.*s", sh, sl, (int) sizeof h, h);
}

int
main(int argc, char **argv)
{
	char *sz;
	struct stat st;
#ifdef KEEP_STATS
	skipped_writes = 0;
	skipped_packets = 0;
#endif
	int ch, omode = O_NOATIME, readonly = 0;
#ifdef USE_AIO
# ifdef O_DIRECT
	omode |= O_DIRECT;
# endif
# ifdef O_DSYNC 
	omode |= O_DSYNC;
# else
	omode |= O_SYNC;
# endif
#endif

	bufcnt = Bufcount;
	setbuf(stdin, NULL);
	progname = *argv;
	tags_tracking = TAGS_ANY;
	iox_init(); //do it right now so we can call iox_flush anytime
	while ((ch = getopt(argc, argv, "f:b:dsrm:")) != -1) {
		switch (ch) {
		case 'b':
			bufcnt = atoi(optarg);
			break;

		case 'f':
#ifdef SHADOW_FREEZE
			freeeze_path = strdup(optarg);
			sz = strrchr(freeeze_path, ',');
			if (sz) {
				*sz = 0;
				freeeze_size_limit = atoi(sz+1);
				printf("Freeze storage '%s' with %lluMB size limit\n", freeeze_path, freeeze_size_limit);
				freeeze_size_limit*= 0x100000;
			}
			else
				printf("Freeze storage '%s' without size limit\n", freeeze_path);
#else
			printf("Freeze storage can't be used due to SHADOW_FREEZE not specified in build\n");
#endif
			break;

		case 'd':
#ifdef O_DIRECT
# ifdef USE_AIO
			printf("Direct mode implied by AIO\n");
# else
			omode |= O_DIRECT;
# endif
#else
			printf("Direct IO is not supported in this build\n");
#endif
			break;
		case 's':
#ifdef USE_AIO
			printf("Synchronous mode implied by AIO\n");
#else
# ifdef O_DSYNC 
			omode |= O_DSYNC;
# else
			omode |= O_SYNC;
# endif
#endif
			break;
		case 'r':
			readonly = 1;
			break;
		case 'm':
			setmask(optarg);
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 4 || bufcnt <= 0)
		usage();
	omode |= readonly ? O_RDONLY : O_RDWR;
	bfd = open(argv[3], omode);
	if (bfd == -1) {
		perror("open");
		grace_exit(1);
	}
	if (!readonly && flock(bfd, LOCK_EX|LOCK_NB)<0) {
		perror("flock");
		grace_exit(1);		
	}
	if (fstat(bfd, &st)==0) {
		if (st.st_blksize > SECTOR_SIZE && 
			st.st_blksize < (0x100*SECTOR_SIZE) && 
			(st.st_blksize % SECTOR_SIZE)==0) {
			bfd_blocks_per_sector = (uchar) (st.st_blksize / SECTOR_SIZE);
		}
	}
	tagring_init();
	shelf = atoi(argv[0]);
	shelf_net = htons(shelf);
	type_net = htons(0x88a2);
	slot = atoi(argv[1]);
	setserial(argv[3], shelf, slot);
	size = getsize(bfd);
	size /= SECTOR_SIZE;
	ifname = argv[2];
	sfd = dial(ifname, bufcnt);
	getea(sfd, ifname, mac);
	update_maxscnt();
	printf("pid %ld: e%d.%d, %lld sectors%s%s%s, maxscnt: %u, block/sector: %u\n",
		(long) getpid(), shelf, slot, size,
		readonly ? " O_RDONLY" : " O_RDWR",  

#ifdef O_DIRECT
		(omode&O_DIRECT) ? " O_DIRECT" : "",
#else
		"",
#endif

#ifdef O_DSYNC 
		(omode&O_DSYNC) ? " O_DSYNC" : "",
#else
		(omode&O_SYNC) ? " O_SYNC" : "",
#endif

		maxscnt, bfd_blocks_per_sector);

	fflush(stdout);
	bfd_init();
	atainit();
	malloc_trim(0);
	aoe();
	return 0;
}

void 
grace_exit(int ncode) //flush IO buffers and exit
{
	iox_flush();
	exit(ncode);
}
