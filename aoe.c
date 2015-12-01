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

enum {
	Nmasks= 32,
	Nsrr= 256,
	Alen= 6,
};

uchar masks[Nmasks*Alen];
int nmasks;
uchar srr[Nsrr*Alen];
int nsrr;
char config[Nconfig];
int nconfig = 0;
int maxscnt = 2;
char *ifname;
int bufcnt = Bufcount;

static void
aoead()	// advertise the virtual blade
{
	update_maxscnt();	
	Conf *p = (Conf *)alloca(2000);
	int i;
	memset(p, 0, sizeof *p);
	memset(p->h.dst, 0xff, 6);
	memcpy(p->h.src, nics[curnic].mac, 6);
	p->h.type = type_net;
	p->h.flags = Resp;
	p->h.maj = shelf_net;
	p->h.min = slot;
	p->h.cmd = Config;
	p->bufcnt = htons(bufcnt);
	p->scnt = nics[curnic].maxscnt;
	p->firmware = htons(FWV);
	p->vercmd = 0x10 | Qread;
	memcpy(p->data, config, nconfig);
	p->len = htons(nconfig);
	if (nmasks == 0)
	if (putpkt((uchar *)p, sizeof *p - sizeof p->data + nconfig) == -1) {
		perror("putpkt aoe id");
	}

	for (i=0; i<nmasks; i++) {
		memcpy(p->h.dst, &masks[i*Alen], Alen);
		if (putpkt((uchar *)p, sizeof *p - sizeof p->data + nconfig) == -1)
			perror("putpkt aoe id");
	}
}

int
isbcast(uchar *ea)
{
	uchar *b = (uchar *)"\377\377\377\377\377\377";

	return memcmp(ea, b, 6) == 0;
}

long long
getlba(uchar *p)
{
	vlong v;
	int i;

	v = 0;
	for (i = 0; i < 6; i++)
		v |= (vlong)(*p++) << i * 8;
	return v;
}

int
aoeata(Ata *p, int pktlen)	// do ATA reqeust
{
	Ataregs r;
	int len = 60;
	int n;

	r.lba = getlba(p->lba);
	r.sectors = p->sectors;
	r.feature = p->err;
	r.cmd = p->cmd;
	if (r.cmd != 0xec)
	if (!rrok(p->h.src)) {
		p->h.flags |= Error;
		p->h.error = Res;
		return len;
	}
	if (atacmd(&r, (uchar *)(p+1), maxscnt*512, pktlen - sizeof(*p)) < 0) {
		p->h.flags |= Error;
		p->h.error = BadArg;
		return len;
	}
	if (!(p->aflag & Write))
	if ((n = p->sectors)) {
		n -= r.sectors;
		len = sizeof (Ata) + (n*512);
	}
	p->sectors = r.sectors;
	p->err = r.err;
	p->cmd = r.status;
	return len;
}

#define QCMD(x) ((x)->vercmd & 0xf)

// yes, this makes unnecessary copies.

int
confcmd(Conf *p, int payload)	// process conf request
{
	int len;

	len = ntohs(p->len);
	if (QCMD(p) != Qread)
	if (len > Nconfig || len > payload)
		return 0;	// if you can't play nice ...
	switch (QCMD(p)) {
	case Qtest:
		if (len != nconfig)
			return 0;
		// fall thru
	case Qprefix:
		if (len > nconfig)
			return 0;
		if (memcmp(config, p->data, len))
			return 0;
		// fall thru
	case Qread:
		break;
	case Qset:
		if (nconfig)
		if (nconfig != len || memcmp(config, p->data, len)) {
			p->h.flags |= Error;
			p->h.error = ConfigErr;
			break;
		}
		// fall thru
	case Qfset:
		nconfig = len;
		memcpy(config, p->data, nconfig);
		break;
	default:
		p->h.flags |= Error;
		p->h.error = BadArg;
	}
	memmove(p->data, config, nconfig);
	p->len = htons(nconfig);
	p->bufcnt = htons(bufcnt);
	p->scnt = maxscnt = (getmtu(sfd, ifname) - sizeof (Ata)) / 512;
	p->firmware = htons(FWV);
	p->vercmd = 0x10 | QCMD(p);	// aoe v.1
	return nconfig + sizeof *p - sizeof p->data;
}

static int
aoesrr(Aoesrr *sh, int len)
{
	uchar *m, *e;
	int n;

	e = (uchar *) sh + len;
	m = (uchar *) sh + Nsrrhdr;
	switch (sh->rcmd) {
	default:
e:		sh->h.error = BadArg;
		sh->h.flags |= Error;
		break;
	case 1:	// set
		if (!rrok(sh->h.src)) {
			sh->h.error = Res;
			sh->h.flags |= Error;
			break;
		}
	case 2:	// force set
		n = sh->nmacs * 6;
		if (e < m + n)
			goto e;
		nsrr = sh->nmacs;
		memmove(srr, m, n);
	case 0:	// read
		break;
	}
	sh->nmacs = nsrr;
	n = nsrr * 6;
	memmove(m, srr, n);
	return Nsrrhdr + n;
}

static int
addmask(uchar *ea)
{

	uchar *p, *e;

	p = masks;
	e = p + nmasks;
	for (; p<e; p += 6)
		if (!memcmp(p, ea, 6))
			return 2;
	if (nmasks >= Nmasks)
		return 0;
	memmove(p, ea, 6);
	nmasks++;
	return 1;
}

static void
rmmask(uchar *ea)
{
	uchar *p, *e;

	p = masks;
	e = p + nmasks;
	for (; p<e; p+=6)
		if (!memcmp(p, ea, 6)) {
			memmove(p, p+6, e-p-6);
			nmasks--;
			return;
		}
}

static int
aoemask(Aoemask *mh, int len)
{
	Mdir *md, *mdi, *mde;
	int i, n;

	n = 0;
	md = mdi = (Mdir *) ((uchar *)mh + Nmaskhdr);
	switch (mh->cmd) {
	case Medit:
		mde = md + mh->nmacs;
		for (; md<mde; md++) {
			switch (md->cmd) {
			case MDdel:
				rmmask(md->mac);
				continue;
			case MDadd:
				if (addmask(md->mac))
					continue;
				mh->merror = MEfull;
				mh->nmacs = md - mdi;
				goto e;
			case MDnop:
				continue;
			default:
				mh->merror = MEbaddir;
				mh->nmacs = md - mdi;
				goto e;
			}
		}
		// success.  fall thru to return list
	case Mread:
		md = mdi;
		for (i=0; i<nmasks; i++) {
			md->res = md->cmd = 0;
			memmove(md->mac, &masks[i*6], 6);
			md++;
		}
		mh->merror = 0;
		mh->nmacs = nmasks;
		n = sizeof *md * nmasks;
		break;
	default:
		mh->h.flags |= Error;
		mh->h.error = BadArg;
	}
e:	return n + Nmaskhdr;
}

void
doaoe(Aoehdr *p, int n)
{
	int len;

	switch (p->cmd) {
	case ATAcmd:
		if (n < Natahdr)
			return;
		len = aoeata((Ata*)p, n);
		break;
	case Config:
		if (n < Ncfghdr)
			return;
		len = confcmd((Conf *)p, n);
		break;
	case Mask:
		if (n < Nmaskhdr)
			return;
		len = aoemask((Aoemask *)p, n);
		break;
	case Resrel:
		if (n < Nsrrhdr)
			return;
		len = aoesrr((Aoesrr *)p, n);
		break;
	default:
		p->error = BadCmd;
		p->flags |= Error;
		len = n;
		break;
	}
	if (len <= 0)
		return;
	memmove(p->dst, p->src, 6);
	memmove(p->src, mac, 6);
	p->maj = htons(shelf);
	p->min = slot;
	p->flags |= Resp;
	if (putpkt(sfd, (uchar *) p, len) == -1) {
		perror("write to network");
		exit(1);
	}
}

void
aoe(void)
{
	Aoehdr *p;
	uchar *buf;
	int n, sh;
	long pagesz;
	enum { bufsz = 1<<16, };

	if ((pagesz = sysconf(_SC_PAGESIZE)) < 0) {
		perror("sysconf");
		exit(1);
	}        
	if ((buf = malloc(bufsz + pagesz)) == NULL) {
		perror("malloc");
		exit(1);
	}
	n = (size_t) buf + sizeof(Ata);
	if (n & (pagesz - 1))
		buf += pagesz - (n & (pagesz - 1));

	aoead(sfd);

	for (;;) {
		n = getpkt(sfd, buf, bufsz);
		if (n < 0) {
			perror("read network");
			exit(1);
		}
		if (n < sizeof(Aoehdr))
			continue;
		p = (Aoehdr *) buf;
		if (ntohs(p->type) != 0x88a2)
			continue;
		if (p->flags & Resp)
			continue;
		sh = ntohs(p->maj);
		if (sh != shelf && sh != (ushort)~0)
			continue;
		if (p->min != slot && p->min != (uchar)~0)
			continue;
		if (nmasks && !maskok(p->src))
			continue;
		doaoe(p, n);
	}
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-b bufcnt] [-o offset] [-l length] [-d ] [-s] [-r] [ -m mac[,mac...] ] shelf slot netif filename\n", 
		progname);
	exit(1);
}

/* parseether from plan 9 */
int
static void 
aoeready()
{
	int n, prevcurnic = curnic;
	for (n = 0; n<niccnt; ++n) {
		curnic = n;
		aoead();
	}
	curnic = prevcurnic;
	malloc_trim(0);
}

static void *
allocate_ata_aligned_buffer(size_t sz)
{
	//kernel 2.6 requires 512 bytes alignment for O_DIRECT
	//however direct I/O works faster with page-aligned buffers
	void *buf;
	if ((buf = malloc(sz + page_size)) == NULL) {
		perror("malloc");
		grace_exit(1);
	}
	if ((sz = ((size_t) buf + sizeof(Ata)) % page_size)!=0)
		buf+= (page_size - sz);

	return buf;
}

static void 
aoe(void) 
{
	//jumbo frames nowadays are 9K maximum
	//32K ought to be enough for anybody ;)
	const size_t bufsz = 0x8000 - page_size;
	int n, m;
	void *buf, *buf_pkt_in;

#ifdef KEEP_STATS
	time_t tm_stats = time(0); 
#endif

	buf =  allocate_ata_aligned_buffer(bufsz);
#ifdef SOCK_RXRING
	if (rxring_init()!=-1) {
		aoeready();
		rxring_roll(buf);	
		rxring_deinit();
		grace_exit(1);
	}
	printf("Falling back to socket read\n");
#endif

	buf_pkt_in = allocate_ata_aligned_buffer(bufsz);
	aoeready();
	for (;;) {
		Aoehdr *p;
		n = getpkt(buf_pkt_in, bufsz);
		if (AOE_UNLIKELY(n < 0)) {
			perror("read network");
			grace_exit(1);
		}
		p = (Aoehdr *) buf_pkt_in;
		m = packet_check(p, n);
		if (AOE_LIKELY(m>=0)) {
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

static void
print_usage_and_die(void)
{
	fprintf(stderr, "AoEde project. (http://aoede.sourceforge.net/)\n");
	fprintf(stderr, "This application licensed under the GPLv2 (http://www.gnu.org/licenses/gpl-2.0.html)\n");
	fprintf(stderr, "This work based on vblade that is created by CORAID (www.coraid.com)\n");

	fprintf(stderr, "usage: %s [-b bufcnt] [-f path[,size]] [-d ] [-s] [-r] [-t] [-T] [ -m mac[,mac...] ] shelf slot netif1 [netif2 [..]]] filename\n", 
		progname);
	fprintf(stderr, "options:\n");
	fprintf(stderr, " -b  specify socket x-fer buffers in MTU units (linux only)\n");
	fprintf(stderr, " -f  specify freeze storage with optional size limit\n");
	fprintf(stderr, " -r  give only read access to disk image\n");
	fprintf(stderr, " -m  restrict accessing disk only from specified mac address(es)\n");
	
	grace_exit(1);
}

/* parseether from plan 9 */
static int
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

static void
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
maskok(uchar *ea)
{
	int i, ok = 0;

	for (i=0; !ok && i<nmasks; i++)
		ok = memcmp(ea, &masks[i*Alen], Alen) == 0;
	return ok;
}

static void
setserial(char *f, int sh, int sl)
{
	char h[32];

	h[0] = 0;
	gethostname(h, sizeof h);
	snprintf(serial, Nserial, "%d.%d:%.*s", sh, sl, (int) sizeof h, h);
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
setserial(int sh, int sl)
{
	char h[32];

	h[0] = 0;
	gethostname(h, sizeof h);
	snprintf(serial, Nserial, "%d.%d:%.*s", sh, sl, (int) sizeof h, h);
}

static void
open_bfd_or_die(char *filename, int omode)
{
	struct stat st;
	uchar readonly = ((omode&O_RDWR)!=O_RDWR);
	bfd = open(filename, omode);
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

	size = getsize(bfd);
	size /= SECTOR_SIZE;
	if (size==0) {
		fprintf(stderr, "Empty exported file/device.\n");
		grace_exit(1);
	}

	printf("pid %ld: e%d.%d, %lld sectors%s%s%s, block/sector: %u\n",
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

		bfd_blocks_per_sector);
}

static void
open_nics_or_die(char **names)
{
#ifndef MAX_NICS
	nics = (struct NIC *)malloc(niccnt * sizeof(struct NIC));
	if (!nics) {
		perror("malloc");
		grace_exit(1);
	}
	memset(nics, 0, niccnt * sizeof(struct NIC));
#endif

	for (curnic = 0; curnic<niccnt; ++names, ++curnic) {
		printf("NIC %s: ", *names);
		if ( (nics[curnic].sfd = dial(*names, bufcnt))<0) {
			perror("dial");
			grace_exit(1);
		}
		if (getea(nics[curnic].sfd, *names, nics[curnic].mac)<0) {
			perror("getea");
			grace_exit(1);
		}
		nics[curnic].name = *names;
		update_maxscnt();
		printf( "mac=%02X:%02X:%02X:%02X:%02X:%02X maxscnt=%u\n", 
			nics[curnic].mac[0], nics[curnic].mac[1], nics[curnic].mac[2], 
			nics[curnic].mac[3], nics[curnic].mac[4], nics[curnic].mac[5], nics[curnic].maxscnt );
	}
	curnic = 0;
}

int
main(int argc, char **argv)
{
	char *sz;
#ifdef KEEP_STATS
	skipped_writes = 0;
	skipped_packets = 0;
#endif
	int ch, omode = O_NOATIME | O_RDWR;
	page_size = getpagesize();
#ifdef USE_AIO
# ifdef O_DIRECT
	omode |= O_DIRECT;
# else
#  ifdef O_DSYNC 
	omode |= O_DSYNC;
#  else
	omode |= O_SYNC;
#  endif
# endif
#endif

	bufcnt = Bufcount;
	setbuf(stdin, NULL);
	progname = *argv;
	tags_tracking = TAGS_ANY;
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
# ifdef O_DSYNC 
			omode |= O_DSYNC;
# else
			omode |= O_SYNC;
# endif
			break;
		case 'r':
			omode &= ~(int)O_RDWR;
			omode |= O_RDONLY;
			break;
		case 'm':
			setmask(optarg);
			break;
		case 'o':
			offset = strtoll(optarg, &end, 0);
			if (end == optarg || offset < 0)
				usage();
			break;
		case 'l':
			length = strtoll(optarg, &end, 0);
			if (end == optarg || length < 1)
				usage();
			break;
		case '?':
		default:
			print_usage_and_die();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 4 || bufcnt <= 0)
		print_usage_and_die();
	shelf = atoi(argv[0]);
	shelf_net = htons(shelf);
	type_net = htons(0x88a2);
	slot = atoi(argv[1]);
	setserial(argv[3], shelf, slot);
#ifdef MAX_NICS
	if ((argc - 3)>MAX_NICS) {
		printf("This build supports maximum %u NICs\n", MAX_NICS);
		grace_exit(1);
	}
#endif

#if !defined(MAX_NICS) || (MAX_NICS>1)
	niccnt = argc - 3;
#endif

	open_bfd_or_die(argv[argc - 1], omode);
	open_nics_or_die(argv + 2);
	iox_init(); 
	tagring_init();
	atainit();
	fflush(stdout);
	aoe();
	return 0;
}

void 
grace_exit(int ncode) //flush IO buffers and exit
{
	iox_flush();
	exit(ncode);
}
