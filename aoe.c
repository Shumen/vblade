// aoe.c: the ATA over Ethernet virtual EtherDrive (R) blade
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
#include <fcntl.h>
#include <netinet/in.h>
#include "dat.h"
#include "fns.h"
#include <netinet/if_ether.h>

static void 
sfd_putpkt_or_die(uchar *data, int len)
{
	if (putpkt(sfd, data, len) == -1) {
		perror("sfd_putpkt_or_die: write to network");
		grace_exit(1);
	}
}

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

void
aoeata(Ata *p, Ata *op, int pktlen, uchar dup)	// do ATA reqeust
{
	Ataregs r;
	int n, len = 60;
	r.cmd = p->cmd;

	if (r.cmd != 0xec && !rrok(p->h.src)) {
		op->h.flags |= Error;
		op->h.error = Res;	
		op->cmd = ERR;
		sfd_putpkt_or_die((uchar *)op, len);
		return;
	}

	if (r.cmd==0x30 || r.cmd==0x34) {
#ifdef ASSUME_WRITE_SUCCESS
		op->cmd = DRDY;
		sfd_putpkt_or_die((uchar *)op, len);
		if (dup) {
#else
		if (dup) {
			op->cmd = DRDY;
			sfd_putpkt_or_die((uchar *)op, len);
#endif
#ifdef KEEP_STATS
			++skipped_writes;
#endif		
			return;
		}
		op->cmd = r.cmd;
	}

	r.lba = getlba(p->lba);
	r.sectors = p->sectors;
	r.feature = p->err;

	if (atacmd(&r, (uchar *)(p+1), (uchar *)(op+1), pktlen - sizeof(*p)) < 0) {
#ifdef ASSUME_WRITE_SUCCESS
		if (r.cmd==0x30 || r.cmd==0x34) {
			perror("Write failed, while success was assumed. Exiting to avoid data corruption.\n");
			grace_exit(errno);
			return;
		}		
#endif
		op->h.flags |= Error;
		op->h.error = BadArg;
		sfd_putpkt_or_die((uchar *)op, len);
		return;
	}

#ifdef ASSUME_WRITE_SUCCESS
	if (r.cmd==0x30 || r.cmd==0x34) {
		return;
	}		
#endif

	if (!(op->aflag & Write))
	if ((n = op->sectors)) {
		n -= r.sectors;
		len = sizeof (Ata) + (n*512);
	}
	op->sectors = r.sectors;
	op->err = r.err;
	op->cmd = r.status;
	sfd_putpkt_or_die((uchar *)op, len);
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
	update_maxscnt();
	memmove(p->data, config, nconfig);
	p->len = htons(nconfig);
	p->bufcnt = htons(bufcnt);
	p->scnt = maxscnt;
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
		n = sh->nmacs * Alen;
		if (e < m + n)
			goto e;
		nsrr = sh->nmacs;
		memmove(srr, m, n);
	case 0:	// read
		break;
	}
	sh->nmacs = nsrr;
	n = nsrr * Alen;
	memmove(m, srr, n);
	return Nsrrhdr + n;
}

static int
addmask(uchar *ea)
{
	uchar *p, *e;

	p = masks;
	e = p + nmasks;
	for (; p<e; p +=Alen) {
		if (!memcmp(p, ea, Alen)) {
			if (write_tags_tracking)
				tagring_reset_id((p - masks)/Alen);
			return 2;
		}
	}

	if (nmasks >= Nmasks)
		return 0;

	memmove(p, ea, Alen);
	if (write_tags_tracking)
		tagring_reset_id(nmasks);

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
	uchar *e;
	int i, n;

	n = 0;
	e = (uchar *) mh + len;
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
			memcpy(md->mac, &masks[i*6], 6);
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
doaoe(Aoehdr *p, Aoehdr *op, int n)
{
	int len;
	const uchar cmd = p->cmd;
	uchar dup;
	memcpy(op->dst, p->src, 6);
	memcpy(op->src, mac, 6);
	op->maj = shelf_net;
	op->min = slot;

	if (p!=op) {
		op->type = p->type;
		op->flags = p->flags | Resp;
		op->error = p->error;
		op->cmd = cmd;
		memcpy(op->tag, p->tag, sizeof(op->tag));
		memcpy(op+1, p+1, (cmd!=ATAcmd)  ? 
			n - sizeof(Aoehdr) : sizeof(Ata) - sizeof(Aoehdr));
	}
	else
		op->flags|= Resp;

	dup = (write_tags_tracking && tagring_process(*(unsigned long *)&p->tag[0]));
	switch (cmd) {
	case ATAcmd:
		if (n >= Natahdr)
			aoeata((Ata*)p, (Ata*)op, n, dup);
		return;

	case Config:
		if (n < Ncfghdr)
			return;
		len = confcmd((Conf *)op, n);		
		break;
	case Mask:
		if (n < Nmaskhdr)
			return;
		len = aoemask((Aoemask *)op, n);
		break;
	case Resrel:
		if (n < Nsrrhdr)
			return;
		len = aoesrr((Aoesrr *)op, n);
		break;
	default:
		op->error = BadCmd;
		op->flags |= Error;
		len = n;
		break;
	}
	if (len > 0)
		sfd_putpkt_or_die((uchar *)op, len);
}


void 
handle_signal(int signal)
{
	printf("Got signal: %d\n", signal);
	grace_exit(signal);
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

	signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
	signal(SIGQUIT, handle_signal);
    signal(SIGKILL, handle_signal);

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
			if (write_tags_tracking) 
				tagring_select(m);
			doaoe(p, (Aoehdr *)buf, n);
		}

#ifdef KEEP_STATS
		if (write_tags_tracking && skipped_writes) {
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
#ifdef SOCK_RXRING
	fprintf(stderr, " -t  RX tags tracking (better performance with compatible client)\n");
#else
	fprintf(stderr, " -t  RX tags tracking - not supported in this build\n");
#endif
	fprintf(stderr, " -T  WRITE tags tracking (better data integrity but INCOMPATIBLE CLIENT CAN TRASH DATA!)\n");
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
#ifdef KEEP_STATS
	skipped_writes = 0;
	skipped_packets = 0;
#endif
	int ch, omode = O_NOATIME, readonly = 0;
	bufcnt = Bufcount;
	setbuf(stdin, NULL);
	progname = *argv;
	rx_tags_tracking = 0;
	write_tags_tracking = 0;
	bfd_init(); //do it right now so we can call bfd_flush anytime
	while ((ch = getopt(argc, argv, "b:dsrm:tT")) != -1) {
		switch (ch) {
		case 't':
#ifdef SOCK_RXRING
			rx_tags_tracking = 1;
#else
			printf("RX tags tracking supported only in SOCK_RXRING -enabled build\n");
#endif
			break;
		case 'T':
			write_tags_tracking = 1;
			break;
		case 'b':
			bufcnt = atoi(optarg);
			break;
		case 'd':
#ifdef O_DIRECT
			omode |= O_DIRECT;
#else
			printf("Direct IO is not supported in this build\n");
#endif
			break;
		case 's':
#ifdef O_DSYNC 
			omode |= O_DSYNC;
#else
			omode |= O_SYNC;
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
	
	tagring_init();
	shelf = atoi(argv[0]);
	shelf_net = htons(shelf);
	type_net = htons(0x88a2);
	slot = atoi(argv[1]);
	setserial(argv[3], shelf, slot);
	size = getsize(bfd);
	size /= 512;
	ifname = argv[2];
	sfd = dial(ifname, bufcnt);
	getea(sfd, ifname, mac);
	update_maxscnt();
	printf("pid %ld: e%d.%d, %lld sectors %s, maxscnt: %u%s%s\n",
		(long) getpid(), shelf, slot, size,
		readonly ? "O_RDONLY" : "O_RDWR",  maxscnt,
		rx_tags_tracking ? ", RX tags tracking" : "",
		write_tags_tracking ? ", WRITE tags tracking (ARE YOU SURE?!)" : "");
#ifdef USE_AIO
	if ((omode&O_DIRECT)!=O_DIRECT)
		printf("AIO without -d option (O_DIRECT) is near to useless!\n");
#endif
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
	bfd_flush();
	exit(ncode);
}
