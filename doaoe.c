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
#include <endian.h>
#include <fcntl.h>
#include <netinet/in.h>
#include "dat.h"
#include "fns.h"
#include <netinet/if_ether.h>


static const unsigned long x04030201 = 0x04030201;
static unsigned long ReverseEndianess(unsigned long x)
{
	return ( (((x)>>24)&0xff) | (((x)>>8)&0xff00) | (((x)<<8)&0xff0000) | (((x)<<24)&0xff000000) );
}

#define LE2HST(x)	( (1==*(unsigned char *)&x04030201) ? x : ReverseEndianess(x) )
#define BE2HST(x)	( (4==*(unsigned char *)&x04030201) ? x : ReverseEndianess(x) )

static inline void 
sfd_putpkt_or_die(uchar *data, int len)
{
	if (putpkt(sfd, data, len) == -1) {
		perror("sfd_putpkt_or_die: write to network");
		grace_exit(1);
	}
}


static inline long long
getlba(uchar cmd, uchar *p)
{
	uchar *px = p + 6;
	vlong v = 0;

	do {
		v<<= 8;
		v+= *(--px);
	} while (px!=p);

	switch (cmd) {
	case 0x30:		// write sectors
	case 0x20:		// read sectors
		v&= MAXLBA28SIZE;
		break;

	case 0x34:		// write sectors ext
	case 0x24:		// read sectors ext
		v&= 0x0000ffffffffffffLL;	// full 48
		break;
	}
	return v;
}

static void
ataerror(Ata *op, uchar	error)	
{
	fprintf(stderr, "ataerror (%d): cmd=%d sectors=%d\n", error, op->cmd, op->sectors);

	op->h.flags |= Error;
	op->h.error = error;	
	op->cmd = ERR;
	sfd_putpkt_or_die((uchar *)op, Nata);
}

static void
ataoutofsize(Ata *op)	
{
	op->err = IDNF;
	op->cmd = DRDY | ERR;
	sfd_putpkt_or_die((uchar *)op, Nata);
}

static void
atareply(Ataregs *r, Ata *op) {
	int len;
	if ((op->aflag & Write) == 0 && (len = op->sectors) != 0) {
		len*= 512;
		len+= sizeof (Ata);
	} else
		len = Nata;

	op->sectors = r->sectors;
	op->err = r->err;
	op->cmd = r->status;
	sfd_putpkt_or_die((uchar *)op, len);
}

void
aoeata(Ata *p, Ata *op, int pktlen, uchar dup)	// do ATA reqeust
{
#ifdef FORCE_ASYNC_WRITES
	const uchar write_async = 1;
#else
	const uchar write_async = (p->aflag&Async)!=0;
#endif
	Ataregs r;
	r.cmd = p->cmd;

	if (!rrok(p->h.src) && r.cmd != 0xec)
		return ataerror(op, Res);

	r.lba = getlba(r.cmd, p->lba);
	r.sectors = p->sectors;
	switch (r.cmd)
	{
		case 0x30: case 0x34://write, write ext
			if (sizeof(*p) + 512 * r.sectors > pktlen) 
				return ataerror(op, BadArg);

			if (r.lba + r.sectors > size) 
				return ataoutofsize(op);

			if (dup || write_async) {
				op->cmd = DRDY;
				sfd_putpkt_or_die((uchar *)op, Nata);
				if (dup) {
#ifdef KEEP_STATS
					++skipped_writes;
#endif		
					return;
				}
			} 

			op->cmd = r.cmd;
			atawrite(&r, (uchar *)(p+1));
			if (!write_async) {
				atareply(&r, op);
			} else if (r.err == ABRT) {
				fprintf(stderr, 
					"Failed to complete async write  (%d, %d). Exiting to avoid data corruption.\n", 
					r.sectors, p->sectors);
				grace_exit(errno);
			}			
			break;


		case 0x20: case 0x24://read, read ext
			if (r.sectors > maxscnt) {
				ataerror(op, BadArg);
			} else if (r.lba + r.sectors > size) {
				ataoutofsize(op);
			} else {
				ataread(&r, (uchar *)(op+1));
				atareply(&r, op);
			}

			if (coalesced_read && pktlen>=(sizeof(Ata) + 1 + sizeof(AtaCoalescedRead)) ) {
				uchar nacr = *(uchar *)(p + 1);
				AtaCoalescedRead *acr = (AtaCoalescedRead *)((uchar *)(p + 1) + 1);
				for (;(nacr && pktlen>=((char *)(acr+1) - (char *)p)); --nacr,++acr) {
					r.lba = getlba(r.cmd, acr->lba);
					r.sectors = op->sectors = acr->sectors;
					memcpy(op->h.tag, acr->tag, sizeof(op->h.tag));
					memcpy(op->lba, acr->lba, sizeof(op->lba));
					memcpy(op->resvd, acr->resvd, sizeof(op->resvd));

					if (r.sectors > maxscnt)  {
						ataerror(op, BadArg);
					} else if (r.lba + r.sectors > size)  {
						ataoutofsize(op);
					} else {
						ataread(&r, (uchar *)(op+1));
						atareply(&r, op);
					}
				}
				if (nacr) 
					fprintf(stderr, "Coalesced read truncated: nacr=%u\n", nacr);
		    }
			break;

		case 0xec:	// identify device
			if (r.sectors != 1 || maxscnt<1)
				return ataerror(op, BadArg);

		default:
			atactl(&r, (uchar *)(op+1) );
			atareply(&r, op);
	}

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
			if (tags_tracking==TAGS_INC_LE || tags_tracking==TAGS_INC_BE)
				tagring_reset_id((p - masks)/Alen);
			return 2;
		}
	}

	if (nmasks >= Nmasks)
		return 0;

	memmove(p, ea, Alen);
	if (tags_tracking==TAGS_INC_LE || tags_tracking==TAGS_INC_BE)
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

static uchar
match_feat( char *feat, const char *check )
{
	if (strcmp(feat, check)!=0)
		return 0;

    for (; *feat; ++feat) 
		if (*feat>='a' && *feat<='z') 
			*feat-= ('a' - 'A');

	return 1;
}

static void
resetextensions() {
	coalesced_read = 0;
	tags_tracking = TAGS_ANY;
}

static int
aoeextensions(Aoeextensions *fh, int n)
{
	char *feat;
	if (n<sizeof(Aoeextensions) || n<(sizeof(Aoeextensions) + fh->len) ||
		fh->len<2 || fh->extensions[fh->len-2] || fh->extensions[fh->len-1]) {
		fprintf(stderr, "bad aoeextensions packet\n");
		return -1;
	}
	for (feat = fh->extensions; *feat; feat+= (strlen(feat)+1)) {
		if (match_feat(feat, "reset")) {
			printf("Reset extensions\n");
			resetextensions();
		} else if (match_feat(feat, "coalesced_read")) {
			coalesced_read = 1;
			printf("Coalesced read\n");
	    } else if (match_feat(feat, "tag_inc_le")) {
			tags_tracking = TAGS_INC_LE;
			printf("Tags: incrementing LE\n");
	    } else if (match_feat(feat, "tag_inc_be")) {
			tags_tracking = TAGS_INC_BE;
			printf("Tags: incrementing BE\n");
	    } else if (match_feat(feat, "tag_random")) {
			tags_tracking = TAGS_RANDOM;
			printf("Tags: random\n");
	    }
    }
	return n;
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
	switch (tags_tracking) {
		case TAGS_INC_LE://incrementing little-endian
			dup = tagring_process(LE2HST(*(unsigned long *)&p->tag[0]));
			break;

		case TAGS_INC_BE://incrementing big-endian
			dup = tagring_process(BE2HST(*(unsigned long *)&p->tag[0]));
			break;

		default:
			dup = 0;
	}
	
	switch (cmd) {
	case ATAcmd:
		if (n < Natahdr) 
			return;
		return aoeata((Ata*)p, (Ata*)op, n, dup);

	case Config:
		if (n < Ncfghdr)
			return;
		resetextensions();
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
	case Extensions:
		if (n < sizeof(Aoeextensions) )
			return;

		len = aoeextensions((Aoeextensions *)op, n);
		break;

	default:
		op->error = BadCmd;
		op->flags |= Error;
		len = n;
	}
	if (len > 0)
		sfd_putpkt_or_die((uchar *)op, len);
}
