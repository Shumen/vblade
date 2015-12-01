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

// doaoe.c: the ATA over Ethernet commands processing
#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h> 
#include <unistd.h>
#include <signal.h>
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

static int last_congestion = -1;

static inline unsigned long 
reverse_endianess(unsigned long x)
{ 
	return ( (((x)>>24)&0xff) | (((x)>>8)&0xff00) | (((x)<<8)&0xff0000) | (((x)<<24)&0xff000000) );
}


#if (defined(__BYTE_ORDER) && __BYTE_ORDER  == __LITTLE_ENDIAN) || (defined(__BYTE_ORDER__) &&  __BYTE_ORDER__  == __LITTLE_ENDIAN__)

# define LE2HST(x)	(x)
# define BE2HST(x)	(reverse_endianess(x))

#elif (defined(__BYTE_ORDER) && __BYTE_ORDER  == __BIG_ENDIAN) || (defined(__BYTE_ORDER__) &&  __BYTE_ORDER__  == __BIG_ENDIAN__)

# define LE2HST(x)	(reverse_endianess(x))
# define BE2HST(x)	(x)

#else
# error "Unsupported or unknown byte order"
#endif

static void
resetextensions() {
	coalesced_read = 0;
	tags_tracking = TAGS_ANY;
#ifdef SUPPORT_CRC
	enable_crc = 0;
#endif
}


#define QCMD(x) ((x)->vercmd & 0xf)

// yes, this makes unnecessary copies.

static int
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
		resetextensions();
		break;
	default:
		p->h.flags |= Error;
		p->h.error = BadArg;
	}
	update_maxscnt();
	memmove(p->data, config, nconfig);
	p->len = htons(nconfig);
	p->bufcnt = htons(bufcnt);
	p->scnt = nics[curnic].maxscnt;
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

static int
aoeextensions(Aoeextensions *fh, int n)
{
	char *feat;
	int i;
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
		} else if (match_feat(feat, "congestion")) {
            feat+= (strlen(feat)+1);
            if (!*feat) break;
            i = atoi(feat);
			if (i!=last_congestion) {
				printf("Congestion: %d\n", i);
				last_congestion = i;
				usleep(500000);
			}
		}
#ifdef SUPPORT_CRC
        else if (match_feat(feat, "crc8x4")) {
			printf("CRC: 8x4\n");
			enable_crc = 1;
		}
#endif
    }
	return n;
}

static int
aoemask(Aoemask *mh, int len)
{
	Mdir *md, *mdi, *mde;
//	uchar *e;
	int i, n;

	n = 0;
//	e = (uchar *) mh + len;
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
doaoe(Aoehdr *request, Aoehdr *reply, int n)
{
	int len;
	const uchar cmd = request->cmd;
	unsigned long tag;
	switch (tags_tracking) {
		case TAGS_INC_LE://incrementing little-endian			
			memcpy(&tag, &request->tag[0], 4);
			tag = LE2HST(tag);
			break;

		case TAGS_INC_BE://incrementing big-endian
			memcpy(&tag, &request->tag[0], 4);
			tag = BE2HST(tag);
			break;

		default:
			tag = 0;
	}

	if (AOE_LIKELY(cmd==ATAcmd)) {
		if (n >= Natahdr)
			aoeata((Ata*)request, (Ata*)reply, n, tag);
		return;
	}

	if (tag)
		tagring_check_offside(tag);
	preinit_reply_hdr(request, reply);
	memcpy(reply + 1, request + 1, n - sizeof(Aoehdr));
	
	switch (cmd) {
	case Config:
		if (n < Ncfghdr)
			return;		
		len = confcmd((Conf *)reply, n);		
		break;
	case Mask:
		if (n < Nmaskhdr)
			return;
		len = aoemask((Aoemask *)reply, n);
		break;
	case Resrel:
		if (n < Nsrrhdr)
			return;

		len = aoesrr((Aoesrr *)reply, n);
		break;
	case Extensions:
		if (n < sizeof(Aoeextensions) )
			return;

		len = aoeextensions((Aoeextensions *)reply, n);
		break;

	default:
		reply->error = BadCmd;
		reply->flags |= Error;
		len = n;
	}
	if (len > 0)
		sfd_putpkt_or_die((uchar *)reply, len);
}

