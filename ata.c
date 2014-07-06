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

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h> 
#include <errno.h>
#include <sys/types.h>
#include "dat.h"
#include "fns.h"

static ushort ident[256];

static void
setfld(ushort *a, int idx, int len, char *str)	// set field in ident
{
	uchar *p;

	p = (uchar *)(a+idx);
	while (len > 0) {
		if (*str == 0)
			p[1] = ' ';
		else
			p[1] = *str++;
		if (*str == 0)
			p[0] = ' ';
		else
			p[0] = *str++;
		p += 2;
		len -= 2;
	}
}

static void
setlba28(ushort *ident, vlong lba)
{
	uchar *cp;

	cp = (uchar *) &ident[60];
	*cp++ = lba;
	*cp++ = lba >>= 8;
	*cp++ = lba >>= 8;
	*cp++ = (lba >>= 8) & 0xf;
}

static void
setlba48(ushort *ident, vlong lba)
{
	uchar *cp;

	cp = (uchar *) &ident[100];
	*cp++ = lba;
	*cp++ = lba >>= 8;
	*cp++ = lba >>= 8;
	*cp++ = lba >>= 8;
	*cp++ = lba >>= 8;
	*cp++ = lba >>= 8;
}

static void
setushort(ushort *a, int i, ushort n)
{
	uchar *p;

	p = (uchar *)(a+i);
	*p++ = n & 0xff;
	*p++ = n >> 8;
}

void
atainit(void)
{
	char buf[64];

	setushort(ident, 47, 0x8000);
	setushort(ident, 49, 0x0200);
	setushort(ident, 50, 0x4000);
	setushort(ident, 83, 0x5400);
	setushort(ident, 84, 0x4000);
	setushort(ident, 86, 0x1400);
	setushort(ident, 87, 0x4000);
	setushort(ident, 93, 0x400b);
	setfld(ident, 27, 40, "AoEde virtual blade");
	sprintf(buf, "V%d", AOEDE_VERSION);
	setfld(ident, 23, 8, buf);
	setfld(ident, 10, 20, serial);
}



static struct 
{
	Ata *request;
	Ata *reply;//Natahdr bytes header preinitialized
	Ataregs r;
} ataio_ctx;


#define atapreinit(reply) { \
	preinit_reply_hdr(&(ataio_ctx.request)->h, &(reply)->h); \
	(reply)->aflag = (ataio_ctx.request)->aflag; \
	memcpy(&(reply)->lba, &(ataio_ctx.request)->lba, sizeof((reply)->lba) + sizeof((reply)->resvd)); }

static void
ataerror(uchar error)	
{
	fprintf(stderr, "ataerror (%d): cmd=%d sectors=%d\n", 
			error, ataio_ctx.reply->cmd, ataio_ctx.reply->sectors);
	atapreinit(ataio_ctx.reply);
	ataio_ctx.reply->h.flags |= Error;
	ataio_ctx.reply->h.error = error;	
	ataio_ctx.reply->sectors = ataio_ctx.request->sectors;
	ataio_ctx.reply->cmd = ERR;
	sfd_putpkt_or_die((uchar *)ataio_ctx.reply, Nata);
}

static void
ataoutofsize()	
{
	atapreinit(ataio_ctx.reply);
	ataio_ctx.reply->err = IDNF;
	ataio_ctx.reply->sectors = ataio_ctx.request->sectors;
	ataio_ctx.reply->cmd = DRDY | ERR;
	sfd_putpkt_or_die((uchar *)ataio_ctx.reply, Nata);
}

static void
atareply(Ata *ata_responce) {
	int len;
	atapreinit(ata_responce);
	if ((ata_responce->aflag & Write) == 0 && (len = ataio_ctx.request->sectors) != 0) {
		len*= SECTOR_SIZE;
		len+= sizeof(Ata);
	} else
		len = Nata;
	ata_responce->err = ataio_ctx.r.err;
	ata_responce->sectors = ataio_ctx.r.sectors;
	ata_responce->cmd = ataio_ctx.r.status;

#ifdef SUPPORT_CRC
	if (len>Nata) {
		uchar saved_bytes[4];
	    memcpy(&saved_bytes[0], ((uchar *)ata_responce) + len, sizeof(saved_bytes));
		aoecrc8x4_append(((uchar *)ata_responce) + sizeof(Aoehdr), len - sizeof(Aoehdr));
		sfd_putpkt_or_die((uchar *)ata_responce, len + 4);
		memcpy(((uchar *)ata_responce) + len, &saved_bytes[0], sizeof(saved_bytes));
		return;
	}
#endif

	sfd_putpkt_or_die((uchar *)ata_responce, len);
}

static void 
ataafterio(int n) {
	n /= SECTOR_SIZE;
	if (AOE_LIKELY((ataio_ctx.r.sectors -= n) == 0)) {
		ataio_ctx.r.err = 0;
		ataio_ctx.r.status = DRDY;
	} else {
		ataio_ctx.r.err = ABRT;
		ataio_ctx.r.status = ERR | DRDY;
	}
//not used by caller	r->lba += n;
}

static void
lba2ctx(uchar *p)
{
	uchar *px = p + 6;
	ataio_ctx.r.lba = 0;
	do {
		ataio_ctx.r.lba<<= 8;
		ataio_ctx.r.lba+= *(--px);
	} while (px!=p);

	switch (ataio_ctx.r.cmd) {
	case 0x30:		// write sectors
	case 0x20:		// read sectors
		ataio_ctx.r.lba&= MAXLBA28SIZE;
		break;

	case 0x34:		// write sectors ext
	case 0x24:		// read sectors ext
		ataio_ctx.r.lba&= 0x0000ffffffffffffLL;	// full 48
		break;
	}
}

void 
rd_callback_preserve_header_space(Ata *ata_responce, int nret)
{
	uchar tmp[sizeof(Ata)];
	memcpy(&tmp[0], ata_responce, sizeof(Ata));
	ataafterio(nret);
	atareply(ata_responce);
	memcpy(ata_responce, &tmp[0], sizeof(Ata));
}

void 
rd_callback(Ata *ata_responce, int nret)
{
	ataafterio(nret);
	atareply(ata_responce);
}

void 
rd_callback_with_preinit_buffer(int nret)
{
	ataafterio(nret);
	atareply(ataio_ctx.reply);
}

static void
aoeataread(int pktlen)
{
	if (AOE_UNLIKELY(ataio_ctx.r.sectors > maxscnt))
		ataerror(BadArg);
	else if (AOE_UNLIKELY(ataio_ctx.r.lba + ataio_ctx.r.sectors > size))
		ataoutofsize();
	else 
		iox_getsec(ataio_ctx.reply, ataio_ctx.r.lba, ataio_ctx.r.sectors); //reply will be sent from callback

	if (coalesced_read && pktlen>=(sizeof(Ata) + 1 + sizeof(AtaCoalescedRead)) ) {
		uchar nacr = *(uchar *)(ataio_ctx.request + 1);
		AtaCoalescedRead *acr = (AtaCoalescedRead *)((uchar *)(ataio_ctx.request + 1) + 1);
		for (;(nacr && pktlen>=((char *)(acr+1) - (char *)ataio_ctx.request)); --nacr,++acr) {
			lba2ctx(acr->lba);
			ataio_ctx.r.sectors = ataio_ctx.request->sectors = acr->sectors;
			memcpy(ataio_ctx.request->h.tag, acr->tag, sizeof(ataio_ctx.request->h.tag));
			memcpy(&ataio_ctx.request->lba, acr->lba, sizeof(ataio_ctx.request->lba) + sizeof(ataio_ctx.request->resvd));
//			memcpy(request->resvd, acr->resvd, sizeof(request->resvd));

			if (AOE_UNLIKELY(ataio_ctx.r.sectors > maxscnt))
				ataerror(BadArg);
			else if (AOE_UNLIKELY(ataio_ctx.r.lba + ataio_ctx.r.sectors > size))
				ataoutofsize();
			else
				iox_getsec(ataio_ctx.reply, ataio_ctx.r.lba, ataio_ctx.r.sectors); //reply will be sent from callback
		}
		if (AOE_UNLIKELY(nacr))
			fprintf(stderr, "Coalesced read truncated: nacr=%u\n", nacr);
    }
}

static void
aoeatawrite(int pktlen, uchar dup)
{
#ifdef FORCE_ASYNC_WRITES
	const uchar write_async = 1;
#else
	const uchar write_async = (ataio_ctx.request->aflag&Async)!=0;
#endif

	if (AOE_UNLIKELY(sizeof(Ata) + SECTOR_SIZE * ataio_ctx.r.sectors > pktlen))
		return ataerror(BadArg);

#ifdef SUPPORT_CRC
	if (enable_crc==1 && (sizeof(Ata) + SECTOR_SIZE * ataio_ctx.r.sectors + 4) <= pktlen) {
		if (!aoecrc8x4_verify((uchar *)(ataio_ctx.request + 1) - (sizeof(Ata) - sizeof(Aoehdr)), 
						ataio_ctx.r.sectors*SECTOR_SIZE + (sizeof(Ata) - sizeof(Aoehdr)))) {
			fprintf(stderr, "Write request CRC error\n");
			return;
		}
	}
#endif

	if (AOE_UNLIKELY(ataio_ctx.r.lba + ataio_ctx.r.sectors > size))
		return ataoutofsize();

	if (write_async || AOE_UNLIKELY(dup)) {
		atapreinit(ataio_ctx.reply);
		ataio_ctx.reply->cmd = DRDY;
		ataio_ctx.reply->err = 0;
		ataio_ctx.reply->sectors = 0;
		sfd_putpkt_or_die((uchar *)ataio_ctx.reply, Nata);
		if (AOE_UNLIKELY(dup)) {
#ifdef KEEP_STATS
			++skipped_writes;
#endif		
			return;
		}
	} 

	ataafterio(
		iox_putsec((uchar *)(ataio_ctx.request + 1), ataio_ctx.r.lba, ataio_ctx.r.sectors) );

	if (!write_async) {
		atareply(ataio_ctx.reply);
	} else if (AOE_UNLIKELY(ataio_ctx.r.err == ABRT)) {
		fprintf(stderr, "Failed to complete async write  (%d, %d). Exiting to avoid data corruption.\n", 
			ataio_ctx.r.sectors, ataio_ctx.request->sectors);
		grace_exit(errno);
	}			
}


/* The ATA spec is weird in that you specify the device size as number
 * of sectors and then address the sectors with an offset.  That means
 * with LBA 28 you shouldn't see an LBA of all ones.  Still, we don't
 * check for that.
 */
static void
atactl() 
{
	uchar *odp = (uchar *)(ataio_ctx.reply + 1);
	ushort *ip;
	switch (ataio_ctx.r.cmd) {
	case 0xec:		// identify device
		if (AOE_UNLIKELY(ataio_ctx.r.sectors != 1 || maxscnt<1))
			return ataerror(BadArg);

		memcpy(odp, ident, SECTOR_SIZE);
		ip = (ushort *)odp;
		if (size & ~MAXLBA28SIZE)
			setlba28(ip, MAXLBA28SIZE);
		else
			setlba28(ip, size);
		setlba48(ip, size);
		ataio_ctx.r.err = 0;
		ataio_ctx.r.sectors = 0;
		ataio_ctx.r.status = DRDY;
		break;

	case 0xe7:		// flush cache
		ataio_ctx.r.err = 0;
		ataio_ctx.r.status = DRDY;
		break;

	case 0xe5:		// check power mode
		ataio_ctx.r.err = 0;
		ataio_ctx.r.sectors = 0xff; // the device is active or idle
		ataio_ctx.r.status = DRDY;
		break;

	default:
		ataio_ctx.r.err = ABRT;
		ataio_ctx.r.status = DRDY | ERR;
	}

	atareply(ataio_ctx.reply);
}

void
aoeata(Ata *request, Ata *reply, int pktlen, unsigned long tag)	// do ATA reqeust
{
	ataio_ctx.r.cmd = request->cmd;

	if (AOE_UNLIKELY(!rrok(request->h.src) && ataio_ctx.r.cmd != 0xec))
		return ataerror(Res);

	ataio_ctx.request = request;
	ataio_ctx.reply = reply;
	lba2ctx(request->lba);
	ataio_ctx.r.sectors = request->sectors;
	switch (ataio_ctx.r.cmd)
	{
		case 0x20: case 0x24://read, read ext
			if (tag)
				tagring_check_offside(tag);
			aoeataread(pktlen);
			break;

		case 0x30: case 0x34://write, write ext
			aoeatawrite(pktlen, (tag && tagring_get_and_set(tag)) );
			break;

		default:			
			atactl();
	}
}
