// ata.c:  ATA simulator for aoede
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h> 
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



/* The ATA spec is weird in that you specify the device size as number
 * of sectors and then address the sectors with an offset.  That means
 * with LBA 28 you shouldn't see an LBA of all ones.  Still, we don't
 * check for that.
 */
void
atactl(Ataregs *p, uchar *odp) 
{
	ushort *ip;
	switch (p->cmd) {
	case 0xec:		// identify device
		memcpy(odp, ident, 512);
		ip = (ushort *)odp;
		if (size & ~MAXLBA28SIZE)
			setlba28(ip, MAXLBA28SIZE);
		else
			setlba28(ip, size);
		setlba48(ip, size);
		p->err = 0;
		p->sectors = 0;
		p->status = DRDY;
		break;

	case 0xe7:		// flush cache
		p->err = 0;
		p->status = DRDY;
		break;

	case 0xe5:		// check power mode
		p->err = 0;
		p->sectors = 0xff; // the device is active or idle
		p->status = DRDY;
		break;

	default:
		p->err = ABRT;
		p->status = DRDY | ERR;
	}
}

static inline void 
afterio(Ataregs *p, int n) {
	n /= 512;
	if ((p->sectors -= n) != 0) {
		p->err = ABRT;
		p->status = ERR | DRDY;
	} else {
		p->err = 0;
		p->status = DRDY;
	}

//not used by caller	p->lba += n;
}

void
ataread(Ataregs *p, uchar *odp) 
{
	int n = bfd_getsec(odp, p->lba, p->sectors);
	afterio(p, n);
}

void
atawrite(Ataregs *p, uchar *dp)
{
	int n = bfd_putsec(dp, p->lba, p->sectors);
    afterio(p, n);
}

