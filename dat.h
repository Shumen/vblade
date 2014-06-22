/* dat.h: include file for aoede AoE target */

#define	nil	((void *)0)
/*
 *	tunable variables
 */

enum {
	AOEDE_VERSION		= 21,//same as VBLADE_VERSION from vblade project

	// Firmware version
	FWV			= 0x4000 + AOEDE_VERSION,
};

#undef major
#undef minor
#undef makedev

#define	major(x)		((x) >> 24 & 0xFF)
#define	minor(x)		((x) & 0xffffff)
#define	makedev(x, y)	((x) << 24 | (y))

#define Z_ALIGN(x, z)        (((x)+(z)-1)&~((z)-1))
#define PAGE_ALIGN(x)        Z_ALIGN(x, getpagesize())


//Set in stone, do not change
#define SECTOR_SIZE		512 	


typedef unsigned char uchar;
//typedef unsigned short ushort;
#ifdef __FreeBSD__
typedef unsigned long ulong;
#else
//typedef unsigned long ulong;
#endif
typedef long long vlong;

typedef struct Aoehdr Aoehdr;
typedef struct Ata Ata;
typedef struct Conf Conf;
typedef struct Ataregs Ataregs;
typedef struct Mdir Mdir;
typedef struct Aoemask Aoemask;
typedef struct Aoesrr Aoesrr;
typedef struct Aoeextensions Aoeextensions;
typedef struct AtaCoalescedRead AtaCoalescedRead;

struct Ataregs
{
	vlong	lba;
	uchar	cmd;
	uchar	status;
	uchar	err;
	uchar	sectors;
};

struct Aoehdr
{
	uchar	dst[6];
	uchar	src[6];
	ushort	type;
	uchar	flags;
	uchar	error;
	ushort	maj;
	uchar	min;
	uchar	cmd;
	uchar	tag[4];
};

struct AtaCoalescedRead
{
	uchar	tag[4];
	uchar	lba[6];
	uchar	resvd[5];
	uchar	sectors;
};

struct Ata
{
	Aoehdr	h;
	uchar	aflag;
	uchar	err;
	uchar	sectors;
	uchar	cmd;
	uchar	lba[6];
	uchar	resvd[2];
};

struct Conf
{
	Aoehdr	h;
	ushort	bufcnt;
	ushort	firmware;
	uchar	scnt;
	uchar	vercmd;
	ushort	len;
	uchar	data[1024];
};

// mask directive
struct Mdir {
	uchar res;
	uchar cmd;
	uchar mac[6];
};

struct Aoemask {
	Aoehdr h;
	uchar res;
	uchar cmd;
	uchar merror;
	uchar nmacs;
//	struct Mdir m[0];
};

struct Aoesrr {
	Aoehdr h;
	uchar rcmd;
	uchar nmacs;
//	uchar mac[6][nmacs];
};

struct Aoeextensions {
	Aoehdr h;
	ushort len;
    char extensions[];
};


enum {
	AoEver = 1,

	ATAcmd = 0,		// command codes
	Config,
	Mask,
	Resrel,
	Extensions = Resrel + 0x20,

	Resp = (1<<3),		// flags
	Error = (1<<2),

	BadCmd = 1,
	BadArg,
	DevUnavailable,
	ConfigErr,
	BadVersion,
	Res,

	Write = (1<<0),
	Async = (1<<1),
	Device = (1<<4),
	Extend = (1<<6),

	Qread = 0,
	Qtest,
	Qprefix,
	Qset,
	Qfset,

	Nretries = 3,
	Nconfig = 1024,
#ifdef SOCK_RXRING
	Bufcount = 64,
#else
	Bufcount = 16,
#endif
	/* mask commands */
	Mread= 0,	
	Medit,

	/* mask directives */
	MDnop= 0,
	MDadd,
	MDdel,

	/* mask errors */
	MEunspec= 1,
	MEbaddir,
	MEfull,

	/* header sizes, including aoe hdr */
	Naoehdr= 24,
	Natahdr= Naoehdr + 12,
	Ncfghdr= Naoehdr + 8,
	Nmaskhdr= Naoehdr + 4,
	Nsrrhdr= Naoehdr + 2,
	Nata= 60,

	Nserial= 20,
};

enum {
	// err bits
	UNC =	1<<6,
	MC =	1<<5,
	IDNF =	1<<4,
	MCR =	1<<3,
	ABRT = 	1<<2,
	NM =	1<<1,

	// status bits
	BSY =	1<<7,
	DRDY =	1<<6,
	DF =	1<<5,
	DRQ =	1<<3,
	ERR =	1<<0,
};


enum {
	Nmasks= 32,
	Nsrr= 256,
	Alen= 6,
};

enum {
	TAGS_ANY = 0,
    TAGS_INC_LE = 1,
    TAGS_INC_BE = 2,
    TAGS_RANDOM = 3
};

enum { MAXLBA28SIZE = 0x0fffffff };	


extern uchar freeze_stopping;
extern uchar freeze_active;

extern uchar	masks[Nmasks*Alen];
extern int	nmasks;
extern uchar	srr[Nsrr*Alen];
extern int	nsrr;
extern char	config[Nconfig];
extern int	nconfig;
extern int	bufcnt;
extern int	shelf, slot;
extern ushort  shelf_net, type_net;
extern uchar	mac[6];
extern int	bfd;		// block file descriptor
extern int	sfd;		// socket file descriptor
extern vlong	size;		// size of blade
extern uchar	bfd_blocks_per_sector;	//how many AoE sectors contained in FS block 
extern char	*progname;
extern char	serial[Nserial+1];
extern uchar	tags_tracking;// TAGS_*
extern uchar	coalesced_read;
extern int	maxscnt;
extern char *	ifname;
extern char *	freeeze_path;
extern vlong	freeeze_size_limit;

#ifdef KEEP_STATS
extern vlong skipped_writes;
extern vlong skipped_packets;
#endif
