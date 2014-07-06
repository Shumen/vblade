// fns.h: function prototypes

// aoe.c

void	aoe(void);
void	aoeinit(void);
void	aoequery(void);
void	aoeconfig(void);
void	aoead(int);
void	aoeflush(int, int);
void	aoetick(void);
void	aoerequest(int, int, vlong, int, uchar *, int);
int	maskcheck(uchar *);
int	rrok(uchar *);


// doaoe.c
void sfd_putpkt_or_die(uchar *data, int len);
void preinit_reply_hdr(Aoehdr *request_hdr, Aoehdr *reply_hdr);
void doaoe(Aoehdr *p, Aoehdr *op, int n);


// ata.c

void	atainit(void);
void	aoeata(Ata *request, Ata *reply, int pktlen, unsigned long tag);


// bpf.c

void *	create_bpf_program(int, int);
void	free_bpf_program(void *);

// crc.c
#ifdef SUPPORT_CRC
void aoecrc8x4_append(unsigned char *data, size_t len);
unsigned char aoecrc8x4_verify(const unsigned char *data, size_t len);
#endif
// os specific

int	dial(char *, int);
int	getea(int, char *, uchar *);
int	putpkt(int, uchar *, int);
int	getpkt(int, uchar *, int);
vlong	getsize(int);
int	getmtu(int, char *);
void grace_exit(int);

static inline int 
packet_check(const void *pd, int npd) {
	if ( npd < sizeof(Aoehdr) ||
	  ((Aoehdr *) pd)->type != type_net || (((Aoehdr *) pd)->flags & Resp)!=0 ||
	  (((Aoehdr *) pd)->maj != shelf_net && ((Aoehdr *) pd)->maj != (ushort)~0) ||
	  (((Aoehdr *) pd)->min != slot && ((Aoehdr *) pd)->min != (uchar)~0) ) 
	{
		return -1;
	}

	return maskcheck(((Aoehdr *) pd)->src);
}


#ifdef SOCK_RXRING
int rxring_init();
int rxring_deinit();
void rxring_roll(uchar *buf);
int rxring_maxscnt();
static inline void 
update_maxscnt() {
	maxscnt = rxring_maxscnt();
}
#else
static inline void 
update_maxscnt() {
	maxscnt = (getmtu(sfd, ifname) - sizeof (Ata)) / SECTOR_SIZE;
}
#endif


void rd_callback_preserve_header_space(Ata *ata_responce, int nret);
void rd_callback(Ata *ata_responce, int nret);
void rd_callback_with_preinit_buffer(int nret);

// iox.c
ssize_t iox_read_packet_fd(int fd, void *buf, size_t count);
int iox_poll(int fd, int timeout);
int iox_putsec(uchar *place, vlong lba, int nsec);
void iox_getsec(struct Ata *preinit_ata_responce, vlong lba, int nsec);
void iox_flush();
void iox_init();

// freeze.c
int freeze_putsec(uchar *data, vlong offset, int len);
void freeze_getsec(struct Ata *preinit_ata_responce, vlong offset, int len);
void freeze_start();
void freeze_flush_and_stop(unsigned int time_limit);

//////////////////////////////////////////////////////////
///bfd_ functions - must be used to access disk image file

///should be called prior to any other bfd_*() here.
void bfd_init();

///Call this before entering blocking network wait.
///Returns sujjested wait timeout in seconds:
////0 if some IO performed during this call so caller can check for new packets w/o wait.
////Some suggested blocking wait timeout after what elapsion call bfd_idle_elapsed() .
////Or -1 in other cases.
int bfd_idle_begin(); 

///Call this to allow bfd to release some resources if during t msec there was no relevant activity.
void bfd_idle_elapsed(int t); 

///Call to flush any buffered data on disk, e.g. before process termination.
void bfd_flush();

///Do any IO with bfd only using following IO routines.
int bfd_putsec(uchar *place, vlong lba, int nsec);
int bfd_getsec(struct Ata *preinit_ata_responce, vlong lba, int nsec, uchar no_callback);


////////////////////////////////////////////////////
///tagring_ - used for write op tags tracking 

///Should be called prior to any other tagring_*() here.
void tagring_init();

///Releases tagring-related allocated resources.
void tagring_deinit();

///Selects specified tagring id (value from 0 to Nmasks-1).
///Or deselect any tagring by specifying -1 as id
///Returns previously selected tagring or -1
int tagring_select(int id);

///Removes all marked tags from selected tagring.
void tagring_reset();

///Resets specified by argument tagring
static inline void 
tagring_reset_id(int id) {
	int prev_id = tagring_select(id);
	tagring_reset();
	tagring_select(prev_id);
}


void tagring_check_offside(unsigned long tag);

///Call this with every new tag came from client 
///to check if its unique and put it into selected tagring.
///Returns 1 if specified tag already present in ring queue.
///Returns 0 if it doesn't and put in into that queue.
///Also return 0 if no tagring currently selected
uchar tagring_get_and_set(unsigned long tag);


