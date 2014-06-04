// linux.c: low level access routines for Linux
#define _GNU_SOURCE
#include "config.h"
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <errno.h>

#include "dat.h"
#include "fns.h"

int	getindx(int, char *);
int	getea(int, char *, uchar *);



int
dial(char *eth, int bufcnt)		// get us a raw connection to an interface
{
	int i, n, s;
	struct sockaddr_ll sa;
#if POISON_RECV || POISON_SEND
	srand(time(NULL))
#endif
	memset(&sa, 0, sizeof sa);
	s = socket(PF_PACKET, SOCK_RAW, type_net);
	if (s == -1) {
		perror("got bad socket");
		return -1;
	}
	i = getindx(s, eth);
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = type_net;
	sa.sll_ifindex = i;
	n = bind(s, (struct sockaddr *)&sa, sizeof sa);
	if (n == -1) {
		perror("bind funky");
		return -1;
	}

	struct bpf_program {
		ulong bf_len;
		void *bf_insns;
	} *bpf_program = create_bpf_program(shelf, slot);
	setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, bpf_program, sizeof(*bpf_program));
	free_bpf_program(bpf_program);

	n = getmtu(s, eth);
        n*= bufcnt;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) < 0)
		perror("setsockopt SOL_SOCKET, SO_SNDBUF");
#ifndef SOCK_RXRING
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) < 0)
		perror("setsockopt SOL_SOCKET, SO_RCVBUF");
#endif
	return s;
}

int
getindx(int s, char *name)	// return the index of device 'name'
{
	struct ifreq xx;
	int n;

	strcpy(xx.ifr_name, name);
	n = ioctl(s, SIOCGIFINDEX, &xx);
	if (n == -1)
		return -1;
	return xx.ifr_ifindex;
}

int
getea(int s, char *name, uchar *ea)
{
	struct ifreq xx;
	int n;

        strcpy(xx.ifr_name, name);
	n = ioctl(s, SIOCGIFHWADDR, &xx);
	if (n == -1) {
		perror("Can't get hw addr");
		return 0;
	}
	memmove(ea, xx.ifr_hwaddr.sa_data, 6);
	return 1;
}

int
getmtu(int s, char *name)
{
	struct ifreq xx;
	int n;

	strcpy(xx.ifr_name, name);
	n = ioctl(s, SIOCGIFMTU, &xx);
	if (n == -1) {
		perror("Can't get mtu");
		return 1500;
	}
	return xx.ifr_mtu;
}

int
getsec(int fd, uchar *place, vlong lba, int nsec)
{
	int n = pread(fd, place, nsec * 512, lba * 512);
	if (n!=nsec * 512)
	{
		perror("getsec failed");
		printf("place=%p lba=%llu nsec=%d\n", place, lba, nsec);
	}
	return n;
}

int
putsec(int fd, uchar *place, vlong lba, int nsec)
{
	int n = pwrite(fd, place, nsec * 512, lba * 512);
	if (n!=nsec * 512)
	{
		perror("putsec failed");
		printf("place=%p lba=%llu nsec=%d\n", place, lba, nsec);
	}
	return n;
}

int
getpkt(int fd, uchar *buf, int sz)
{
#if POISON_RECV
    while ((rand()%POISON_RECV)==0)
        read(fd, buf, sz);
#endif

	return read(fd, buf, sz);
}

int
putpkt(int fd, uchar *buf, int sz)
{
#if POISON_SEND
    if ((rand()%POISON_SEND)==0)
        return sz;
#endif
	return write(fd, buf, sz);
}

vlong
getsize(int fd)
{
	vlong size;
	struct stat s;
	int n;

	n = ioctl(fd, BLKGETSIZE64, &size);
	if (n == -1) {	// must not be a block special
		n = fstat(fd, &s);
		if (n == -1) {
			perror("getsize");
			grace_exit(1);
		}
		size = s.st_size;
	}
	return size;
}


#ifdef SOCK_RXRING

////////////////////////////////////////////////////////////////////////////
//,...even ring can has end
//Memory mapped ring buffer -based receive implementation
//TODO: implement USE_TX_RING for sending data and thus minimize mem copy-s
//buffer for data sending still necessary also with RX ring cause 
//PACKET_RX_RING doesn't have ability to align data as we need
//BTW PACKET_TX_RING DOES allow this, so when PACKET_TX_RING
//will be implemented  - malloc'ed buffer can be removed completely
//NB: there're systems that support RX ring but don't support TX ring
/////////////////////////////////////////////////////////////////////////////

#include <linux/if_packet.h>
#include <sys/mman.h>
#include <poll.h>
#include <assert.h>

#define PACKET_TAG(pd)	(*(ulong *)&((const Aoehdr *)(pd))->tag[0])
#define OFFSET_PTR(ptr, adding) (((void *)(ptr)) + (adding))
#define ROLL_PTR(ptr, adding, base, limit) if (limit==(ptr=OFFSET_PTR(ptr, adding))) ptr = base; 


void doaoe(Aoehdr *p, Aoehdr *op, int n);

static struct PacketsRing
{
	int frames;
	int frame_size;
	char *ring;
} rx_ring = {0};

static int 
poll_rx_ring_socket(struct tpacket_hdr *header) 
{
	struct pollfd pollset;
	int r, idle_hint;
	for (;;) {
		pollset.fd = sfd;
		pollset.events = POLLIN;
		pollset.revents = 0;

		idle_hint = bfd_idle_begin();
		r = (idle_hint!=0) ? poll(&pollset, 1, idle_hint) : 1;
			
		if ((header->tp_status & TP_STATUS_USER)!=0)
			return 0;

		if (r==0) {
			bfd_idle_elapsed(idle_hint);
#ifdef KEEP_STATS
			if (rx_tags_tracking || write_tags_tracking)
				printf("skipped_writes=%llu skipped_packets=%llu\n", skipped_writes, skipped_packets);
#endif
		}
		else if (r < 0) {
			if (errno != EINTR) {
				perror("poll()");
				return -1;
			}
			usleep(1000);
		}
	}
}

static void 
roll_rx_ring_with_tags_tracking(uchar *buf) 
{
	struct tpacket_hdr *rx_base = (struct tpacket_hdr *) rx_ring.ring;
	struct tpacket_hdr *rx_limit = (struct tpacket_hdr *)
			(rx_ring.ring + rx_ring.frames*rx_ring.frame_size);
	struct tpacket_hdr *rx;

	//using this buffer with forward-collected information highly improves
	//performance on minimalistic boxes due to minimizing accessed memory pages
	//while looking for duplicated packets
	struct FwdPacketInfo
	{
		//-2 means this structure doesn't contain relevant information
		//-1 means that packet should be ignored
		//any other value - packet valid and this is its corresponding mask index
		int mask;

		//valid packet tag value (if mask>=0)
		ulong tag;
	} *fpi_base = (struct FwdPacketInfo *)alloca(rx_ring.frames * sizeof(struct FwdPacketInfo));
	struct FwdPacketInfo *fpi, *fpi_limit = fpi_base + rx_ring.frames;

	//init all fpi entries as not containing relevant information
	for (fpi = fpi_base; fpi!=fpi_limit; ++fpi) 
		fpi->mask = -2;	

	for (fpi = fpi_base, rx = rx_base;;) {
		int mask = fpi->mask;

		if ((rx->tp_status & TP_STATUS_USER)==0) {//if we have nothing then lets wait for something
			if (poll_rx_ring_socket(rx)<0)
				break;			
		}

		if (mask!=-1 && (mask>=0 || (rx->tp_status & TP_STATUS_COPY)==0)) {
			ulong tag;
			void *data = OFFSET_PTR(rx, rx->tp_mac);
			int len = rx->tp_snaplen;

			if (mask==-2)  {
				mask = packet_check(data, len);	
				if (mask>=0)
					tag = PACKET_TAG(data);
			}
			else
				tag = fpi->tag;
				
			if (mask>=0) {
				//look forward for duplicated packets
				//first check relevant forward-collected entries 
				struct FwdPacketInfo *tmp_fpi = fpi;
				for (;;) {
					ROLL_PTR(tmp_fpi, sizeof(struct FwdPacketInfo), fpi_base, fpi_limit);
					if (tmp_fpi==fpi) //reached end of ring, nothing to check more 
						break;
					
					if (tmp_fpi->mask==-2) {//reached end of relevant collected entries following 
											//nested loop inspects remaining valid RX entries in ring
						struct tpacket_hdr *tmp_rx = //start from corresponding RX entry
							OFFSET_PTR(rx_base, (tmp_fpi - fpi_base)*rx_ring.frame_size);

						while ((tmp_rx->tp_status & TP_STATUS_USER)!=0) {
							assert(tmp_rx!=rx);
							
							if ((tmp_rx->tp_status & TP_STATUS_COPY)==0) {
								void *tmp_data = OFFSET_PTR(tmp_rx, tmp_rx->tp_mac);
								if ((tmp_fpi->mask = packet_check(tmp_data, tmp_rx->tp_snaplen))>=0 &&
									tag==(tmp_fpi->tag = PACKET_TAG(tmp_data)) && tmp_fpi->mask==mask) {//duplicated packet
									tmp_fpi->mask = -1;
#ifdef KEEP_STATS
									++skipped_packets;
#endif
								}
							}
							else
								tmp_fpi->mask = -1;

							ROLL_PTR(tmp_rx, rx_ring.frame_size, rx_base, rx_limit);
							ROLL_PTR(tmp_fpi, sizeof(struct FwdPacketInfo), fpi_base, fpi_limit);
							if (tmp_fpi==fpi) 
								break;
						}

						break;
					}

					if (tmp_fpi->tag==tag && tmp_fpi->mask==mask) {//duplicated packet
						tmp_fpi->mask = -1;
#ifdef KEEP_STATS
						++skipped_packets;
#endif
					}
				}
				

				//select corresponding tagring and deal with packet
#if POISON_RECV
               if ((rand()%POISON_RECV)!=0)
#endif
                {
					if (write_tags_tracking)
						tagring_select(mask);
					doaoe((Aoehdr *)data, (Aoehdr *)buf, len);
                }
			}
		}
		fpi->mask = -2;
		rx->tp_status = 0;
		ROLL_PTR(fpi, sizeof(struct FwdPacketInfo), fpi_base, fpi_limit);
		ROLL_PTR(rx, rx_ring.frame_size, rx_base, rx_limit);

		//both rings must be rolled synchronously
		assert( (fpi==fpi_base && rx==rx_base) || (fpi!=fpi_base && rx!=rx_base));
	}
}



static void 
roll_rx_ring_no_tags_tracking(uchar *buf) 
{
	struct tpacket_hdr *rx_base = (struct tpacket_hdr *) rx_ring.ring;
	struct tpacket_hdr *rx_limit = 
		(struct tpacket_hdr *)(rx_ring.ring + rx_ring.frames*rx_ring.frame_size);
	struct tpacket_hdr *rx;

	for (rx = rx_base;;) {
		if ((rx->tp_status & TP_STATUS_USER)==0) {//if we have nothing then lets wait for something
			if (poll_rx_ring_socket(rx)<0)
				break;			
		}

		if ((rx->tp_status & TP_STATUS_COPY)==0) {
//			if (rx->tp_status!=TP_STATUS_USER && rx->tp_status!=(TP_STATUS_USER|TP_STATUS_LOSING )) printf("strange tp_status: 0x%x\n", (unsigned int)rx->tp_status);
			void *data = OFFSET_PTR(rx, rx->tp_mac);
			int len = rx->tp_snaplen;
			int mask = packet_check(data, len);	
#if POISON_RECV
			if ((rand()%POISON_RECV)!=0)
#endif
			if (mask>=0) {
				if (write_tags_tracking)
					tagring_select(mask);
				doaoe((Aoehdr *)data, (Aoehdr *)buf, len);
			}
		}
		rx->tp_status = 0;
		ROLL_PTR(rx, rx_ring.frame_size, rx_base, rx_limit);
	}
}



////////////
//public interface

int 
rxring_init() 
{
	struct tpacket_req tp;
	rx_ring.frame_size = PAGE_ALIGN(getmtu(sfd, ifname) + 
				TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + 
				TPACKET_ALIGN(sizeof(struct sockaddr_ll)) + 32); 
	rx_ring.frames = Z_ALIGN(bufcnt, 8);
	//sometimes system fails to allocate neccessary ring space
	//try to allocate smaller one in such case
	for (;; rx_ring.frames-= 4) {
		tp.tp_block_size = rx_ring.frames * rx_ring.frame_size;
		tp.tp_block_nr = 1;
		tp.tp_frame_size = rx_ring.frame_size;
		tp.tp_frame_nr = rx_ring.frames;
		if (setsockopt(sfd, SOL_PACKET, PACKET_RX_RING, (void*) &tp, sizeof(tp))==0) 
			break;

		if (rx_ring.frames<=4) {
			perror("setsockopt() ring");
			return -1;
		}
	}

	rx_ring.ring = mmap(0, tp.tp_block_size * tp.tp_block_nr, 
				PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
	if (!rx_ring.ring) {
		perror("mmap() ring");
		return -1;
	}

	printf("Initialized RX RING of %u frames * %u bytes per frame\n", 
			rx_ring.frames, rx_ring.frame_size);
	return 0;
}

int 
rxring_deinit() 
{
	if (munmap(rx_ring.ring, rx_ring.frames * rx_ring.frame_size)) {
		perror("munmap() ring");
		return 1;
	}
	memset(&rx_ring, 0, sizeof(rx_ring));
	return 0;
}

void 
rxring_roll(uchar *buf) 
{
	if (rx_tags_tracking)
		roll_rx_ring_with_tags_tracking(buf);
	else
		roll_rx_ring_no_tags_tracking(buf);
}

int 
rxring_maxscnt() 
{
	int mtu = getmtu(sfd, ifname);
	if (rx_ring.frame_size) {//todo: re-map ring if mtu grown
		int rxring_mtu = rx_ring.frame_size - 
			TPACKET_ALIGN(sizeof(struct tpacket_hdr)) - TPACKET_ALIGN(sizeof(struct sockaddr_ll)) - 32;
		if (mtu>rxring_mtu) 
			mtu = rxring_mtu;
	}
	return (mtu - sizeof (Ata)) / 512;
}


#endif //SOCK_RXRING
