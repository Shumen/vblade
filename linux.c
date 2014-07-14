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

#define MEM_FENCE	asm volatile("": : :"memory");  
//#define MEM_FENCE	__sync_synchronize();

int
dial(char *eth, int bufcnt)		// get us a raw connection to an interface
{
	int i, n, s, mtu;
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

	mtu = getmtu(s, eth);
    n = mtu * bufcnt;
	for (;(setsockopt(s, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) < 0 && n>mtu); n-= mtu)
		perror("setsockopt SOL_SOCKET, SO_SNDBUF");

#ifndef SOCK_RXRING
    n = mtu * bufcnt;
	for (;(setsockopt(s, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) < 0 && n>mtu); n-= mtu)
		perror("setsockopt SOL_SOCKET, SO_SNDBUF");
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
		return -1;
	}
	memmove(ea, xx.ifr_hwaddr.sa_data, 6);
	return 0;
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
getpkt(uchar *buf, int sz)
{
#if POISON_RECV
    while ((rand()%POISON_RECV)==0)
        iox_read_sfd(buf, sz);
#endif
	return iox_read_sfd(buf, sz);
}

int
putpkt(uchar *buf, int sz)
{
#if POISON_SEND
    if ((rand()%POISON_SEND)==0)
        return sz;
#endif
	return write(nics[curnic].sfd, buf, sz);
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


#if defined(PACKET_RX_RING_RESERVE) && !defined(PACKET_RESERVE)
# warning "PACKET_RX_RING_RESERVE option ignored due to PACKET_RESERVE is not supported by environment."
# warning "Unaligned memory accesses can degrade performance, so consider disabling SOCK_RXRING option."
#endif

#define GET_PACKET_TAG(PACKET, TAG)	memcpy(&(TAG), &((const Aoehdr *)(PACKET))->tag[0], 4)
#define OFFSET_PTR(ptr, adding) (((void *)(ptr)) + (adding))
#define ROLL_PTR(ptr, adding, base, limit) if (limit==(ptr=OFFSET_PTR(ptr, adding))) ptr = base; 
#define ROLL_PTR_CHECK_EXIT(ptr, adding, base, limit, exit_expression, exit_value) if (limit==(ptr=OFFSET_PTR(ptr, adding))) {ptr = base; if (exit_expression) return exit_value;  }


//using this buffer with forward-collected information highly improves
//performance on minimalistic boxes due to minimizing accessed memory pages
//while looking for duplicated packets (used if tags_tracking!=TAGS_ANY)
struct FwdPacketInfo
{
	//-2 means this structure doesn't contain relevant information
	//-1 means that packet should be ignored
	//any other value - packet valid and this is its corresponding mask index
	int mask;

	//valid packet tag value (if mask>=0)
	ulong tag;
};

static struct PacketsRing
{
	volatile struct tpacket_hdr *base, *limit, *current;
	struct FwdPacketInfo *fpi_base, *fpi_limit, *fpi_current;
	int frame_size;
} 
#if (MAX_NICS>1)
	rx_rings[MAX_NICS] = {{0}}, 
#endif
	rx_selected = {0};

static int
poll_rx_rings() 
{
	int i, idle_hint;
/*#if !defined(MAX_NICS) || (MAX_NICS>1)
	for (i = 0; i<niccnt; ++i) {
		if (i!=curnic && (rx_rings[i].current->tp_status & TP_STATUS_USER)!=0) {
			rx_rings[curnic] = rx_selected;
			rx_selected = rx_rings[i];
			curnic = i;
			return 0;
		}
	}
#endif*/

	for (;;) {
		if (bfd_idle_begin()==0) {
#if (MAX_NICS>1)
			int prevnic = curnic;
#endif
			i = iox_poll(-1);
			if (i>0) {
#if (MAX_NICS>1)
				if (curnic!=prevnic) {
					rx_rings[prevnic] = rx_selected;
					rx_selected = rx_rings[curnic];
				}
#endif
			} else if (i<0) {
				perror("iox_poll()");
				return -1;
			} 
		}
		if ((rx_selected.current->tp_status & TP_STATUS_USER)!=0)
			return 0;
	}
}

//allocate FPI-s on stack to keep them in CPU cache
#define INIT_FPI(pr) { \
	pr.fpi_base = (struct FwdPacketInfo *)alloca \
		( (((char*)pr.limit - (char*)pr.base) / pr.frame_size) * sizeof(struct FwdPacketInfo)); \
	memset(pr.fpi_base, 0, (((char*)pr.limit - (char*)pr.base) / pr.frame_size) * sizeof(struct FwdPacketInfo)); \
	pr.fpi_limit = pr.fpi_base + (((char*)pr.limit - (char*)pr.base) / pr.frame_size); \
	for (pr.fpi_current = pr.fpi_limit; pr.fpi_current!=pr.fpi_base;) {--pr.fpi_current; pr.fpi_current->mask = -2; } }


static uchar
roll_rx_ring_with_tags_tracking(uchar *buf) 
{
#if (MAX_NICS>1)
	int i;
	for (i = 0; i<niccnt; ++i) {
		INIT_FPI(rx_rings[i]);
	}
	rx_selected.fpi_base = rx_rings[curnic].fpi_base;
	rx_selected.fpi_limit = rx_rings[curnic].fpi_limit;
	rx_selected.fpi_current = rx_rings[curnic].fpi_current;
#else
	INIT_FPI(rx_selected);
#endif

	for (;;) {
		if ((rx_selected.current->tp_status & TP_STATUS_USER)==0) {//if we have nothing then lets wait for something
			if (poll_rx_rings()<0)
				break;			
		}
		MEM_FENCE;

		int mask = rx_selected.fpi_current->mask;
		if (mask!=-1 && (mask>=0 || (rx_selected.current->tp_status & TP_STATUS_COPY)==0)) {
			ulong tag;
			void *data = OFFSET_PTR(rx_selected.current, rx_selected.current->tp_mac);
			int len = rx_selected.current->tp_snaplen;

#ifdef DBG_VALIDATE
			assert( (rx_selected.current->tp_status & TP_STATUS_COPY)==0 );
#endif

			if (mask==-2)  {
				mask = packet_check(data, len);	
				if (mask>=0) {
					GET_PACKET_TAG(data, tag);
				}
			}
			else
				tag = rx_selected.fpi_current->tag;
				
			if (mask>=0) {
				//look forward for duplicated packets
				//first check relevant forward-collected entries 
				struct FwdPacketInfo *tmp_fpi = rx_selected.fpi_current;
				for (;;) {
					ROLL_PTR(tmp_fpi, sizeof(struct FwdPacketInfo), rx_selected.fpi_base, rx_selected.fpi_limit);
					if (tmp_fpi==rx_selected.fpi_current) //reached end of ring, nothing to check more 
						break;
					
					if (tmp_fpi->mask==-2) {//reached end of relevant collected entries following 
											//nested loop inspects remaining valid RX entries in ring
						volatile struct tpacket_hdr *tmp_rx = //start from corresponding RX entry
							OFFSET_PTR(rx_selected.base, (tmp_fpi - rx_selected.fpi_base) * rx_selected.frame_size);

						while ((tmp_rx->tp_status & TP_STATUS_USER)!=0) {
#ifdef DBG_VALIDATE
							assert(tmp_rx!=rx_selected.current);
#endif
							
							if ((tmp_rx->tp_status & TP_STATUS_COPY)==0) {
								void *tmp_data = OFFSET_PTR(tmp_rx, tmp_rx->tp_mac);
								if ((tmp_fpi->mask = packet_check(tmp_data, tmp_rx->tp_snaplen))>=0) {
									GET_PACKET_TAG(tmp_data, tmp_fpi->tag);
									if (tag==tmp_fpi->tag && tmp_fpi->mask==mask) {//duplicated packet
										tmp_fpi->mask = -1;
#ifdef KEEP_STATS
										++skipped_packets;
#endif
									}
								}
							}
							else
								tmp_fpi->mask = -1;

							ROLL_PTR(tmp_rx, rx_selected.frame_size, rx_selected.base, rx_selected.limit);
							ROLL_PTR(tmp_fpi, sizeof(struct FwdPacketInfo), rx_selected.fpi_base, rx_selected.fpi_limit);
							if (tmp_fpi==rx_selected.fpi_current) 
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
					if (tags_tracking==TAGS_INC_LE || tags_tracking==TAGS_INC_BE)
						tagring_select(mask);
					doaoe((Aoehdr *)data, (Aoehdr *)buf, len);
                }
			}
		}
		rx_selected.fpi_current->mask = -2;
		MEM_FENCE;
		rx_selected.current->tp_status = 0;
		ROLL_PTR(rx_selected.fpi_current, sizeof(struct FwdPacketInfo), rx_selected.fpi_base, rx_selected.fpi_limit);
		ROLL_PTR_CHECK_EXIT(rx_selected.current, rx_selected.frame_size, rx_selected.base, rx_selected.limit, (tags_tracking==TAGS_ANY), 1);

#ifdef DBG_VALIDATE
		//both rings must be rolled synchronously
		assert( (rx_selected.fpi_current==rx_selected.fpi_base && rx_selected.current==rx_selected.base) 
				|| (rx_selected.fpi_current!=rx_selected.fpi_base && rx_selected.current!=rx_selected.base));
#endif
	}
	return 0;
}

static uchar
roll_rx_ring_no_tags_tracking(uchar *buf) 
{
	for (;;) {
		if ((rx_selected.current->tp_status & TP_STATUS_USER)==0) {//if we have nothing then lets wait for something
			if (poll_rx_rings()<0)
				break;			
		} 
		MEM_FENCE;

		if ((rx_selected.current->tp_status & TP_STATUS_COPY)==0) {
			void *data = OFFSET_PTR(rx_selected.current, rx_selected.current->tp_mac);
			int len = rx_selected.current->tp_snaplen;
			int mask = packet_check(data, len);	
#if defined(PACKET_RX_RING_RESERVE) && (PACKET_RX_RING_RESERVE==-1)
			static int reserve_printed = 0;
			if (!reserve_printed) {
				reserve_printed = 1;
				printf("Suggested PACKET_RX_RING_RESERVE for 4096 align: %u\n", (unsigned int)4096 - (sizeof(Ata) + rx_selected.current->tp_mac) );
				printf("Suggested PACKET_RX_RING_RESERVE for 512 align: %u\n", (unsigned int)512 - (sizeof(Ata) + rx_selected.current->tp_mac));
			}
#endif

#if POISON_RECV
			if ((rand()%POISON_RECV)!=0)
#endif
			if (mask>=0) {
				if (tags_tracking==TAGS_INC_LE || tags_tracking==TAGS_INC_BE)
					tagring_select(mask);
				doaoe((Aoehdr *)data, (Aoehdr *)buf, len);
			}
		}
		MEM_FENCE;
		rx_selected.current->tp_status = 0;
		ROLL_PTR_CHECK_EXIT(rx_selected.current, rx_selected.frame_size, rx_selected.base, rx_selected.limit, (tags_tracking!=TAGS_ANY), 1);
	}
	return 0;
}


static uchar 
is_power_of_2(unsigned int v)
{
	unsigned int c = 2;
	for (;;) {
		if (c==v)
			return 1;
		c*= 2;
		if (c>v)
			return 0;
	}
}


static int
rxring_deinit_some(int cnt) 
{
	int r = 0;
#if (MAX_NICS>1)
	while (cnt) {
		--cnt;
		if (munmap((void*)rx_rings[cnt].base, ((char*)rx_rings[cnt].limit - (char*)rx_rings[cnt].base) )!=0) {
			perror("munmap()");
			r = -1;
		}
	}
#else
	if (munmap((void*)rx_selected.base, ((char*)rx_selected.limit - (char*)rx_selected.base) )!=0) {
		perror("munmap()");
		r = -1;
	}
#endif
	return r;
}
////////////
//public interface

int 
rxring_init() 
{
	struct tpacket_req tp;
	int frames, reserve;
	int i;

	for (i = 0; i<niccnt; ++i)
	{
#if defined(PACKET_RX_RING_RESERVE) && (PACKET_RX_RING_RESERVE!=-1) && defined(PACKET_RESERVE)
		reserve = PACKET_RX_RING_RESERVE;
		if (setsockopt(nics[i].sfd, SOL_PACKET, PACKET_RESERVE, (void*) &reserve, sizeof(reserve))!=0) {
			perror("setsockopt(PACKET_RESERVE)");
			reserve = 0;
		}
#else
		reserve = 0;
#endif
		memset(&rx_selected, 0, sizeof(rx_selected));
		rx_selected.frame_size = getmtu(nics[i].sfd, nics[i].name) + reserve +
					TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + 
					TPACKET_ALIGN(sizeof(struct sockaddr_ll)) + 32; 
		rx_selected.frame_size = PAGE_ALIGN(rx_selected.frame_size);
		while (!is_power_of_2(rx_selected.frame_size))rx_selected.frame_size+= PAGE_ALIGN(1);
		frames = Z_ALIGN(bufcnt, 8);
		//sometimes system fails to allocate neccessary ring space
		//try to allocate smaller one in such case
		printf("RX RING on %s: ", nics[i].name);
		for (tp.tp_block_nr = 1;;) {			
			if ((frames%tp.tp_block_nr)==0) {
				tp.tp_block_size = (frames/tp.tp_block_nr) * rx_selected.frame_size;
				tp.tp_frame_size = rx_selected.frame_size;
				tp.tp_frame_nr = frames;
				if (setsockopt(nics[i].sfd, SOL_PACKET, PACKET_RX_RING, (void*)&tp, sizeof(tp))==0) 
					break;
			}

			if (frames<++tp.tp_block_nr) {
				if (frames<=4) {					
					perror("setsockopt(PACKET_RX_RING)"); 
					rxring_deinit_some(i) ;
					return -1;
				}
				frames-= 4;
				tp.tp_block_nr = 1;
			}
		}

		rx_selected.base = (volatile struct tpacket_hdr *)mmap(0, 
			tp.tp_block_size * tp.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, nics[i].sfd, 0);
		if (!rx_selected.base) {
			perror("mmap() ring");
			rxring_deinit_some(i) ;
			return -1;
		}
		rx_selected.limit = (volatile struct tpacket_hdr *)
			(((void *)rx_selected.base) + frames * rx_selected.frame_size);
		rx_selected.current = rx_selected.base;
		printf("%u frames * %u bytes per frame with reserve of %d, all in %u block(s)\n", 
				frames, rx_selected.frame_size, reserve, tp.tp_block_nr);
#if (MAX_NICS>1)
		rx_rings[i] = rx_selected;
#endif
	}

	return 0;
}

int 
rxring_deinit() 
{
	return rxring_deinit_some(niccnt);
}

void 
rxring_roll(uchar *buf) 
{
#if (MAX_NICS>1)
	rx_selected = rx_rings[curnic];
#endif

	for (;;) {
		if (tags_tracking!=TAGS_ANY) {
			if (roll_rx_ring_with_tags_tracking(buf)==0) break;
		}
		else {
			if (roll_rx_ring_no_tags_tracking(buf)==0) break;
		}
#ifdef KEEP_STATS
		printf("tags tracking switched to %d\n", tags_tracking);
#endif
	}
}

void
update_maxscnt() 
{
	int mtu = getmtu(nics[curnic].sfd, nics[curnic].name);
	if (rx_selected.frame_size) {//todo: re-map ring if mtu grown
		int rxring_mtu = rx_selected.frame_size - 
			TPACKET_ALIGN(sizeof(struct tpacket_hdr)) - TPACKET_ALIGN(sizeof(struct sockaddr_ll)) - 32;
		if (mtu>rxring_mtu) 
			mtu = rxring_mtu;
	}
	nics[curnic].maxscnt = sectors_per_packet_size(mtu);
}


#endif //SOCK_RXRING
