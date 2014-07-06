/*
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


/////////////////////////////////////////////////////////////////////////////////////////
///Simple buffering functionality. No deep predictions: just merge&flush and read-ahead.
///Using it greatly improved write performance on ARM-based NAS with 256 megs of RAM.
///Note that write buffering may be required when using direct write to file ( -d arg)
///together with RX ring receive, cause data in RX ring came at unaligned addresses
/////////////////////////////////////////////////////////////////////////////////////////


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
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include "dat.h"
#include "fns.h"
#ifdef USE_AIO
# include <libaio.h>

# if BUFFERS_COUNT<2 
#  error "Too few BUFFERS_COUNT to use with AIO"
# endif

# if !BUFFER_FULL_THRESHOLD
#  error "BUFFER_FULL_THRESHOLD must be defined when using AIO"
# endif

#endif

static int
getsec(uchar *place, vlong lba, int nsec)
{
	int n = pread(bfd, place, nsec * SECTOR_SIZE, lba * SECTOR_SIZE);
	if (AOE_UNLIKELY(n!=nsec * SECTOR_SIZE))
	{
		perror("getsec failed");
		printf("place=%p lba=%llu nsec=%d\n", place, lba, nsec);
	}
	return n;
}

static int
putsec(uchar *place, vlong lba, int nsec)
{
	int n = pwrite(bfd, place, nsec * SECTOR_SIZE, lba * SECTOR_SIZE);
	if (AOE_UNLIKELY(n!=nsec * SECTOR_SIZE))
	{
		perror("putsec failed");
		printf("place=%p lba=%llu nsec=%d\n", place, lba, nsec);
	}
	return n;
}


#if BUFFERS_COUNT

#if BUFFERS_COUNT>255
# error "Too big BUFFERS_COUNT"
#endif

#if !BUFFERED_SECTORS
# error "Too small BUFFERED_SECTORS"
#endif

#if BUFFER_FULL_THRESHOLD>=BUFFERED_SECTORS
# error "Too big BUFFER_FULL_THRESHOLD"
#endif

static unsigned long use_counter = 0;
static uchar wanna_after_party = 0, allocated_buffers = 0;

enum
{
	SBS_CLEAN = 0,
	SBS_DIRTY = 1,
	SBS_FLUSHING = 2,
	SBS_READING = 3
};

static struct SectorBuffer
{
#ifdef USE_AIO
	struct iocb 	aio;//must be at beginning
#endif
    vlong			lba;
    uchar			*data;
    unsigned long	used;
    unsigned long	nsec;
	uchar			state;//SBS_*
} sbs[BUFFERS_COUNT];

#ifdef USE_AIO
static struct
{
	io_context_t	ctx;
	uchar 			pending;
} aio;
#endif


static inline char 
are_regions_overlap(vlong lba1, int nsec1, vlong lba2, int nsec2) 
{	
	return (lba1<(lba2+nsec2) && lba2<(lba1+nsec1));
}


#ifdef DBG_VALIDATE

static void 
dbg_validate_buffers(char *info)
{
	uchar i, j;
	for (i = 0; i<(BUFFERS_COUNT-1); ++i) {
		if (sbs[i].nsec) {
		for (j = i+1; j<BUFFERS_COUNT; ++j) {
			if (sbs[j].nsec)
			{
				if (are_regions_overlap(sbs[i].lba, sbs[i].nsec, sbs[j].lba, sbs[j].nsec))
				{
					printf("overlap: %s [%u vs %u]\n", info, i, j);
					assert(0);
				}
			}	
		} }
	}
}

#else
# define dbg_validate_buffers(info) ;
#endif

#ifdef KEEP_STATS
static struct 
{
	vlong  wr_preempt;
	vlong  wr_collide;
	vlong  wr_nice;
	vlong  wr_new;

	vlong  rd_nice;
	vlong  rd_preempt;
	vlong  rd_miss;
	vlong  rd_collide;

	vlong  aio;
	vlong  after_party;
} sbst;

# define TOTAL_WRITES (sbst.wr_nice + sbst.wr_new + sbst.wr_preempt)	//wr_collide is currently redundant
# define TOTAL_READS (sbst.rd_nice + sbst.rd_miss + sbst.rd_preempt)

# define INIT_STATS do {memset(&sbst, 0, sizeof(sbst)); }while(0)

# define INCREMENT_STAT(x) do {++sbst.x; }while(0)

# define STATS_ON_BEGIN_BUFFERING do {printf("BFDIO: begin buffering\n"); }while (0)

# define STATS_ON_IDLE do {printf("BFDIO: idle, buffers: %u, wr: %llu, rd: %llu\n", allocated_buffers, TOTAL_WRITES, TOTAL_READS); }while(0)

# define STATS_ON_STOP_BUFFERING(frd)	do { \
				printf("BFDIO: free'd %u buffer(s) (%u remain)\nwr_nice=%llu wr_new=%llu wr_preempt=%llu wr_collide=%llu rd_nice=%llu rd_preempt=%llu rd_miss=%llu rd_collide=%llu after_party=%llu aio=%llu\n", \
				frd, allocated_buffers, sbst.wr_nice, sbst.wr_new, sbst.wr_preempt, sbst.wr_collide, sbst.rd_nice, sbst.rd_preempt, sbst.rd_miss, sbst.rd_collide, sbst.after_party, sbst.aio); }while(0)


#else
# define INIT_STATS do {;}while(0)
# define INCREMENT_STAT(x) do {;}while(0)
# define STATS_ON_BEGIN_BUFFERING do {;}while(0)
# define STATS_ON_IDLE do {;}while(0)
# define STATS_ON_STOP_BUFFERING(frd) do {;}while(0)
#endif

#ifdef USE_AIO

static void 
process_completed_aio_events(const struct io_event *ioe, int n)
{
	int i;
	for (i = 0; i<n; ++i) {
		struct SectorBuffer *sb = (struct SectorBuffer *)(void *)ioe[i].obj;
		if (AOE_UNLIKELY(ioe[i].res<0)) {
#if defined(KEEP_STATS) || defined(DBG_VALIDATE)
			fprintf(stderr, "AIO error: state=%u res=%d res2=%d\n", 
							(unsigned int)sb->state, (int)ioe[i].res, (int)ioe[i].res2);
#endif
			switch (sb->state) {
				case SBS_READING://read failed - reset to empty
					sb->lba = 0;
					sb->nsec = 0;
					sb->state = SBS_CLEAN;
					break;
				case SBS_FLUSHING://flush failed - reset to dirty
					sb->state = SBS_DIRTY;
					break;
#ifdef DBG_VALIDATE
				default:
					printf("AIO failed for non-aio!: %u", sb->state);
					assert(0);
#endif
			}
		}
		else {//all OK - buffer is clean now
#ifdef DBG_VALIDATE
			assert(sb->state==SBS_READING || sb->state==SBS_FLUSHING);
			assert ((sb->nsec*SECTOR_SIZE)==ioe[i].res);
#endif
			sb->state = SBS_CLEAN;
			INCREMENT_STAT(aio);
		}
	}
	aio.pending-= n;
}


static void 
process_aio_completion(struct timespec *ts)
{
	struct io_event ioe[BUFFERS_COUNT];
	int n = io_getevents(aio.ctx, 1, BUFFERS_COUNT, &ioe[0], ts);
	if (n>0)  process_completed_aio_events(&ioe[0], n);
}

static inline void 
wait_aio_complete_all()
{
	while (aio.pending!=0) {
		struct io_event ioe[BUFFERS_COUNT];
		int n = io_getevents(aio.ctx, aio.pending, BUFFERS_COUNT, &ioe[0], 0);
		if (n>0)  process_completed_aio_events(&ioe[0], n);
	}
}

static inline void 
wait_aio_complete_sb(struct SectorBuffer *sb, uchar async_state)
{
	while (sb->state==async_state) {
		struct io_event ioe[BUFFERS_COUNT];
		int n = io_getevents(aio.ctx, 1, BUFFERS_COUNT, &ioe[0], 0);
		if (n>0)  process_completed_aio_events(&ioe[0], n);
	}
}

static inline void 
check_aio_complete()
{
	if (aio.pending!=0)  {
		struct timespec ts = {0, 0};
		process_aio_completion(&ts);
	}
}

static inline int
read_sb_async(struct SectorBuffer *sb)
{
	struct iocb *jobs[] = {&sb->aio};
	sb->state = SBS_READING;
	io_prep_pread(&sb->aio, bfd, sb->data, sb->nsec*SECTOR_SIZE, sb->lba*SECTOR_SIZE);
	++aio.pending;
	if (AOE_UNLIKELY(io_submit(aio.ctx, 1, &jobs[0])!=1)) {
		perror("read_sb_async - io_submit");
		sb->lba = 0;
		sb->nsec = 0;
		sb->state = SBS_CLEAN;
		--aio.pending;
		return -1;
	}
	return 0;
}

static inline int 
flush_sb_async(struct SectorBuffer *sb)
{
	struct iocb *jobs[] = {&sb->aio};
	assert(sb->state!=SBS_FLUSHING && sb->state!=SBS_READING);
	sb->state = SBS_FLUSHING;
	io_prep_pwrite(&sb->aio, bfd, sb->data, sb->nsec*SECTOR_SIZE, sb->lba*SECTOR_SIZE);
	++aio.pending;
	if (AOE_UNLIKELY(io_submit(aio.ctx, 1, &jobs[0])!=1)) {
		perror("flush_sb_async - io_submit");
		sb->state = SBS_DIRTY;
		--aio.pending;
		return -1;
	}

	return 0;
}


#endif

static int 
flush_sb_sync(struct SectorBuffer *sb)
{
#ifdef USE_AIO	//if there pending AIO - enqueue this operation as AIO and wait for its completion 
	if (aio.pending!=0 && flush_sb_async(sb)==0) { 
		wait_aio_complete_sb(sb, SBS_FLUSHING);
		if (sb->state == SBS_CLEAN)
			return 0;
	}
#endif

	if (AOE_UNLIKELY(putsec(&sb->data[0], sb->lba, sb->nsec)!=(sb->nsec*SECTOR_SIZE)))
		return -1;
	sb->state = SBS_CLEAN;
	return 0;
}

static int 
read_sb_sync(struct SectorBuffer *sb)
{
#ifdef USE_AIO	//if there pending AIO - enqueue this operation as AIO and wait for its completion 
	if (aio.pending!=0 && read_sb_async(sb)==0) { 
		wait_aio_complete_sb(sb, SBS_READING);
		if (sb->state == SBS_CLEAN)
			return sb->nsec * SECTOR_SIZE;
	}
#endif

	return getsec(&sb->data[0], sb->lba, sb->nsec);
}


void 
bfd_flush() 
{
	uchar i;
#ifdef USE_AIO
	wait_aio_complete_all();
#endif
	for (i = 0; i<BUFFERS_COUNT; ++i) {
		if (sbs[i].state==SBS_DIRTY)
			flush_sb_sync(&sbs[i]);
	}
}

int 
bfd_idle_begin() 
{
	uchar i;
#ifdef USE_AIO
	check_aio_complete();
#endif
	if (wanna_after_party) {
		uchar flush_oldest = 1, did_io = 0;
		struct SectorBuffer *oldest_dirty_sb = 0;
		wanna_after_party = 0;
		for (i = 0; i<BUFFERS_COUNT; ++i) {
			struct SectorBuffer *sbc = &sbs[i];
			if (sbc->state==SBS_DIRTY) {
#if BUFFER_FULL_THRESHOLD
				if (sbc->nsec>=BUFFER_FULL_THRESHOLD) {
					if (flush_sb_sync(sbc)==0) {
						INCREMENT_STAT(after_party);
						flush_oldest = 0;
						did_io = 1;
					}
				}
				else
#endif
				{
					if (!oldest_dirty_sb || oldest_dirty_sb->used>sbc->used)
						oldest_dirty_sb = sbc;
				}
			}
			else
				flush_oldest = 0;
		}
		if (flush_oldest && oldest_dirty_sb && flush_sb_sync(oldest_dirty_sb)==0) {
			INCREMENT_STAT(after_party);
			did_io = 1;
		}
		return did_io ? 0 : (oldest_dirty_sb ? 1 : (allocated_buffers ? 10 : -1) );
	}

	for (i = 0; i< BUFFERS_COUNT; ++i) {
		if (sbs[i].state!=SBS_CLEAN)
			return 1;//no need to loop more
	}
	return allocated_buffers ? 10: -1;
}

void 
bfd_idle_elapsed(int t)
{
	unsigned char frd = 0, i;
#ifdef USE_AIO
	wait_aio_complete_all();
#endif
	for (i = 0; i<BUFFERS_COUNT; ++i) {
		struct SectorBuffer *sbc = &sbs[i];
		if (sbc->data) {
			if (sbc->nsec && sbc->state==SBS_DIRTY) {
				if (flush_sb_sync(sbc)!=0)
					continue;
			}

			if (t>=10) {
				--allocated_buffers;
				++frd;
				free(sbc->data - page_size);
				sbc->data = 0;
				sbc->lba = 0;
				sbc->nsec = 0;
			}
		}
	}


	if (frd) {
		STATS_ON_STOP_BUFFERING(frd);
		malloc_trim(0);
	}
	else {
		STATS_ON_IDLE;
	}
}

uchar ensure_allocated_data(struct SectorBuffer *sb)
{
	if (sb->data)
		return 1;

#ifdef SUPPORT_CRC //need some space at the end for CRC
	sb->data = valloc(2*page_size + BUFFERED_SECTORS*SECTOR_SIZE);
#else
	sb->data = valloc(page_size + BUFFERED_SECTORS*SECTOR_SIZE);
#endif

	if (!sb->data)
		return 0;
	sb->data+= page_size;
	if (1==++allocated_buffers)
		STATS_ON_BEGIN_BUFFERING;

	return 1;
}


uchar ensure_sb_clean(struct SectorBuffer *sb)
{
	switch (sb->state) {
#ifdef USE_AIO
		case SBS_FLUSHING:
			do {
				process_aio_completion(0);
			} while (sb->state==SBS_FLUSHING);
			//now it can be clean or dirty
			if (AOE_LIKELY(sb->state==SBS_CLEAN))
				return 1;//return if clean
			//otherwise fall through to dirty case
#endif
		case SBS_DIRTY:
			return (flush_sb_sync(sb)==0) ? 1 : 0;

#ifdef USE_AIO
		case SBS_READING:
			do {
				process_aio_completion(0);
			} while (sb->state==SBS_READING) ;
#endif

		default:
			return 1;
	}
}

int 
bfd_putsec(uchar *place, vlong lba, int nsec)
{
	struct SectorBuffer *sb = 0;
	uchar nice = 0, i, may_request_after_party = 1;

#ifdef USE_AIO //need some buffers to be free
	struct SectorBuffer *sb_oldest_dirty = 0;
	uchar dirties = 0;
	while (aio.pending==BUFFERS_COUNT)
		process_aio_completion(0);
#endif
	dbg_validate_buffers("put - before");

	for (i = 0; i<BUFFERS_COUNT; ++i) {
		struct SectorBuffer *sbc = &sbs[i];
		if (sbc->nsec) {
			if (!nice && (sbc->state==SBS_DIRTY || (sbc->state==SBS_CLEAN && sbc->nsec<=(nsec/2))) &&
				sbc->lba<=lba && (sbc->lba+sbc->nsec)>=lba && (lba + (vlong)nsec - sbc->lba)<=BUFFERED_SECTORS) {
				sb = sbc;				
				nice = 1;
			}
			else if (are_regions_overlap(lba, nsec, sbc->lba, sbc->nsec)) {				
				INCREMENT_STAT(wr_collide);
				if (!ensure_sb_clean(sbc))
					return -1;

				sbc->lba = 0;
				sbc->nsec = 0;
				sbc->used = 0;
				if (nice || (sb && !sb->nsec) )
					may_request_after_party = 0;
				else
					sb = sbc;
			}
			else if (sbc->state!=SBS_FLUSHING && sbc->state!=SBS_READING) {
				if (!sb || (!nice && sbc->used<sb->used)) {		
					sb = sbc;
#ifdef USE_AIO
					if (sbc->state==SBS_DIRTY) {
						++dirties;
						if (!sb_oldest_dirty)
							sb_oldest_dirty = sbc;
					}
#endif
				}
#ifdef USE_AIO
				else if (sbc->state==SBS_DIRTY) {
					++dirties;
					if (!sb_oldest_dirty || sb_oldest_dirty->used>sbc->used )
						sb_oldest_dirty = sbc;
				}
#endif
			}
		}
		else if (!sb) {
			sb = sbc;
		}
		else if (!nice && sbc->used<sb->used) {
			if (sb->nsec)
				sb = sbc;
			else
				may_request_after_party = 0;
		}
		else
			may_request_after_party = 0;		
	}
#ifdef USE_AIO
	if (dirties>(BUFFERS_COUNT/2) && sb_oldest_dirty!=sb)
		flush_sb_async(sb_oldest_dirty);		
#endif

	if (sb) {
		if (!nice) {
			if (sb->nsec) {
				if (!ensure_sb_clean(sb))
					sb = 0;
			}
			else
				INCREMENT_STAT(wr_new);

			if (sb) {
				sb->nsec = 0;
				if (ensure_allocated_data(sb))
					sb->lba = lba;
				else
					sb  = 0;
			}
		}
		else
			INCREMENT_STAT(wr_nice);

		if (sb) {
			vlong til_nsec =  lba + (vlong)nsec - sb->lba;
			nsec*= SECTOR_SIZE;
			memcpy(&sb->data[(lba - sb->lba)*SECTOR_SIZE], place, nsec);
			sb->used = ++use_counter;
			sb->state = SBS_DIRTY;
			if (sb->nsec<til_nsec)  {
				sb->nsec = til_nsec;
#if BUFFER_FULL_THRESHOLD
				if (til_nsec>=BUFFER_FULL_THRESHOLD) {
#ifdef USE_AIO
					i = 0;
					if (nice && bfd_blocks_per_sector!=1) {
						vlong lba_end_aligned = bfd_blocks_per_sector * ((sb->lba + til_nsec)/bfd_blocks_per_sector);
						sb->nsec = (int) (lba_end_aligned - sb->lba);
						if (sb->nsec!=til_nsec) {
							if (flush_sb_async(sb)!=-1) {
								i = 1;
								til_nsec-= sb->nsec;
								if (bfd_putsec(&sb->data[sb->nsec * SECTOR_SIZE], lba_end_aligned, til_nsec)!= (til_nsec*SECTOR_SIZE)) {
									nsec-= (til_nsec*SECTOR_SIZE);
								}
							} else
								sb->nsec = til_nsec;
						}
					}					
					if (!i && flush_sb_async(sb)==-1)
#endif
					{
						if (may_request_after_party)
							wanna_after_party = 1;
					}
				}
#endif
			}
			dbg_validate_buffers("put - after");

			return nsec;
		}
	}

	printf("unbuffered putsec place=%p\n", place);
#ifdef USE_AIO
	wait_aio_complete_all();
#endif
	return putsec(place, lba, nsec);
}

#if READ_TRACKS

# if READ_TRACKS>0xff
#  error "Too big READ_TRACKS"
# endif

struct ReadTrack
{
	vlong lba;
	unsigned long used;
	uchar weight;//read-ahead necessity magic estimation value
} rts[READ_TRACKS];

struct ReadTrack *ReferenceReadTrack(vlong lba)
{
	uchar i;
	struct ReadTrack *rt = 0, *oldest_rt = 0;

	for (i = 0; i<READ_TRACKS; ++i) {
		struct ReadTrack *rtc = &rts[i];

		if (lba>=rtc->lba && lba<=(rtc->lba + BUFFERED_SECTORS)) {
			if (!rt || rt->lba>rtc->lba)
				rt = rtc;
		}
		else {
			if (rtc->weight)
				rtc->weight--;

			if (!rt && (!oldest_rt || oldest_rt->used>rtc->used))
				oldest_rt = rtc;
		}
	}
	if (!rt)  {
		rt = oldest_rt;
		rt->weight = 0;
	}//few magic values
	else if (rt->weight<0x40)
		rt->weight+= 3;		
	else if (rt->weight<0x80)
		rt->weight+= 2;		
	else if (rt->weight<0xff)
		rt->weight++;

	rt->lba = lba;
	rt->used = ++use_counter;
	return rt;
}
#endif

int
bfd_getsec(struct Ata *preinit_ata_responce, vlong lba, int nsec, uchar no_callback)
{	
	uchar i;
	int out = 0;
	uchar *place = (uchar *)(preinit_ata_responce + 1);
#if READ_TRACKS
	struct SectorBuffer *sb = 0;
	vlong right_edge = size;
	struct ReadTrack *rt = ReferenceReadTrack(lba);
#endif
	dbg_validate_buffers("get - before");
	for (i = 0; i<BUFFERS_COUNT; ++i) {
		struct SectorBuffer *sbc = &sbs[i];
		if (sbc->nsec && are_regions_overlap(lba, nsec, sbc->lba, sbc->nsec)) {
#ifdef USE_AIO
			while (sbc->state==SBS_READING || sbc->state==SBS_FLUSHING)
				process_aio_completion(0);
#endif

			if (lba>=sbc->lba && lba<(sbc->lba+sbc->nsec)) {
				unsigned int lba_delta = (lba - sbc->lba);
				int n = sbc->nsec - lba_delta;
				if (n>nsec) n = nsec;
				nsec-= n;
				lba+= n;
				n*= SECTOR_SIZE;
				lba_delta*= SECTOR_SIZE;
				if (out || nsec || no_callback) {
					memcpy(place, &sbc->data[lba_delta], n);
					out+= n;
					place+= n;
				} else {
					if (lba_delta)
						rd_callback_preserve_header_space((Ata*)(&sbc->data[lba_delta]) - 1, n);
					else
						rd_callback((Ata*)(&sbc->data[0]) - 1, n);
				}

				sbc->used = ++use_counter;
				if (!nsec) {
					if (out) {
						if (!no_callback)
							rd_callback_with_preinit_buffer(out);
					} else
						out+= n;

					INCREMENT_STAT(rd_nice);

#if READ_TRACKS && BUFFER_FULL_THRESHOLD && defined(USE_AIO)
					if (rt->weight>=15 && (n + lba_delta)>=(BUFFER_FULL_THRESHOLD*SECTOR_SIZE)) {
						vlong lba_ahead = sbc->lba + sbc->nsec + BUFFERED_SECTORS;//one step futher
						uchar already_processed = i;
						if (bfd_blocks_per_sector!=1) {
							lba_ahead/= bfd_blocks_per_sector;
							lba_ahead*= bfd_blocks_per_sector;
						}
						for (i = 0;;++i) {
							if (i==BUFFERS_COUNT) {
								if (lba_ahead<right_edge && sb && 
									ensure_sb_clean(sb) && 
									ensure_allocated_data(sb)) {
									sb->lba = lba_ahead;
									sb->nsec = ((size - lba_ahead) > BUFFERED_SECTORS) 
													? BUFFERED_SECTORS : (int)(size - lba_ahead);
									sb->used = ++use_counter;
									read_sb_async(sb);
								}
								break;
							}

							sbc = &sbs[i];
							if (sbc->nsec && 
								are_regions_overlap(lba_ahead, BUFFERED_SECTORS, sbc->lba, sbc->nsec)) {
								break;
							}
							if ((i>already_processed) && (!sb || sbc->used<sb->used))
								sb = sbc;
						}
					}
#endif
					dbg_validate_buffers("get - after1");
					return out;
				}
			}
			else if ( lba<sbc->lba && (lba+nsec)>sbc->lba && (lba+nsec)<=(sbc->lba+sbc->nsec)) {
				int n = nsec - (sbc->lba - lba);
				nsec-= n;
				n*= SECTOR_SIZE;
				out+= n;
				memcpy(&place[(sbc->lba - lba)*SECTOR_SIZE], &sbc->data[0], n);
				sbc->used = ++use_counter;
				right_edge = 0;//avoid intersecting buffering 
			}
			else {
				if (!ensure_sb_clean(sbc)) {
					if (!no_callback)
						rd_callback_with_preinit_buffer(-1);
					return -1;
				}


				sbc->lba = 0;
				sbc->nsec = 0;
				sbc->used = 0;
				INCREMENT_STAT(rd_collide);
#if READ_TRACKS
				sb = sbc;
#endif
			}
		}
#if READ_TRACKS
		else  {
			if (!sb || sbc->used<sb->used)
				sb = sbc;
			if (sbc->lba>lba && right_edge>sbc->lba ) // && sbc->nsec)
				right_edge = sbc->lba;
		}
#endif
	}
	
#if READ_TRACKS	 
	if (sb && rt->weight>=10 && right_edge>(lba+nsec) //another magic value to complete potion
		&& ensure_sb_clean(sb) && ensure_allocated_data(sb)) {
		int  nret;
		sb->lba = lba;				
		sb->nsec = ( (lba+BUFFERED_SECTORS)<=right_edge) ? BUFFERED_SECTORS : right_edge - lba;
		nret = read_sb_sync(sb);
		nsec*= SECTOR_SIZE;
		if (nret>=nsec) {
			INCREMENT_STAT(rd_preempt);
			dbg_validate_buffers("get - after2");
			sb->nsec = nret/SECTOR_SIZE;
			if (!out && !no_callback) {
				rd_callback(((Ata *)&sb->data[0]) - 1, nsec);
				return nsec;
			}

			memcpy(place, sb->data, nsec);
			out+= nsec;
			if (!no_callback)
				rd_callback_with_preinit_buffer(out);
			return out;
		}

		sb->lba = 0;
		sb->nsec = 0;
		nsec/= SECTOR_SIZE;
	}
#endif

	INCREMENT_STAT(rd_miss);
	nsec = getsec(place, lba, nsec);	
	dbg_validate_buffers("get - after3");	
	if (nsec>0) out+= nsec;
	if (!no_callback)
		rd_callback_with_preinit_buffer(out);
	return out;
}

void 
bfd_init() {
	memset(&sbs, 0, sizeof(sbs));
	INIT_STATS;
#if READ_TRACKS
	memset(&rts[0], 0, sizeof(rts));
#endif
#ifdef USE_AIO
	memset(&aio, 0, sizeof(aio));
	io_queue_init(BUFFERS_COUNT, &aio.ctx);
#endif
}



#else //no BUFFERS_COUNT - no buffering at all

#if defined(O_DIRECT) && defined(SOCK_RXRING)
# warning "Direct IO may work faulty when write buffering disabled and SOCK_RXRING enabled"
#endif

void bfd_init() {};
int bfd_idle_begin() {return -1; };
void bfd_idle_elapsed(int t) {}; 
int bfd_putsec(uchar *place, vlong lba, int nsec) { return putsec(place, lba, nsec); }
int
bfd_getsec(struct Ata *preinit_ata_responce, vlong lba, int nsec, uchar no_callback) 
{ 
	nsec = getsec((uchar *)(preinit_ata_responce + 1), lba, nsec);
	if (!no_callback)
		rd_callback_with_preinit_buffer(nsec);
	return nsec;
}
void bfd_flush() {} ;

#endif


