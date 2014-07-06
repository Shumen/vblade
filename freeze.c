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
#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <malloc.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include "dat.h"
#include "fns.h"


uchar freeze_stopping = 0;
uchar freeze_active = 0;

#ifdef SHADOW_FREEZE


//size of per-bitmap bitmap array in bytes
//every byte represents 8 sectors states 
//so size of segment eq 8*SEGMENT_BITMAP_BYTES*SECTOR_SIZE
#define SEGMENT_BITMAP_BYTES		(0xfe0)	//this gives almost 16megs segment size


//each single bit of bitmap represn's single sector state
#define SECTORS_PER_SEGMENT			(SEGMENT_BITMAP_BYTES*8)


//count of per-segment bitmaps kept in memory simultaneously, each takes (SEGMENT_BITMAP_BYTES) + 16 bytes
#define SEGMENTS_IN_MEMORY        	(0x100) 	

//how many sectors flushed at one read/write transactions note 
//that buffer of size SECTOR_SIZE*MAX_FLUSH_SECTORS is kept on stack
#define MAX_FLUSH_SECTORS			(0x80)

#define DIV_CEIL(X, Y)				(((X)%(Y)) ? (X)/(Y)+1 : (X)/(Y))

#define FBI_ANY(segment_index)       (2*(segment_index))
#define FBI_ALL(segment_index)       (1 + 2*(segment_index))

struct FreezeSegmentBitmap
{
	unsigned int dirtycnt;
	uchar data[SEGMENT_BITMAP_BYTES];
};

struct FreezeSegment
{
	unsigned int index;
	unsigned int usecnt;
	unsigned int dirtycnt_on_read;
};

struct FreezeStructs
{
	struct FreezeSegment segments[SEGMENTS_IN_MEMORY];
	struct FreezeSegmentBitmap bitmaps[SEGMENTS_IN_MEMORY];
	uchar fast_bitmap[1];
} *freeze_structs = NULL;

static int freeze_last_usecnt = 0;
static int freeze_fd = -1;
static unsigned long long freeze_data_offset = 0;

static inline void 
bitmap_set(uchar *bitmap, unsigned int index)  
{ 
	bitmap[index/8]|= ((uchar)1<<(index%8)); 
}
static inline void 
bitmap_reset(uchar *bitmap, unsigned int index)  
{ 
	bitmap[index/8]&= ~((uchar)1<<(index%8)); 
}
static inline uchar 
bitmap_get(uchar *bitmap, unsigned int index)
{ 
	return ((bitmap[index/8] & (1<<(index%8)))!=0); 
}

static inline uchar 
bitmap_get_set(uchar *bitmap, unsigned int index) 
{
	const uchar oct = bitmap[index/8], 
		bm = ((uchar)1<<(index%8));
	if (oct&bm) 
		return 1;

	bitmap[index/8] = oct | bm;
	return 0;
}


static inline uchar 
bitmap_get_reset(uchar *bitmap, unsigned int index) 
{
	const uchar oct = bitmap[index/8], 
		bm = ((uchar)1<<(index%8));
	if ((oct&bm)==0)
		return 0;

	bitmap[index/8] = oct & (~bm);
	return 1;
}

static inline uchar fastbitmap_get(unsigned int index) { return bitmap_get(freeze_structs->fast_bitmap, index); }
static inline uchar fastbitmap_get_reset(unsigned int index) { return bitmap_get_reset(freeze_structs->fast_bitmap, index); }
static inline void fastbitmap_set(unsigned int index) { bitmap_set(freeze_structs->fast_bitmap, index); }
static inline void fastbitmap_reset(unsigned int index) { bitmap_reset(freeze_structs->fast_bitmap, index); }



static void 
load_stgbitmap_seg(struct FreezeSegment *seg)
{
	struct FreezeSegmentBitmap *bitmap = 
		&freeze_structs->bitmaps[seg - &freeze_structs->segments[0]];
	ssize_t nret = pread(freeze_fd, bitmap, 
		sizeof(*bitmap), seg->index * sizeof(*bitmap));
	if (nret<sizeof(*bitmap))
		memset(bitmap, 0, sizeof(*bitmap));
	seg->dirtycnt_on_read = bitmap->dirtycnt;
}

static char 
save_stgbitmap_seg(struct FreezeSegment *seg)
{
	struct FreezeSegmentBitmap *bitmap = 
		&freeze_structs->bitmaps[seg - &freeze_structs->segments[0]];
	if (pwrite(freeze_fd, bitmap, 
		sizeof(*bitmap), seg->index * sizeof(*bitmap))!=sizeof(*bitmap)) {
		return 0;
	}
	seg->dirtycnt_on_read = bitmap->dirtycnt;
	return 1;
}

static struct FreezeSegment * 
lookup_stgbitmap_seg(unsigned int index, struct FreezeSegmentBitmap **bitmap)
{
	struct FreezeSegment *seg = &freeze_structs->segments[0], 
		*end = &freeze_structs->segments[SEGMENTS_IN_MEMORY], 
		*oldest = &freeze_structs->segments[0];
	if (seg->index==index) {
		seg->usecnt = ++freeze_last_usecnt;
		*bitmap = &freeze_structs->bitmaps[0];
		return seg;
	}

	for (;;) {	
		++seg;
		if (seg == end) {
			*bitmap = &freeze_structs->bitmaps[oldest - &freeze_structs->segments[0]];
			if (oldest->dirtycnt_on_read != (*bitmap)->dirtycnt) {
				if (!save_stgbitmap_seg(oldest)) {
					printf("lookup_stgbitmap_seg - failed save oldest\n");
					*bitmap = NULL;
					return NULL;
				}
			}
			oldest->index = index;
			load_stgbitmap_seg(oldest);
			oldest->usecnt = ++freeze_last_usecnt;
			return oldest;
		}
		
		if (seg->index==index) {
			seg->usecnt = ++freeze_last_usecnt;
			*bitmap = &freeze_structs->bitmaps[seg - &freeze_structs->segments[0]];
			return seg;
		}

		if (seg->usecnt<oldest->usecnt)
			oldest = seg;
	}
}

//////////////


void 
freeze_start()
{	
	size_t fastbitmap_bytes;
	assert(!freeze_structs);
    freeze_active = 1;
	if (!freeeze_path)
		return;

	freeze_data_offset = DIV_CEIL(size, SECTORS_PER_SEGMENT) * sizeof(struct FreezeSegmentBitmap);
	freeze_data_offset = Z_ALIGN(freeze_data_offset, 0x10000);

	fastbitmap_bytes = (size_t)DIV_CEIL(size, 4 * SECTORS_PER_SEGMENT);	
	freeze_structs = (struct FreezeStructs*)
			malloc(sizeof(struct FreezeStructs) + fastbitmap_bytes);
	if (freeze_structs) {
		memset(freeze_structs, 0, sizeof(struct FreezeStructs) + fastbitmap_bytes);
	    freeze_fd = open(freeeze_path, O_CREAT|O_TRUNC|O_RDWR, S_IREAD|S_IWRITE);
	    if (freeze_fd==-1) {
			fprintf(stderr, "freeze_start: FAILED to create '%s' errno=%u\n", freeeze_path, errno);
		} else if (flock(freeze_fd, LOCK_EX|LOCK_NB)<0) {
			fprintf(stderr, "freeze_start: FAILED to lock '%s' errno=%u\n", freeeze_path, errno);
			close(freeze_fd);
			freeze_fd = -1;
		}
	    if (freeze_fd!=-1) {
			printf("freeze_start: OK, used RAM: 0x%x + 0x%x, freeze_data_offset=0x%llx\n", 
					sizeof(struct FreezeStructs), fastbitmap_bytes, freeze_data_offset);
			freeze_last_usecnt = 0;
			ftruncate(freeze_fd, freeze_data_offset + size*SECTOR_SIZE);
		} else {
			free(freeze_structs);
			freeze_structs = 0;
		}
	} else {
		fprintf(stderr, "freeze_start: FAILED allocate: 0x%x + 0x%x, freeze_data_offset=0x%llx\n", 
				sizeof(struct FreezeStructs), fastbitmap_bytes, freeze_data_offset);
	}
}

static inline void 
freeze_decrement_seg_dirtycnt(unsigned int segment_index, struct FreezeSegmentBitmap *bitmap)
{
	const unsigned int dirtycnt = --(bitmap->dirtycnt);
	if (dirtycnt == (SECTORS_PER_SEGMENT-1))
		fastbitmap_reset(FBI_ALL(segment_index));
	if (dirtycnt == 0)
		fastbitmap_reset(FBI_ANY(segment_index));
}

static inline void 
freeze_increment_seg_dirtycnt(unsigned int segment_index, struct FreezeSegmentBitmap *bitmap)
{
	const unsigned int dirtycnt = ++(bitmap->dirtycnt);				
	if (dirtycnt == SECTORS_PER_SEGMENT)
		fastbitmap_set(FBI_ALL(segment_index));
	if (dirtycnt == 1)
		fastbitmap_set(FBI_ANY(segment_index));
}

static char 
sstd_flush_seg_portion_io(struct FreezeSegment *seg, 
							struct FreezeSegmentBitmap *bitmap, 
							unsigned int index_start, 
							unsigned int index_end)
{
	uchar buffer[MAX_FLUSH_SECTORS*SECTOR_SIZE];
	unsigned int nsec = (index_end - index_start);
	unsigned long long lba = seg->index;
	lba*= SECTORS_PER_SEGMENT;
	lba+= index_start;
	
	if (pread(freeze_fd, buffer, nsec * SECTOR_SIZE, lba * SECTOR_SIZE + freeze_data_offset)!=nsec * SECTOR_SIZE)
		return 0;
	if (bfd_putsec(buffer, lba, nsec)!=nsec* SECTOR_SIZE)
		return 0;

	for (;index_start!=index_end;++index_start) {
		if (bitmap_get_reset(bitmap->data, index_start))
			freeze_decrement_seg_dirtycnt(index_start, bitmap);
	}
	return save_stgbitmap_seg(seg);
}			

static uchar 
sstd_flush_seg(unsigned int segment_index)
{
	struct FreezeSegmentBitmap *bitmap;
	struct FreezeSegment *seg = lookup_stgbitmap_seg(segment_index, &bitmap);
	unsigned int index = 0, index_start = -1;
	uchar all;
	if (!seg)
		return 0;
	
	all = fastbitmap_get_reset(FBI_ALL(segment_index));
	for (;;) {
		if (all || bitmap_get(bitmap->data, index)) {
			if (index_start==-1) {
				index_start = index;
			} else if ( (index-index_start)==MAX_FLUSH_SECTORS) {
				if (!sstd_flush_seg_portion_io(seg, bitmap, index_start, index))
					return 0;
				index_start = index;
			}
		}
		else if (index_start!=-1) {
			if (!sstd_flush_seg_portion_io(seg, bitmap, index_start, index))
				return 0;
			index_start = -1;
		}
		if (++index == SECTORS_PER_SEGMENT) {
			if (index_start!=-1) {
				if (!sstd_flush_seg_portion_io(seg, bitmap, index_start, index))
					return 0;
			}
			
			memset(bitmap->data, 0, sizeof(bitmap->data));
			bitmap->dirtycnt = 0;
			fastbitmap_reset(FBI_ANY(segment_index));
			return 1;
		}
	}
}

void 
freeze_flush_and_stop(unsigned int time_limit)
{
	if (!freeeze_path) {
		freeze_active = 0;
		return;
	}

	if (freeze_structs)  {
		time_t ts, ts_start = time(NULL);
		unsigned int segment_index;
		unsigned int total_segs = (unsigned int)DIV_CEIL(size, SECTORS_PER_SEGMENT);
		if (!freeze_stopping) {
			freeze_stopping = 1;
			printf("freeze_flush_and_stop: begin\n");
		}
		for (segment_index = 0; segment_index<total_segs; ++segment_index) {
			if (fastbitmap_get(FBI_ANY(segment_index))) {
				if (!sstd_flush_seg(segment_index))
					return;
				
				time(&ts);
				if (time_limit!=-1 && (ts<ts_start || ts>=(ts_start+time_limit)))
					return;
			}
		}

		free(freeze_structs);
		freeze_structs = NULL;
	}
	if (freeze_fd!=-1) {
		close(freeze_fd);
		freeze_fd = -1;
	}
	unlink(freeeze_path);
	if (freeze_stopping) {
		freeze_active = 0;
		freeze_stopping = 0;
		printf("freeze_flush_and_stop: end\n");
		malloc_trim(0);
	}
}

////////////////////////


#define DECLARE_INITIAL_IO_INDEXES(OFFSET, segment_index, INDEX) 	\
	unsigned int segment_index = (unsigned int) \
		( (OFFSET)/(unsigned long long)SECTORS_PER_SEGMENT); \
	unsigned int INDEX = (unsigned int)(unsigned long long) \
		( (OFFSET) - (unsigned long long)segment_index * SECTORS_PER_SEGMENT);


struct ReadRegion
{
	vlong offset;
	uchar *data;
};

#define READ_REGION_ACTIVE(RR, DATA, OFFSET) if (!RR.data) { \
					RR.data = (DATA); RR.offset = (OFFSET); \
					RR.offset*= SECTOR_SIZE; RR.offset+= freeze_data_offset; }

#define READ_REGION_NOT_ACTIVE(RR, DATA) if (RR.data) { \
	pread(freeze_fd, RR.data, (DATA) - RR.data, RR.offset); RR.data = 0; }


static char 
freeze_region_probably_has_non_dirty(unsigned int segment_index, unsigned int index, int nsec)
{	
	for (;;) {
		if (!fastbitmap_get(FBI_ALL(segment_index)))
			return 1;

		if (nsec<=(SECTORS_PER_SEGMENT - index))
			return 0;

		nsec-= (SECTORS_PER_SEGMENT - index);
		++segment_index;
		index = 0;
	}
}

void
freeze_getsec(struct Ata *preinit_ata_responce, vlong lba, int nsec)
{
	struct ReadRegion rr = {0, 0};	
	DECLARE_INITIAL_IO_INDEXES(lba, segment_index, index);
	int rv;
	uchar all;
	uchar *place;
	struct FreezeSegment *seg;
	struct FreezeSegmentBitmap *bitmap;

	if (!freeeze_path || !freeze_active) {
		bfd_getsec(preinit_ata_responce, lba, nsec, 0);
		return;
	}


	if (freeze_region_probably_has_non_dirty(segment_index, index, nsec)) {
		rv = bfd_getsec(preinit_ata_responce, lba, nsec, 1);
		if (rv<=0)
			return rd_callback_with_preinit_buffer(rv);

		nsec = DIV_CEIL(rv, SECTOR_SIZE);
	}
	else
		rv = nsec * SECTOR_SIZE;

	place = (uchar*)(preinit_ata_responce + 1);
	for (;;) {
		for (;;) {
			if (fastbitmap_get(FBI_ANY(segment_index))) break;
			READ_REGION_NOT_ACTIVE(rr, place);
			if (nsec<=(SECTORS_PER_SEGMENT - index))
				return rd_callback_with_preinit_buffer(rv);
			nsec-= (SECTORS_PER_SEGMENT - index);
			lba+= (SECTORS_PER_SEGMENT - index);
			place+= (SECTORS_PER_SEGMENT - index)*SECTOR_SIZE;
			++segment_index;
			index = 0;
		}		
		seg = lookup_stgbitmap_seg(segment_index, &bitmap);
		if (!seg)
			return rd_callback_with_preinit_buffer(-1);

		all = fastbitmap_get(FBI_ALL(segment_index));
		for (;;) {
			if (all || bitmap_get(bitmap->data, index)) {
				READ_REGION_ACTIVE(rr, place, lba);
			} else {
				READ_REGION_NOT_ACTIVE(rr, place);
			}
			++lba;
			place+= SECTOR_SIZE;
			if (!--nsec) {
				READ_REGION_NOT_ACTIVE(rr, place);
				return rd_callback_with_preinit_buffer(rv);
			}
			if (++index == SECTORS_PER_SEGMENT) break;
		}
		++segment_index;
		index = 0;
	}
}

static uchar
freeze_reset(unsigned int segment_index, unsigned int index, int nsec)
{
	struct FreezeSegment *seg;
	struct FreezeSegmentBitmap *bitmap;
	for (;;) {
		for (;;) {
			if (fastbitmap_get(FBI_ANY(segment_index))) break;
			if (nsec<=(SECTORS_PER_SEGMENT - index))
				return 1;
			nsec-= (SECTORS_PER_SEGMENT - index);
			++segment_index;
			index = 0;
		}		
		seg = lookup_stgbitmap_seg(segment_index, &bitmap);
		if (!seg)
			return 0;
		for (;;) {
			if (bitmap_get_reset(bitmap->data, index))
				freeze_decrement_seg_dirtycnt(segment_index, bitmap);
			if (!--nsec) 
				return save_stgbitmap_seg(seg);

			if (++index == SECTORS_PER_SEGMENT) {
				if (!save_stgbitmap_seg(seg))
					return 0;
				break;
			}
		}
		++segment_index;
		index = 0;
	}
}


static uchar
freeze_set(unsigned int segment_index, unsigned int index, int nsec)
{
	struct FreezeSegment *seg;
	struct FreezeSegmentBitmap *bitmap;
	for (;;) {
		for (;;) {
			if (!fastbitmap_get(FBI_ALL(segment_index))) break;
			if (nsec<=(SECTORS_PER_SEGMENT - index))
				return 1;
			nsec-= (SECTORS_PER_SEGMENT - index);		
			++segment_index;
			index = 0;
		}
		
		seg = lookup_stgbitmap_seg(segment_index, &bitmap);
		if (!seg)
			return 0;

		for (;;) {
			if (!bitmap_get_set(bitmap->data, index))
				freeze_increment_seg_dirtycnt(segment_index, bitmap);
			if (!--nsec) return 1;
			if (++index == SECTORS_PER_SEGMENT) break;
		}
		++segment_index;
		index = 0;
	}	
}


int
freeze_putsec(uchar *place, vlong lba, int nsec)
{
	int rv;
	if (!freeeze_path)
		return -1;

	if (freeze_stopping || !freeze_active) {
		rv = bfd_putsec(place, lba, nsec);
		if (!freeze_active)
			return rv;
	} else {
		rv = pwrite(freeze_fd, place, nsec*SECTOR_SIZE, lba*SECTOR_SIZE + freeze_data_offset);
	}

    if (rv<=0) {
		fprintf(stderr, "freeze_write: rv<=0\n");
        return rv;
	}
	

	nsec = DIV_CEIL(rv, SECTOR_SIZE);
	DECLARE_INITIAL_IO_INDEXES(lba, segment_index, index);
	if (freeze_stopping) {
		if (!freeze_reset(segment_index, index, nsec))
			rv = -1;
	} else if (!freeze_set(segment_index, index, nsec)) {
		fprintf(stderr, "freeze_write: freeze_set failed\n");
		rv = -1;		
	}

	return rv;
}

#else

int freeze_putsec(uchar *data, vlong offset, int len) { return freeze_active ? -1 : bfd_putsec(data, offset, len);;}
int freeze_getsec(uchar *data, vlong offset, int len) { return bfd_getsec(data, offset, len); }
void freeze_start() { freeze_active = 1; }
void freeze_flush_and_stop(unsigned int time_limit) { freeze_active = 0; }

#endif
