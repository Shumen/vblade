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
#include <netinet/in.h>
#include "dat.h"


/////////////////////////////////////////////////////////////////////
///This code tracks ordered sequence of values and detects
///duplicates withing 'sliding window' of desired size.
///Every single value marked with single bit in bits ring queue
///so memory&cpu footprint is very low under normal operation.
///Currently only monotonically incrementing values are supported.
///Using this code with unique values generates with any other
///ordering will be ineffective: CPU usage will be higher and many 
///actually duplicated values will be reported as unique.
///Up to Nmasks separate rings can be accessed by
///changing currently selected id, such approach was used instead of 
///usual context-as-argument passing due to performance reasons.
////////////////////////////////////////////////////////////////////


//sliding window size, 32768 is large enough and fits in 4KB of memory
#define TAGS_IN_RING 32768

static struct tagring
{
	unsigned long maximum_tag;
	unsigned int maximum_tag_index;
	uchar *ring_of_bits;
} tagrings[Nmasks], selected;

static int selected_id = -1;


static inline void 
set_bit(unsigned int index)  
{ 
	selected.ring_of_bits[index/8]|= (1<<(index%8)); 
}

//static inline uchar get_bit(unsigned int index)
//{ return ((selected.ring_of_bits[index/8] & (1<<(index%8)))!=0); }

static inline uchar 
get_set_bit(unsigned int index) 
{
	const uchar oct = selected.ring_of_bits[index/8], bm = ((uchar)1<<(index%8));
	if (oct&bm) 
		return 1;

	selected.ring_of_bits[index/8] = oct | bm;
	return 0;
}

#define PARTIAL_BEGIN_OF_RESET_BITS(oct_index, index, n) \
	unsigned int oct_index = index/8; \
	if (index&7) { \
		uchar oct = ~selected.ring_of_bits[oct_index]; \
		uchar bm = (uchar)1<<(index%8); \
		for (;(n && bm); --n, bm<<=1) oct|= bm; \
		selected.ring_of_bits[oct_index] = ~oct; \
		if (!n)  return; \
		++oct_index; }
	
#define PARTIAL_END_OF_RESET_BITS(oct_index, n) { \
		uchar oct = ~selected.ring_of_bits[oct_index], bm = 1; \
		for (;n; --n, bm<<=1) oct|= bm; \
		selected.ring_of_bits[oct_index] = ~oct; }


static void //resets [0, index)
reset_bits_to(unsigned int index) 
{
	unsigned int oct_index;
	if (index>8) {
		oct_index = index/8;
		memset(&selected.ring_of_bits[0], 0, oct_index);
		index&= 7;
	}
	else
		oct_index = 0;
	if (index) {	
		PARTIAL_END_OF_RESET_BITS(oct_index, index);
	}
}

static void //resets [index, TAGS_IN_RING)
reset_bits_from(unsigned int index) 
{
	unsigned int n = TAGS_IN_RING - index;
	PARTIAL_BEGIN_OF_RESET_BITS(oct_index, index, n);	
	memset(&selected.ring_of_bits[oct_index], 0, n/8);
}

static void //resets [index, index+n)
reset_bits(unsigned int index, unsigned int n) 
{
	PARTIAL_BEGIN_OF_RESET_BITS(oct_index, index, n);

	if (n>8) {
		int no = n/8;
		memset(&selected.ring_of_bits[oct_index], 0, no);
		n-= no*8;
		if (!n)
			return;

		oct_index+= no;
	}

	PARTIAL_END_OF_RESET_BITS(oct_index, n);	
}

/////public interface

void 
tagring_init() 
{
	selected_id = -1;
	memset(tagrings, 0, sizeof(tagrings));
	memset(&selected, 0, sizeof(selected));
}

int 
tagring_select(int id) 
{
	int out = selected_id;
	if (id!=selected_id) {
		if (0<=selected_id)
			tagrings[selected_id] = selected;
		
		if (0<=(selected_id = id))
			selected = tagrings[id];
		else
			memset(&selected, 0, sizeof(selected));
	}
	return out;
}

void 
tagring_deinit() 
{
	int i;
	tagring_select(-1);
	memset(&selected, 0, sizeof(selected));
	for (i = 0; i<Nmasks; ++i) {
		if (tagrings[i].ring_of_bits)
			free(tagrings[i].ring_of_bits);
	}	
}

void 
tagring_reset() 
{
	selected.maximum_tag = 0;
	selected.maximum_tag_index = 0;
	if (selected.ring_of_bits) 
		memset(selected.ring_of_bits, 0, TAGS_IN_RING/8);
}

uchar 
tagring_process(unsigned long tag) 
{
	if (!selected.ring_of_bits) {
		if (selected_id==-1 || !(selected.ring_of_bits = valloc(TAGS_IN_RING/8)))
			return 0;
		memset(selected.ring_of_bits, 0, TAGS_IN_RING/8);
	}
	
	if (tag>selected.maximum_tag) {
		unsigned int index = selected.maximum_tag_index + (unsigned int)(tag - selected.maximum_tag);
		if (index<TAGS_IN_RING) {
			if (index>(selected.maximum_tag_index+1)) 
				reset_bits(selected.maximum_tag_index+1, index - selected.maximum_tag_index - 1);

			selected.maximum_tag = tag;
			selected.maximum_tag_index = index;
			set_bit(index);
			return 0;
		}

		index-= (TAGS_IN_RING - selected.maximum_tag_index);

		if (index<selected.maximum_tag_index) {
			reset_bits_to(index);
			set_bit(index);
			if (selected.maximum_tag_index<(TAGS_IN_RING-1))
				reset_bits_from(selected.maximum_tag_index+1);

			selected.maximum_tag = tag;
			selected.maximum_tag_index = index;			
			return 0;
		}
	}
	else {
		unsigned int delta = (unsigned int) (selected.maximum_tag - tag);
		if (delta<=selected.maximum_tag_index)
			return get_set_bit(selected.maximum_tag_index - delta);

		delta-= selected.maximum_tag_index;
		if (delta<(TAGS_IN_RING-selected.maximum_tag_index))
			return get_set_bit(TAGS_IN_RING - delta);
	}

	//specified tag doesn't fall into current queue region
	//reset all present content and put only this single tag

	selected.maximum_tag = tag;
	selected.maximum_tag_index = 0;

	selected.ring_of_bits[0] = 1;
	memset(&selected.ring_of_bits[1], 0, (TAGS_IN_RING/8)-1);

	//...that actually does same thing as this slower code:
	//set_bit(0);
	//reset_bits_from(1);
	
	return 0;
}
