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
//IO multipleXor
//redirects IO requests to bfdio.c or to freeze.c with freeze/unfreeze managing

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
#include <poll.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include "dat.h"
#include "fns.h"

#define MIN_USER_SIGUSR1			0x01
#define SIGUSR_REQUEST_FREEZE 		0x01
#define SIGUSR_REQUEST_UNFREEZE 	0x02
#define MAX_USER_SIGUSR1			0x02

#define SIGUSR_REQUEST_DIE 			0xfe
#define SIGUSR_REQUEST_DIYING		0xff

static volatile int die_signal = 0;
static volatile uchar sigusr_request = 0;
static volatile uchar count_of_sigusr1 = 0;
static sigset_t sst_usr, sst_notusr;

static inline void 
process_sigusr_request()
{
	if (sigusr_request) {
		switch (sigusr_request) {
			case SIGUSR_REQUEST_FREEZE:
				if (!freeze_active) {
					bfd_flush();
					freeze_start();
				}
				sigusr_request = 0;
			break;

			case SIGUSR_REQUEST_UNFREEZE:
				if (freeze_active)
					freeze_flush_and_stop(0);
				sigusr_request = 0;
			break;

			case SIGUSR_REQUEST_DIE:
				printf("Dying peacefully\n");
				grace_exit(die_signal);
				sigusr_request = SIGUSR_REQUEST_DIYING;
			break;
		}
	}
}

static time_t tm_last_long_flush = 0;
#ifdef MAX_NICS
static struct pollfd pollset[MAX_NICS];
#else
static struct pollfd *pollset = NULL;
#endif
static int pollset_remain = 0;

static signed char 
tricky_ppoll(struct timespec *ts)
{
	int i;
	if (pollset_remain!=0) {
		--pollset_remain;
		for (i = 0; i<niccnt; ++i) {
			if (pollset[i].revents!=0) {
				pollset[i].revents = 0;
				curnic = i;
				return 1;
			}
		}
	}

	for (i = 0; i<niccnt; ++i) {
		pollset[i].fd = nics[i].sfd;
		pollset[i].events = POLLIN;
		pollset[i].revents = 0;
	}

	i = ppoll(&pollset[0], niccnt, ts, &sst_notusr);
	if (i>0) {
		pollset_remain = i - 1;
		for (i = 0; i<niccnt; ++i) {
			if (pollset[i].revents!=0) {
				pollset[i].revents = 0;
				curnic = i;
				return 1;
			}
		}
	}

	pollset_remain = 0;

	return i;
}

int 
iox_poll(int timeout) 
{
	time_t tms = 0, tm;	
	struct timespec ts;
	int r;
	for (;;) {
		process_sigusr_request();
		if (AOE_UNLIKELY(freeze_stopping)) {//do flush instead of idle waiting
			time(&tm);
			if (!tms) tms = tm;
			if (!tm_last_long_flush) tm_last_long_flush = tm;
			if (tm<tm_last_long_flush || tm>(tm_last_long_flush+2)) {
				freeze_flush_and_stop(1);
				time(&tm_last_long_flush);
			}

			if (AOE_LIKELY(freeze_stopping)) {
				ts.tv_sec = 0;
				ts.tv_nsec = 0;
				r = tricky_ppoll(&ts);
				if (r<0) {
					if (errno!=EINTR)
						return -1;
				} else if (r>0) {
					return r;
				} else if (timeout!=-1) {
					time(&tm);
					if (tm<tms || (tm - tms)>timeout)
						return 0;
				}
			}
		} else {
			if (timeout!=-1) {
				ts.tv_sec = timeout;
				ts.tv_nsec = 0;
				r = tricky_ppoll(&ts);
			} else
				r = tricky_ppoll(NULL);

			if (r!=-1 || errno!=EINTR) break;
		}
	}
	return r;
}

static void 
iox_sleep(int t)
{
	sigprocmask(SIG_UNBLOCK, &sst_usr, NULL);
	sleep(t);
	sigprocmask(SIG_BLOCK, &sst_usr, NULL);	
}

ssize_t 
iox_read_sfd(void *buf, size_t count)
{
	ssize_t r;
	sigprocmask(SIG_UNBLOCK, &sst_usr, NULL);
	for (;;)
	{
		if (niccnt>1 || AOE_UNLIKELY(freeze_stopping)) {
			r = iox_poll(-1); //it will take care about unfreezing
			if (r<=0)
				break;
		}
		r = read(nics[curnic].sfd, buf, count);
		if (AOE_LIKELY(r!=-1 || errno!=EINTR)) break;
		if (AOE_UNLIKELY(sigusr_request)) {
			sigprocmask(SIG_BLOCK, &sst_usr, NULL);
			process_sigusr_request();
			sigprocmask(SIG_UNBLOCK, &sst_usr, NULL);
		}
	}
	sigprocmask(SIG_BLOCK, &sst_usr, NULL);
	process_sigusr_request();
	return r;
}

static time_t prev_inrequest_flush = 0, prev_flush_time = 1;

static void 
iox_check_for_inrequest_freeze_flush()
{
	time_t now;
	if (freeze_stopping) {
		time(&now);
		if ( (now<prev_inrequest_flush) || (now-prev_inrequest_flush)>prev_flush_time) {		
			freeze_flush_and_stop(0);
			time(&prev_inrequest_flush);
			prev_flush_time = (prev_inrequest_flush - now);
			if (prev_flush_time<1)
				prev_flush_time = 1;
		}
	}
}

int 
iox_putsec(uchar *place, vlong lba, int nsec)
{	
	int r;
	for (;;) {
		process_sigusr_request();
		if (!freeze_active)
			return bfd_putsec(place, lba, nsec);

		r = freeze_putsec(place, lba, nsec);
		if (r!=-1) {
			iox_check_for_inrequest_freeze_flush();
			return r;
		}
		
		if (freeze_stopping)
			freeze_flush_and_stop(1);
		else
			iox_sleep(1);
	}
}

void
iox_getsec(struct Ata *preinit_ata_responce, vlong lba, int nsec)
{
	process_sigusr_request();
	if (freeze_active) {
		iox_check_for_inrequest_freeze_flush();
		freeze_getsec(preinit_ata_responce, lba, nsec);
	} else {
		bfd_getsec(preinit_ata_responce, lba, nsec, 0); 
	}
}

void 
iox_flush()
{
	while (freeze_active)
		freeze_flush_and_stop(-1);

	bfd_flush();
}

static void 
handle_deadly_signal(int signal)
{
	fprintf(stderr, "Got deadly signal: %d\n", signal);
	if (sigusr_request!=SIGUSR_REQUEST_DIE && sigusr_request!=SIGUSR_REQUEST_DIYING) {
		die_signal = signal;
		sigusr_request = SIGUSR_REQUEST_DIE;
		raise(SIGUSR2);
	}
}

static void 
handle_sigusr1(int signal)
{
	if (!++count_of_sigusr1)
		fprintf(stderr, "Too many SIGUSR1!\n");
}

static void 
handle_sigusr2(int signal)
{
	if (sigusr_request!=SIGUSR_REQUEST_DIE && sigusr_request!=SIGUSR_REQUEST_DIYING) {
		printf("Got sigusr2 while count_of_sigusr1=%u\n", count_of_sigusr1);
		if (count_of_sigusr1>=MIN_USER_SIGUSR1 && count_of_sigusr1<=MAX_USER_SIGUSR1)
			sigusr_request = count_of_sigusr1;
		count_of_sigusr1 = 0;
	} else if (sigusr_request!=SIGUSR_REQUEST_DIE)
		printf("Got sigusr2 while die requested\n");
}


void 
iox_init()
{
	struct sigaction sa;

#ifndef MAX_NICS
	if (pollset) free(pollset);
	pollset = (struct pollfd *)malloc(niccnt * sizeof(struct pollfd));
	if (!pollset) {
		perror("malloc");
		exit(-1);
	}
#endif

	memset(&pollset[0], 0, sizeof(pollset));
	memset(&sa, 0, sizeof(sa));
    sigfillset(&sa.sa_mask);

	bfd_init();
	sigemptyset(&sst_usr);
	sigaddset(&sst_usr, SIGUSR1);
	sigaddset(&sst_usr, SIGUSR2);
	sigprocmask(SIG_BLOCK, &sst_usr, &sst_notusr);
	sigdelset(&sst_notusr, SIGUSR1);
	sigdelset(&sst_notusr, SIGUSR2);

	sa.sa_handler = &handle_deadly_signal;
	sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);

	sa.sa_handler = &handle_sigusr1;
	sigaction(SIGUSR1, &sa, NULL);

	sa.sa_handler = &handle_sigusr2;
	sigaction(SIGUSR2, &sa, NULL);
}

