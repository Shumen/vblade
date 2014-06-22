//IO pulmtipleXor
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
				grace_exit(die_signal);
				sigusr_request = SIGUSR_REQUEST_DIYING;
			break;
		}
	}
}

int 
iox_poll(int fd, int timeout) 
{
	struct pollfd pollset;
	struct timespec ts;
	time_t tms = 0, tm;
	int r;
	for (;;) {
		pollset.fd = fd;
		pollset.events = POLLIN;
		pollset.revents = 0;

		process_sigusr_request();
		if (freeze_stopping) {//do flush instead of idle waiting
			if (!tms) time(&tms);
			freeze_flush_and_stop(1);
			if (freeze_stopping) {
				ts.tv_sec = 0;
				ts.tv_nsec = 0;
				r = ppoll(&pollset, 1, &ts, &sst_notusr);
				if (r==-1) {
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
				r = ppoll(&pollset, 1, &ts, &sst_notusr);
			} else
				r = ppoll(&pollset, 1, NULL, &sst_notusr);

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
iox_read_packet_fd(int fd, void *buf, size_t count)
{
	ssize_t r;
	sigprocmask(SIG_UNBLOCK, &sst_usr, NULL);
	for (;;)
	{
		process_sigusr_request();
		if (freeze_stopping) {
			if (iox_poll(fd, 10)<=0)//it will take care about unfreezing
				continue;
		}
		r = read(fd, buf, count);
		if (r!=-1 || errno!=EINTR) break;
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

int 
iox_getsec(uchar *place, vlong lba, int nsec)
{
	process_sigusr_request();
	if (!freeze_active)
		return bfd_getsec(place, lba, nsec);

	iox_check_for_inrequest_freeze_flush();
	return freeze_getsec(place, lba, nsec);
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
	bfd_init();
	sigemptyset(&sst_usr);
	sigaddset(&sst_usr, SIGUSR1);
	sigaddset(&sst_usr, SIGUSR2);
	sigprocmask(SIG_BLOCK, &sst_usr, &sst_notusr);
	sigdelset(&sst_notusr, SIGUSR1);
	sigdelset(&sst_notusr, SIGUSR2);

	signal(SIGINT, handle_deadly_signal);
    signal(SIGTERM, handle_deadly_signal);
	signal(SIGQUIT, handle_deadly_signal);
    signal(SIGKILL, handle_deadly_signal);
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGUSR2, handle_sigusr2);
}

