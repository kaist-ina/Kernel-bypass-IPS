#include <time.h>

#include "time_measure.h"

struct timespec tstart = { 0, 0 }, tend = { 0, 0 };
struct timespec tstart_match = { 0, 0 }, tend_match = { 0, 0 };

timespec time_diff(timespec start, timespec end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

void fstart()
{    
    clock_gettime(CLOCK_MONOTONIC, &tstart);
}

uint64_t fend()
{
    struct timespec tdiff = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &tend);
    tdiff = time_diff(tstart, tend);
    uint64_t diff_ns = tdiff.tv_sec*1.0e9 + tdiff.tv_nsec;
    return diff_ns;
}


void fstart_match()
{    
    clock_gettime(CLOCK_MONOTONIC, &tstart_match);
}

uint64_t fend_match()
{
    struct timespec tdiff = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &tend_match);
    tdiff = time_diff(tstart_match, tend_match);
    uint64_t diff_ns = tdiff.tv_sec*1.0e9 + tdiff.tv_nsec;
    return diff_ns;
}
