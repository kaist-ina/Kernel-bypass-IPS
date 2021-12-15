#ifndef _TIME_MEASURE_H_
#define _TIME_MEASURE_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

void fstart();
uint64_t fend();

void fstart_match();
uint64_t fend_match();

#if defined(__cplusplus)
}
#endif

#endif /* !_TIME_MEASURE_H_ */