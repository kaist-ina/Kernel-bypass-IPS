#ifndef _MATCH_MAIN_H_
#define _MATCH_MAIN_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

void pat_load_ruleset(uint8_t **ruleset, uint32_t ruleset_size);
int pat_search_each(uint8_t *packets, int pkt_length, uint8_t core);

#if defined(__cplusplus)
}
#endif

#endif /* !_MATCH_MAIN_H_ */
