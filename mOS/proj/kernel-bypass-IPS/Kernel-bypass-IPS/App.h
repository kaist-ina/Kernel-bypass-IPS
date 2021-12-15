#ifndef _APP_H_
#define _APP_H_

#include <stdint.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__cplusplus)
extern "C" {
#endif

void ocall_set_blacklist(uint32_t ip_addr);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
