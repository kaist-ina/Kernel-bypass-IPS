#ifndef _PRINT_UTIL_
#define _PRINT_UTIL_


#if defined(__cplusplus)
extern "C" {
#endif

void my_printe(const char* fname, const char* fmt, ...);
void my_printl(const char* fname, const char* fmt, ...);

#define printe(fmt, ...) my_printe(__FUNCTION__, fmt, ##__VA_ARGS__)
#define printl(fmt, ...) my_printl(__FUNCTION__, fmt, ##__VA_ARGS__)

#if defined(__cplusplus)
}
#endif

#endif /* !_PRINT_UTIL_ */


