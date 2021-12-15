#include "print_util.h"
#include "Match_Main.h"
#include "dfc_framework.h"
#include "dfc.h"
#include <set>


using namespace std;

#define USE_DFC

DFC_STRUCTURE* dfc;

void pat_load_ruleset(uint8_t **ruleset, uint32_t ruleset_size)
{
    int i;
    printl("DFC new!");
    dfc = DFC_New();
    for (i = 0; i < ruleset_size; i++) {
        DFC_AddPattern(dfc, (unsigned char*)ruleset[i],
            strlen((const char*)ruleset[i]),
            0 /*case-sensitive pattern*/, i /*Pattern ID*/);
    }
    DFC_Compile(dfc);

    printl("Rule loaded");
}

void Print_Result(uint8_t* pattern, uint32_t* id_list, uint32_t list_size)
{
#if 0 // Set 1 to debug
    int i;
    printf(" [Matched!] Pattern: %s, IDs:", pattern);

    for (i = 0; i < list_size; i++) {
        printf("%u", id_list[i]);
        if (i != list_size - 1)
            printf(", ");
    }
    printf("\n");
#endif
}

int total_len = 0;

int pat_search_each(uint8_t *packet, int pkt_length, uint8_t core)
{
    int dfc_match;
    int tot_length = 0, offset = 0, buflen;

    if(packet == NULL) {
        return 0;
    }    
    
   while(tot_length < pkt_length) {
        buflen = pkt_length - tot_length;
        buflen = (buflen >= 1448)? 1448 : buflen;
        dfc_match = DFC_Search(dfc, packet + offset, buflen, Print_Result);
        if (dfc_match > 0) {
            printl("DFC: [core %d] dfc_match = %d", core, dfc_match);
        }
        offset += buflen;
        tot_length += buflen;
   }
    return dfc_match;
}
