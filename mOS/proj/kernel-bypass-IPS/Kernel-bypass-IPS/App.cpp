#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netinet/in.h>
#include <set>
#include <map>
#include <getopt.h>

#include "App.h"
#include "mos_api.h"
#include "cpu.h"
#include "Match_Main.h"
#include "time_measure.h"
#include "print_util.h"

using namespace std;

/* Maximum CPU cores */
#define MAX_CORES 8
/* Default path to mOS configuration file */
#define MOS_CONFIG_FILE \
    "/config/mos.conf"

/*----------------------------------------------------------------------------*/
/* Global variables */
struct thread_context
{
	mctx_t mctx;         /* per-thread mos context */
	int mon_listener;    /* listening socket for flow monitoring */
};

struct connection {
    int sock; /* socket ID */
    struct sockaddr_in addrs[2]; /* Address of a client and a server */
    bool target;
    bool malicious;
    uint32_t next_seq;
    uint32_t dropped_seq;
    uint64_t total_payloadlen;
    TAILQ_ENTRY(connection)
    link; /* link to next context in this core */
};

TAILQ_HEAD(, connection) g_sockq[MAX_CORES]; /* connection queue */
struct thread_context g_mctx[MAX_CORES] = {{0}}; /* init all fields to 0 */
set<uint32_t> set_blacklist;
bool is_finish = false;

/*----------------------------------------------------------------------------*/
/* Signal handler */
static void sigint_handler(int signum)
{
    int i;
    printl("SIGINT received... Closing mOS");
    /* Terminate the program if any interrupt happens */
    for (i = 0; i < MAX_CORES; i++) {
        mtcp_close(g_mctx[i].mctx, g_mctx[i].mon_listener);
        mtcp_destroy_context(g_mctx[i].mctx);
    }    
}

/*----------------------------------------------------------------------------*/
void ocall_set_blacklist(uint32_t ip_addr) 
{
    struct in_addr ip_saddr;
    ip_saddr.s_addr = ip_addr;
    printl("PUSH blacklist IP: %s", inet_ntoa(ip_saddr));
    if (set_blacklist.find(ip_addr) == set_blacklist.end()) {
        set_blacklist.insert(ip_addr);   
    }   
}

static inline struct connection* find_connection(int cpu, int sock)
{
    struct connection* c;

    TAILQ_FOREACH(c, &g_sockq[cpu], link)
    if (c->sock == sock)
        return c;

    return NULL;
}

int scan_cnt = 0;
uint32_t dfc_cnt = 0;
uint64_t total_match_ns;

static void
cb_creation(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
    socklen_t addrslen = sizeof(struct sockaddr) * 2;
    struct connection* c;
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t core = mctx->cpu;

    c = (struct connection*)calloc(sizeof(struct connection), 1);
    if (!c) {
        return;
    }

    //printl("FSTART()");
    dfc_cnt = 0;
    total_match_ns = 0;

    /* Fill values of the connection structure */
    c->sock = sock;
    if (mtcp_getpeername(mctx, c->sock, (struct sockaddr*)c->addrs, &addrslen,
            MOS_SIDE_BOTH) < 0) {
        printe("mtcp_getpeername");
    }

    c->malicious = false;
    c->next_seq = 0;
    c->dropped_seq = 0;
    c->target = false;
    c->total_payloadlen = 0;

    src_ip = c->addrs[0].sin_addr.s_addr;
    src_port = ntohs(c->addrs[0].sin_port);
    
    /* Insert the structure to the queue */
    TAILQ_INSERT_TAIL(&g_sockq[core], c, link);
    struct in_addr ip_addr;
    ip_addr.s_addr = src_ip;
    ///printf("-----------------------------------------------------------------\n");
    //printl("[core %d] Flow came in, IP = %s, port = %d", mctx->cpu, inet_ntoa(ip_addr), src_port);
    
    if(src_port == 3000) {
        //printl("Start time measure!");
        c->target = true;
        fstart();
    }
}

static void
cb_pkt_in(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
    struct connection* c;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    int i;
    struct pkt_ctx *p;
    struct pkt_info pinfo;
    struct iphdr *iph;
    struct tcphdr *th;
    uint8_t core = mctx->cpu;
    int payloadlen;
    uint64_t total_fct_ns, sub_ns;
    double total_fct_ms, total_match_ms, sub_ms;
    uint32_t ip_addr;
    bool is_malicious = false;

    if(side != MOS_SIDE_CLI) {
        return;
    }

    if (mtcp_getlastpkt(mctx, sock, side, &p) < 0) {
		printe("Failed to get packet context!!!");
    }

    pinfo = p->p;
    iph = pinfo.iph;
    th = pinfo.tcph;
    payloadlen = pinfo.payloadlen;
    int drop = 0;
    uint32_t next_seq;
    
    if(payloadlen > 0 && !th->syn) {
        if (!(c = find_connection(mctx->cpu, sock))) {
            printe("No connection");
            return;
        }

        if(c->malicious) {
            drop = 1;
            printl("Malicious flow, drop packet");
            mtcp_save_pkt(mctx, sock, side, drop);
            mtcp_send_reset(mctx, sock, side, p);
            return;
        }

        next_seq = c->next_seq;

        //printl("Incoming packet [%d] [%d] pinfo.in_ifidx = %d, iph->id = %d, th->psh = %d, th->syn = %d, th->ack = %d, th->fin = %d, th->seq = %u (%u, %u), th->ack = %u payloadlen = %d", 
        //       side, mctx->cpu, pinfo.in_ifidx, ntohs(iph->id), th->psh, th->syn, th->ack, th->fin, ntohl(th->seq), c->dropped_seq, next_seq, ntohl(th->ack_seq), payloadlen);

        if(next_seq != 0 && ntohl(th->seq) > next_seq) {
            c->dropped_seq = next_seq;
            //printl("Drop packet [%d] [%d] pinfo.in_ifidx = %d, iph->id = %d, th->psh = %d, th->syn = %d, th->ack = %d, th->fin = %d, th->seq = %u (%u, %u), th->ack = %u payloadlen = %d", 
                //side, mctx->cpu, pinfo.in_ifidx, ntohs(iph->id), th->psh, th->syn, th->ack, th->fin, ntohl(th->seq), c->dropped_seq, next_seq, ntohl(th->ack_seq), payloadlen);
            mtcp_save_pkt(mctx, sock, side, 1);
            return;
        }

        if(next_seq == 0 || ntohl(th->seq) == next_seq) {
            if(c->dropped_seq != 0) {
                //printl("Found packet [%d] [%d] pinfo.in_ifidx = %d, iph->id = %d, th->psh = %d, th->syn = %d, th->ack = %d, th->fin = %d, th->seq = %u (%u, %u), th->ack = %u payloadlen = %d", 
                    //side, mctx->cpu, pinfo.in_ifidx, ntohs(iph->id), th->psh, th->syn, th->ack, th->fin, ntohl(th->seq), c->dropped_seq, next_seq, ntohl(th->ack_seq), payloadlen);
                c->dropped_seq = 0;
            }
            c->next_seq = ntohl(th->seq)+payloadlen;
            mtcp_save_pkt(mctx, sock, side, drop);
        }
        else {
            //printl("Ignore packet [%d] [%d] pinfo.in_ifidx = %d, iph->id = %d, th->psh = %d, th->syn = %d, th->ack = %d, th->fin = %d, th->seq = %u (%u, %u), th->ack = %u payloadlen = %d", 
            //   side, mctx->cpu, pinfo.in_ifidx, ntohs(iph->id), th->psh, th->syn, th->ack, th->fin, ntohl(th->seq), c->dropped_seq, next_seq, ntohl(th->ack_seq), payloadlen);
        }

        if(c->target && th->fin) {
            is_finish = true;
        }
    }
}

static void
cb_new_data(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
    struct connection* c;
    unsigned char payload[819200];
    int payloadlen;
    uint32_t ip_addr;
    int i;
    uint8_t core = mctx->cpu;
    bool is_malicious = false;
    
    uint64_t total_fct_ns, sub_ns;
    double total_fct_ms, total_match_ms, sub_ms;

    if (!(c = find_connection(core, sock))) {
        printe("No connection");
        return;
    }

    if (side == MOS_SIDE_CLI || c->malicious == true) {
        printl("side == MOS_SIDE_CLI || c->malicious == true");
        return;
    }    

    payloadlen = mtcp_peek(mctx, sock, side, (char *)payload, 819200);
    if (payloadlen <= 0) {
        printe("payloadlen = %d", payloadlen);
    }
    c->total_payloadlen += payloadlen;
    // printl("[core %d] read = %d B, total read = %d KB", mctx->cpu, payloadlen, c->total_payloadlen/1024);
    
    #if 1
    ip_addr = ntohl(c->addrs[0].sin_addr.s_addr);
    if(c->target) {
        fstart_match();
    }
    if (pat_search_each(payload, payloadlen, core) > 0) {
        is_malicious = true;
        c->malicious = true;
    }
    if(c->target) {
        total_match_ns += fend_match();
    }
    #endif
    
    if (0 && is_malicious) {
        ocall_set_blacklist(ip_addr);
        unsigned char ip[4] = {0,0,0,0};
        for (int i=0; i<4; i++) { 
            ip[i] = (ip_addr >> (i*8)) & 0xFF; 
        }
        printl("[%u] SET BLACKLIST: %d.%d.%d.%d\n", ip[3], ip[2], ip[1], ip[0]);
    }
    else {
        mtcp_flush_pkts(mctx, sock, side, 0); 
    }

    if(c->target && is_finish) {
        total_fct_ns = fend();
        total_fct_ms = (double)total_fct_ns/1.0e6;
        total_match_ms = (double)total_match_ns/1.0e6;
        sub_ns = total_fct_ns-total_match_ns;
        sub_ms = (double)sub_ns/1.0e6;
        printl("Total FCT = %llu ns, %f ms", total_fct_ns, total_fct_ms);
        printl("Total DFC = %llu ns, %f ms", total_match_ns, total_match_ms);
        printl("Flow completion time = %llu ns, %f ms", sub_ns, sub_ms);
        printf("%f\n", sub_ms);
        is_finish = false;
    }
}

static void
cb_on_error(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t *arg)
{
    //mtcp_setlastpkt(mctx, sock, side, 0, NULL, 0, MOS_DROP);
    printl("cb_on_error occur!");
}

/* Destroy connection structure */
static void 
cb_destroy(mctx_t mctx, int sock, int side, uint64_t events, filter_arg_t* arg)
{
    struct connection* c;
    uint32_t src_ip;
    uint64_t total_size;
    uint8_t core = mctx->cpu;

    if (!(c = find_connection(core, sock)))
        return;    


    printl("Total payload length = %d KB, %d MB", c->total_payloadlen/1024, c->total_payloadlen/1024/1024);

    TAILQ_REMOVE(&g_sockq[core], c, link);
    free(c);
}
/*----------------------------------------------------------------------------*/
static void
init_thread_context(struct thread_context* ctx, int core)
{

    struct timeval tv_1sec = { /* 1 second */
		.tv_sec = 1,
		.tv_usec = 0
	};

    monitor_filter ft = {0};

	ctx->mctx = mtcp_create_context(core);
	/* create socket  */
	ctx->mon_listener = mtcp_socket(ctx->mctx, AF_INET,
                    MOS_SOCK_MONITOR_STREAM, 0);
    
	if (ctx->mon_listener < 0)
        printe("Failed to create monitor listening socket!\n");

    ft.stream_syn_filter = "tcp";

    if (mtcp_bind_monitor_filter(ctx->mctx, ctx->mon_listener, &ft) == -1) {
        perror("mtcp_bind_monitor_filter() failed: ");
        exit(EXIT_FAILURE);
    }

    TAILQ_INIT(&g_sockq[ctx->mctx->cpu]);
    
    /* register callback */
    if (mtcp_register_callback(ctx->mctx, ctx->mon_listener, 
        MOS_ON_CONN_START,
        MOS_HK_SND, cb_creation)) {
        fprintf(stderr, "Failed to register cb_creation()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }
    if (mtcp_register_callback(ctx->mctx, ctx->mon_listener, 
        MOS_ON_CONN_NEW_DATA,
        MOS_NULL, cb_new_data)) {
        fprintf(stderr, "Failed to register cb_new_data()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }
    if (mtcp_register_callback(ctx->mctx, ctx->mon_listener, 
        MOS_ON_PKT_IN,
        MOS_HK_SND, cb_pkt_in)) {
        fprintf(stderr, "Failed to register cb_pkt_in()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }
    if (mtcp_register_callback(ctx->mctx, ctx->mon_listener, 
        MOS_ON_CONN_END,
        MOS_HK_SND, cb_destroy)) {
        fprintf(stderr, "Failed to register cb_destroy()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }
    if (mtcp_register_callback(ctx->mctx, ctx->mon_listener, 
        MOS_ON_ERROR,
        MOS_NULL, cb_on_error)) {
        fprintf(stderr, "Failed to register cb_on_error()\n");
        exit(-1); /* no point in proceeding if callback registration fails */
    }
}
/*----------------------------------------------------------------------------*/
static void
cleanup_thread_context(struct thread_context* ctx)
{
	/* wait for the TCP thread to finish */
	mtcp_app_join(ctx->mctx);
		
	/* close the monitoring socket */
	mtcp_close(ctx->mctx, ctx->mon_listener);

	/* tear down */
	mtcp_destroy_context(ctx->mctx);	
}
/*----------------------------------------------------------------------------*/
int load_ruleset(const char *path)
{
    uint8_t **ruleset = NULL;
    ssize_t r;
    uint8_t *line = NULL, *pos;
    int i = 0, size = 1024;
    size_t len;
    FILE *file = fopen(path, "rb");
    if(!file) {
        printe("fopen ruleset returns error!");
        return -1;
    }
    ruleset = (uint8_t **)calloc(sizeof(char *), size);
    while((r = getline((char **)&line, &len, file)) != -1) {
        if (i == size) {
            size *= 2;
            ruleset = (uint8_t **)realloc(ruleset, sizeof(char *) * size);
        }
        if((pos = (uint8_t *)strchr((char *)line, '\n')) != NULL) {
            *pos = '\0';
        }
        ruleset[i++] = line;
        line = NULL;
    }
    printl("Ruleset load success at %p! Rule size: %d lines", ruleset, i);
    pat_load_ruleset(ruleset, i);
    fclose(file);
    return 0;
}

/*----------------------------------------------------------------------------*/
/* Application entry */
int main(int argc, char* argv[])
{
    (void)(argc);
    (void)(argv);

    int i, opt;
    char fname[1024]; /* path to the default mos config file */
    char rule_path[1024]; /* ET PRO ruleset */
    char* fpath = MOS_CONFIG_FILE;
    char *user_rule_path = NULL;

    struct mtcp_conf mcfg; /* mOS configuration */

    while (true) {
        opt = getopt(argc, argv, "r:h");
        if (-1 == opt)
            break;
        switch (opt) {
        case 'r':
            user_rule_path = strdup(optarg);
			break;
        case 'h':
        case '?':
        default:
            printf("<Usage> \n"
                "\t-r <path>:\n\t\t Set ruleset file.\n"
                "\t-h :\n\t\t Show this message\n"
            );
            exit(0);
            break;
        }
    }

    if (getcwd(fname, sizeof(fname)) == NULL) {
        printe("getcwd error");
        return -1;
    }
    strcat(fname, fpath);    

    /* Check user's rule path */
    if(user_rule_path == NULL) {
        printe("User rule path is empty");
        return -1;
    }

    strcpy(rule_path, user_rule_path);
    printl("User rule path is %s", rule_path);

    if(load_ruleset(rule_path) == -1) {
        printe("Failed to load ruleset");
        return -1;
    }

    /* parse mos configuration file */
    if (mtcp_init(fname)) {
        printe("Failed to initialize mtcp.");
        return -1;
    }

    /* set the core limit */
    mtcp_getconf(&mcfg);
    mcfg.num_cores = MAX_CORES;
    mtcp_setconf(&mcfg);

    /* Register signal handler */
    mtcp_register_signal(SIGINT, sigint_handler);

    /* initialize monitor threads */	
	for (i = 0; i < mcfg.num_cores; i++) {
        init_thread_context(&g_mctx[i], i);
    }
    
    /* wait until all threads finish */	
    for (i = 0; i < mcfg.num_cores; i++) {
        cleanup_thread_context(&g_mctx[i]);
        printl("Message test thread %d joined.\n", i);	  
    }

	getchar();
    return 0;
}
