#ifndef MDEF_H
#define MDEF_H 1
#include "milterconfig.h"
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sysexits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <syslog.h>
#include <regex.h> /* Provides regular expression matching */
#include <strings.h> /* String utillity functions */
#include <libmilter/mfapi.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <string.h>	   /* strstr / strdup */
#include <sys/socket.h>   /* inet_ functions / structs */
#include <netinet/in.h>   /* inet_ functions / structs */
#include <arpa/inet.h>	/* in_addr struct */
#include <unistd.h>
#include <signal.h>
#include "firm-dkim.h"


#ifndef true
#define false	0
#define true	1
#endif /* ! true */

#define MAXLISTSIZE 1000
#define MAXDOMSIZE 50
#define MAXIDSIZE 500
#define MAXSIGNDOMS 50
#define MAXHDRS 10
#define DKIM_KEYFILE "/etc/postfix/dkim/dkim_keys.private"
#define PIDFILE "/var/run/dkim/dkim.pid"
#define NUMHDR 10
#define BODYSIZE 10240
#define DKIMHDR "DKIM-Signature"
#define ABUSE_HDR_VAL "abuse@cleanmail.in"
#define ABUSE_HDR "X-Abuse-Reports-To"
#define DSIGNDOM "cleanmail.in"
#define MAXHEADERSIZE 2000
#define MAXSINGLEHDR 200
#define MAXSINGLEVAL 180

typedef struct {
    char *key;
} bl;

typedef struct {
    int count;
    bl *list;
} mlist;

typedef struct {
    char *privatekeyfile;
    char *pvtkey;
    char *selector;
    char *socket;
    char *pidfile;
    mlist *signheaders;
    mlist *signdomains;
    RSA *rsa_private;
    } milter_cfg;


char socket1[300];
int compbl(const void *m1, const void *m2);
int init_milter(const char* cfgfile, milter_cfg * cfg);
void sighandler(int signum);
char * file2str(char* filename);
int domainOf(char *domain, const char *email);
int cmpstr(const void * a, const void * b);
int read_conf(const char* cfgfile, milter_cfg * cfg);
void printf_conf(milter_cfg *cfg);
char * trim_strdup(char * str);
void mlist_read(mlist *ml, char *val, int max);
int md5_b64(char *result_hex, char* input);
int debuglog(char *a,char *b,char *c,char *d);
int concat_h(char *dest , int length_dest, char *src);


int canon_hdr(char *headerf, char *headerv, int headerv_len, char *dest,char *hdr);
struct mlfiPriv {
    char envfrom[MAXIDSIZE];
    char headerdom[MAXDOMSIZE];
    char adom[MAXDOMSIZE];
    int hd;
    char *mailbody;
    short int addheader;
    short int addsignf;
    short int addsigna;
    char header_str[MAXHEADERSIZE];
    char header_list[MAXHEADERSIZE];
    int size;
    int alloc;
    short int debug;

};

#define MLFIPRIV        ((struct mlfiPriv *) smfi_getpriv(ctx))
;
#endif
