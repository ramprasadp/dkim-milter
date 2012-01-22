/* This file contains all the function calls */
#include "mdef.h"
#include <openssl/md5.h>

/* Initialization function Let us read all the config , the keys etc here. So that we dont have to do any reading when the mail arrives*/
int init_milter(const char* cfgfile, milter_cfg * cfg) {
    FILE *pid;
    openlog("dmilter", LOG_PID | LOG_CONS, LOG_MAIL);
    syslog(LOG_INFO, "Staring dkim_milter");
    // printf("Staring dkim_milter\n");
    if( !read_conf(cfgfile, cfg)){
        syslog(LOG_INFO, "skim milter conf error");
        exit(0);
    }
    //printf_conf(cfg);
    pid = fopen(cfg->pidfile, "w");
    fprintf(pid, "%d\n", getpid());
    fclose(pid);

    return (0);

}


int md5_b64(char *result_hex, char* input) {
  int i;
  unsigned char result[MD5_DIGEST_LENGTH]={0};
  MD5((unsigned char*)input, strlen(input), result);
  for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    sprintf(result_hex + i * 2, "%02x", result[i]);
  return(1);
}


void sighandler(int signum) {
    syslog(LOG_INFO, "SIGINT received. Inside sighandler\n");
    //smfi_stop();
    unlink(socket1);
  //  printf("Stopping dkim_milter\n");
    exit(0);
}

char * file2str(char* filename) {
    char *content=NULL;
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "file %s open/read failed\n", filename);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long int size = ftell(file);

    rewind(file);
    content = (char *) malloc(size + 10);
    fread(content, 1, size, file);
    fclose(file);
    return (content);
}

/* This function finds the domain part of a email id */

int domainOf(char *domain, const char *email) {
    int i = 0;
    char *p;
    p = rindex(email, '@');
    if (!p) {
        /* Oops Not a valid email id */
        domain[0] = '\0';
        return (0);

    }
    p = p + 1;
    while (p[i] && p[i] != '>') {
        domain[i] = p[i];
        if (++i >= MAXDOMSIZE) break;
    }
    domain[i] = '\0';
    return (1);
}

int cmpstr(const void * a, const void * b) {
    //printf("Comparing <%s>,<%s>\n",(char *)a,(char *)b);
    const char **ia = (const char **) a;
    const char **ib = (const char **) b;
    return strcmp(*ia, *ib);
    /* strcmp functions works exactly as expected from
    comparison function */
}

char * trim_strdup(char * str) {
    char c, copy[1000];
    int i = 0, j = 0;
    while (j < 1000 && (c = str[i++])) if (!isspace(c)) copy[j++] = c;
    copy[j] = '\0';
    return (strdup(copy));
}

void mlist_read(mlist *ml, char *val, int max) {
    char *dom;
    char *tmp[MAXSIGNDOMS];
    int i = 0, n;
    dom = strtok(val, ",");
    while (dom != NULL) {
        tmp[i++] = trim_strdup(dom);
        dom = strtok(NULL, ",");
        if (i >= max) {
            syslog(LOG_INFO, "Number of mlist exceeding limit %d\n", max);
        }
    }
    qsort(tmp, i, sizeof (char *), cmpstr);
    n = ml->count = i;
    ml->list = (bl*) malloc(n * sizeof (bl));
    for (i = 0; i < n; i++) {
        ml->list[i].key = tmp[i];
        //     printf("Read %s in %d\n", ml->list[i].key, i);

    }
    //   printf("HARD C P=%p  %s\n", ml, ml->list[0].key);
}

int read_conf(const char* cfgfile, milter_cfg * cfg) {
    FILE *f1;
    char *key, *val, line[1000];
    int found = 0;
    f1 = fopen(cfgfile, "r");
    if (!f1) {
        syslog(LOG_INFO, "Milter could not read config file %s", cfgfile);
        fprintf(stderr, "Milter could not read config file %s\n", cfgfile);
        exit(1);
    }
    while (!feof(f1)) {
       fgets(line, 1000, f1);
        if (feof(f1)) break;
       // printf("Got line --%s\n", line);

        key = strtok(line, "=");
        if (key == NULL) continue;
        val = strtok(NULL, "=");
        if (!val || key[0] == '#') continue;
       // printf("Got KEY=%s,VAL=%s\n", key, val);

        if (strcasecmp(key, "socket") == 0) {
            cfg->socket = trim_strdup(val);
            found++;
            continue;
        }
        if (strcasecmp(key, "keyfile") == 0) {
            cfg->privatekeyfile = trim_strdup(val);
            found++;
            continue;
        }
        if (strcasecmp(key, "pidfile") == 0) {
            cfg->pidfile = trim_strdup(val);
            found++;
            continue;
        }
        if (strcasecmp(key, "selector") == 0) {
            cfg->selector = trim_strdup(val);
            found++;
            continue;
        }
        if (strcasecmp(key, "domains") == 0) {
            cfg->signdomains = malloc(sizeof (mlist));
            mlist_read(cfg->signdomains, val, MAXSIGNDOMS);
            found++;
            continue;
        }

        if (strcasecmp(key, "headers") == 0) {
            cfg->signheaders = malloc(sizeof (mlist));
            mlist_read(cfg->signheaders, val, MAXHDRS);
            found++;
            continue;
        }

    }
    /* Read the private key into a string */
    cfg->pvtkey = file2str(cfg->privatekeyfile);

    return ((found == 6) ? 1 : 0);

}

void printf_conf(milter_cfg *cfg) {
    int i;

    printf("Keyfile = %s\n", cfg->privatekeyfile);
    printf("Socket = %s\n", cfg->socket);
    printf("selector = %s\n", cfg->selector);
    for (i = 0; i < cfg->signdomains->count; i++)
        printf("Domain %d = <%s>\n", i + 1, cfg->signdomains->list[i].key);
    for (i = 0; i < cfg->signheaders->count; i++)
        printf("Header %d = <%s>\n", i + 1, cfg->signheaders->list[i].key);

}

int compbl(const void *m1, const void *m2) {
    bl *mi1 = (bl *) m1;
    bl *mi2 = (bl *) m2;
    return strcmp(mi1->key, mi2->key);
}


