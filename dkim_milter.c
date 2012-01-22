/* This is the milter  that will be used for dkim signature addition into mail
 *
 * Based on dkim-milter but that code is largely inefficient. 
 * I am writing this code just with the objective of performance 
 *  Ram <ram@netcore.co.in> 17-Nov-2011
 *
 * Please send feedback to me directly 
 *
 *
 */

#include "mdef.h"
#include "firm-dkim.h"

extern char socket1[300];
int headersize;

milter_cfg *dkim_cfg;

void free_priv(SMFICTX *ctx) {
    int i;
    stringpair **headers;
    struct mlfiPriv *priv = MLFIPRIV;
    if (!priv) return;

    headers = priv->headers;
    for (i = 0; i < priv->hd; ++i) {
        // syslog(LOG_INFO,"Freeing %s %s %d of %d" ,headers[i]->key,headers[i]->value,i,priv->hd);
        free(headers[i]->key);
        free(headers[i]->value);
        free(headers[i]);
    }
    free(headers);
    free(priv->mailbody);
    free(priv);
    smfi_setpriv(ctx, NULL);

}

sfsistat mlfi_cleanup(SMFICTX *ctx, bool ok) {
    free_priv(ctx);
    return SMFIS_ACCEPT;
}

sfsistat mlfi_envfrom(SMFICTX *ctx, char **envfrom) {
    struct mlfiPriv *priv = NULL;
   // syslog(LOG_INFO, "Creating a priv object queueid=<%s> from=<%s>", smfi_getsymval(ctx, "i"), envfrom[0]);
    priv = (struct mlfiPriv *) malloc(sizeof *priv);
    if (!priv) {
        /* can't accept this message right now */
        return SMFIS_ACCEPT;
    }
    strncpy(priv->envfrom, envfrom[0], MAXIDSIZE - 1);
    priv->hd = 0;

    priv->addsignf = 0;


    priv->headers = (stringpair **) malloc(headersize);
    //  priv->mailbody = (char *) calloc(BODYSIZE,sizeof(char));
    priv->mailbody = (char *) malloc(BODYSIZE);
    priv->mailbody[0] = 0;

    priv->size = 0;
    priv->alloc = BODYSIZE - 10;
    smfi_setpriv(ctx, priv);
    return SMFIS_CONTINUE;

}

sfsistat mlfi_header(SMFICTX *ctx, char *headerf, char *headerv) {
    int n = MLFIPRIV->hd;
    bl tmp;
    stringpair *st;
    if (0 == strcmp(DKIMHDR, headerf)) {
        syslog(LOG_INFO, "Mail from=<%s> is already signed skipping", MLFIPRIV->envfrom);
        return mlfi_cleanup(ctx, false);
    }
    tmp.key = headerf;
    if (!bsearch(&tmp, dkim_cfg->signheaders->list, dkim_cfg->signheaders->count, sizeof (bl), compbl))
        return SMFIS_CONTINUE;

    if (0 == strcmp(headerf, "From")) {
        domainOf(MLFIPRIV->headerdom, headerv);
        tmp.key = MLFIPRIV->headerdom;
        if (bsearch(&tmp, dkim_cfg->signdomains->list, dkim_cfg->signdomains->count, sizeof (bl), compbl)) {
           // syslog(LOG_INFO, "From domain %s In SIGNLIST", tmp.key);
            MLFIPRIV->addsignf = 1;
        }
    }

    st = malloc(sizeof (stringpair));
    st->key = strdup(headerf);
    st->value = strdup(headerv);
    MLFIPRIV->headers[n] = st;
    // syslog(LOG_INFO, "GOt headers %s %s num=%d", headerf, headerv, MLFIPRIV->hd);
    MLFIPRIV->hd = n + 1;

    smfi_setpriv(ctx, MLFIPRIV);

    return SMFIS_CONTINUE;
}

sfsistat mlfi_body(SMFICTX *ctx, u_char *bodyp, size_t bodylen) {
    if (MLFIPRIV->size + bodylen > MLFIPRIV->alloc) {
        /* Need to allocate more memory for body string*/
        MLFIPRIV->alloc = MLFIPRIV->alloc + bodylen;
        MLFIPRIV->mailbody = realloc(MLFIPRIV->mailbody, MLFIPRIV->alloc);
        // syslog(LOG_INFO, "Reallocating memory for body %s", smfi_getsymval(ctx, "i"));
    }

    strncat(MLFIPRIV->mailbody, (char *) bodyp, bodylen);
    MLFIPRIV->size += bodylen;

    return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX *ctx) {
  char *dkim;
  if(MLFIPRIV->addsignf == 1){
    dkim = dkim_create(MLFIPRIV->headers, MLFIPRIV->hd,
		       MLFIPRIV->mailbody, dkim_cfg->pvtkey, 
		       MLFIPRIV->headerdom,
		       dkim_cfg->selector,
		       0);
    
    syslog(LOG_INFO,"Adding signature Mail From %s",MLFIPRIV->envfrom);
    smfi_addheader(ctx, DKIMHDR, dkim);
    free(dkim);
  }

  return mlfi_cleanup(ctx, false);
}

  sfsistat mlfi_close(SMFICTX *ctx) {

    return mlfi_cleanup(ctx, false);
}

sfsistat mlfi_abort(SMFICTX *ctx) {
    return mlfi_cleanup(ctx, false);
}


struct smfiDesc smfilter = {
    "NC DKIM filter", /* filter name */
    SMFI_VERSION, /* version code -- do not change */
    SMFIF_ADDHDRS, /* flags */
    NULL, /* connection info filter */
    NULL, /* SMTP HELO command filter */
    mlfi_envfrom, /* envelope sender filter */
    NULL, /* envelope recipient filter */
    mlfi_header, /* header filter */
    NULL, /* end of header */
    mlfi_body, /* body block filter */
    mlfi_eom, /* end of message */
    mlfi_abort, /* message aborted */
    mlfi_close /* connection cleanup */
};

int
main(argc, argv)
int argc;
char *argv[];
{
    bool setconn = false;
    if (argv[2] == NULL && fork()) exit(0);
    dkim_cfg = malloc(sizeof (milter_cfg));
    init_milter(argv[1], dkim_cfg);

    // printf("Connecting to %s\n", dkim_cfg->socket);
    (void) smfi_setconn(dkim_cfg->socket);
    setconn = true;
    headersize = dkim_cfg->signheaders->count * sizeof (stringpair);
    //   printf("Header size = %d for %d\n", headersize, dkim_cfg->signheaders->count);
    if (!setconn) {
        fprintf(stderr, "%s: Missing required argument\n", argv[0]);
        exit(EX_USAGE);
    }
    if (smfi_register(smfilter) == MI_FAILURE) {
        fprintf(stderr, "smfi_register failed\n");
        exit(EX_UNAVAILABLE);
    }
    return smfi_main();
}

/* eof */
