/* This is the milter  that will be used for dkim signature addition into mail
 *
 * Based on dkim-milter but that code is largely inefficient. 
 * I am writing this code just with the objective of performance 
 *  Ram <ram@netcore.co.in> 17-Nov-2011
 *  Currently just a blank milter .. I want to see the performance a blank milter
 */

#include "mdef.h"
#include "firm-dkim.h"


milter_cfg *dkim_cfg;

void free_priv(SMFICTX *ctx) {
    struct mlfiPriv *priv = MLFIPRIV;
    if (!priv) return;
    free(priv->mailbody);
    free(priv);
    smfi_setpriv(ctx, NULL);

}

sfsistat mlfi_cleanup(SMFICTX *ctx, bool ok) {
    free_priv(ctx);
    return SMFIS_ACCEPT;
}

sfsistat mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
    return SMFIS_CONTINUE;
}

sfsistat mlfi_envfrom(SMFICTX *ctx, char **envfrom) {
    struct mlfiPriv *priv = NULL;
    int l = 0;
    // syslog(LOG_INFO, "Creating a priv object queueid=<%s> from=<%s>", smfi_getsymval(ctx, "i"), envfrom[0]);
    priv = (struct mlfiPriv *) malloc(sizeof *priv);
    if (!priv) {
        /* can't accept this message right now */
        return SMFIS_ACCEPT;
    }
    if (envfrom[0]) l = strlen(envfrom[0]);
    if (l > 3 && l < MAXIDSIZE) {
        strcpy(priv->envfrom, envfrom[0]);
    } else {
        syslog(LOG_INFO, "Skipping Mail with bad-envfrom length %d", l);
        free(priv);
        return SMFIS_ACCEPT;

    }
    priv->debug = 0;
#ifdef DEBUG
    if (strstr(envfrom[0], "debugid") != NULL) {
        priv->debug = 1;
    }
#endif
    priv->hd = 0;
    priv->addheader = 0;
    priv->addsignf = 0;
    priv->addsigna = 0;

    //  priv->mailbody = (char *) calloc(BODYSIZE,sizeof(char));
    priv->mailbody = (char *) malloc(BODYSIZE);
    priv->mailbody[0] = 0;
    priv->header_str[0] = 0;
    priv->header_list[0] = 0;
    priv->size = 0;
    priv->alloc = BODYSIZE - 10;
    smfi_setpriv(ctx, priv);
    return SMFIS_CONTINUE;

}

sfsistat mlfi_header(SMFICTX *ctx, char *headerf, char *headerv) {
    int len, n = MLFIPRIV->hd;
    bl tmp;
    char canon_h[MAXSINGLEHDR], lc_headerf[50];


    /* Make sure we have a valid header value */
    if (!(headerv)) return SMFIS_CONTINUE;

    /* Let us compute the header length will be useful later too*/
    len = strlen(headerv);
    if (len < 3 || len >= MAXSINGLEVAL) return SMFIS_CONTINUE; /* Just a little security */

    if (0 == strcmp(DKIMHDR, headerf)) {
        syslog(LOG_INFO, "Mail from=<%s> is already signed skipping", MLFIPRIV->envfrom);
        return mlfi_cleanup(ctx, false);
    }

    if ((0 == strcmp(headerf, ABUSE_HDR))
            && (0 == MLFIPRIV->addsigna) &&
            (0 == strcmp(headerv, ABUSE_HDR_VAL))) {
        //  syslog(LOG_INFO, "Mail from=<%s> has Abuse header ", MLFIPRIV->envfrom);
        MLFIPRIV->addsigna = 1;
        smfi_setpriv(ctx, MLFIPRIV);
        return SMFIS_CONTINUE;
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

    /* Canonicalize the header and add to the header_str*/
    canon_hdr(headerf, headerv, len, canon_h, lc_headerf);
    strcat(MLFIPRIV->header_str, canon_h);
    strcat(MLFIPRIV->header_list, lc_headerf);
    // syslog(LOG_INFO, "GOt headers %s %s num=%d", headerf, headerv, MLFIPRIV->hd);
    MLFIPRIV->hd = n + 1;

    smfi_setpriv(ctx, MLFIPRIV);
    return SMFIS_CONTINUE;
}

sfsistat mlfi_eoh(SMFICTX *ctx) {

    if (MLFIPRIV->addsignf == 0 && MLFIPRIV->addsigna == 0) {
        MLFIPRIV->addheader = 1;
        syslog(LOG_INFO, "%s Adding abuse header", MLFIPRIV->envfrom);
        smfi_setpriv(ctx, MLFIPRIV);
    }

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
    char *dkim = dkim_signature(
            MLFIPRIV->header_str,
            MLFIPRIV->header_list,
            MLFIPRIV->mailbody, dkim_cfg->rsa_private,
            (MLFIPRIV->addsignf == 1) ? MLFIPRIV->headerdom : DSIGNDOM,
            dkim_cfg->selector,
            MLFIPRIV->debug);
#ifdef DEBUG
    if (MLFIPRIV->debug) {
        debuglog(MLFIPRIV->envfrom, MLFIPRIV->header_str, dkim, "N");
    }
#endif

    syslog(LOG_INFO, "Adding signature Mail From %s", MLFIPRIV->envfrom);
    smfi_addheader(ctx, DKIMHDR, dkim);
    if (MLFIPRIV->addheader) smfi_addheader(ctx, ABUSE_HDR, ABUSE_HDR_VAL);

    free(dkim);

    //smfi_replacebody(ctx, (unsigned char *) MLFIPRIV->mailbody, MLFIPRIV->size + 14);
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
    mlfi_connect, /* connection info filter */
    NULL, /* SMTP HELO command filter */
    mlfi_envfrom, /* envelope sender filter */
    NULL, /* envelope recipient filter */
    mlfi_header, /* header filter */
    mlfi_eoh, /* end of header */
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
