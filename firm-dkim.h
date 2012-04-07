
#ifndef _FIRM_DKIM_H_
#define _FIRM_DKIM_H_

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/sha.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/err.h>


typedef struct {
	char *key;
	char *value;
} stringpair;

char *dkim_create(stringpair **headers, int headerc, char *body, char *pkey, char *domain, char *selector, int v);
char *dkim_signature(char *hstr, char *header_list, char *body, RSA *rsa_private, char *domain, char *selector,int v);
int rsa_read_pem(RSA **rsa, char *buff, int len);
#endif
