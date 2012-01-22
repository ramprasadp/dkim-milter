/*This is the dkim library from http://code.google.com/p/firm-dkim
 * Please check the documentation from firm-dkim directly
 *
 *
 */
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

#endif
