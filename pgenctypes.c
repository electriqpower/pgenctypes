/*-
 * Copyright (c) 2011.-2012. Ivan Voras
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * An implementation of encrypted data types for PostgreSQL. Data using
 * these types is always encrypted while stored in the database, using
 * the key specified in the per-session variable "xxx".
 *
 * The data is encrypted using AES-256.
 *
 * The types defined are:
 * 	- enctext	- like text
 * 	- encbigint	- like bigint
 * 	- encdouble	- like double
 */

#include <stdlib.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "postgres.h"

#include "fmgr.h"
#include "libpq/pqformat.h"		/* needed for send/recv functions */
#include "access/tuptoaster.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "libpq/md5.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"
#include "parser/scansup.h"
#include "regex/regex.h"
#include "utils/builtins.h"
#include "utils/bytea.h"
#include "utils/lsyscache.h"
#include "utils/pg_locale.h"
#include "utils/guc.h"

#include "pgenctypes.h"

PG_MODULE_MAGIC;
void _PG_init(void);

Datum		enctext_in(PG_FUNCTION_ARGS);
Datum		enctext_out(PG_FUNCTION_ARGS);

Datum		encbigint_in(PG_FUNCTION_ARGS);
Datum		encbigint_out(PG_FUNCTION_ARGS);
Datum		encbigint_to_int8(PG_FUNCTION_ARGS);
Datum		encbigint_from_int8(PG_FUNCTION_ARGS);
Datum		encbigint_to_int4(PG_FUNCTION_ARGS);
Datum		encbigint_from_int4(PG_FUNCTION_ARGS);

Datum		encdouble_in(PG_FUNCTION_ARGS);
Datum		encdouble_out(PG_FUNCTION_ARGS);
Datum		encdouble_to_float8(PG_FUNCTION_ARGS);
Datum		encdouble_from_float8(PG_FUNCTION_ARGS);
Datum		encdouble_to_float4(PG_FUNCTION_ARGS);
Datum		encdouble_from_float4(PG_FUNCTION_ARGS);

Datum		pgenctypes_set_key(PG_FUNCTION_ARGS);

/*
Datum		enctext_abs_lt(PG_FUNCTION_ARGS);
Datum		enctext_abs_le(PG_FUNCTION_ARGS);
Datum		enctext_abs_eq(PG_FUNCTION_ARGS);
Datum		enctext_abs_ge(PG_FUNCTION_ARGS);
Datum		enctext_abs_gt(PG_FUNCTION_ARGS);
Datum		enctext_abs_cmp(PG_FUNCTION_ARGS);
*/

/* Internal utility functions */
#define RESULT_OK 0
#define RESULT_ERROR 1

static int enctext_to_cstring(struct pgenctype_text **in, char **out, unsigned *len);
static int enctypes_decrypt_if_needed(struct pgenctype_block **in);
static int enctypes_encrypt(struct pgenctype_block **in);
static void reset_key(const char *new_key, unsigned new_key_size);
static inline int is_key_set(void);
static Datum enctypes_dump(struct pgenctype_block *in);

static void dump_data(unsigned char *data, unsigned size, char *msg);

PG_FUNCTION_INFO_V1(enctext_in);
/* External string representation to internal. */
Datum
enctext_in(PG_FUNCTION_ARGS)
{
	char *inputText = PG_GETARG_CSTRING(0);
	unsigned len = strlen(inputText);
	struct pgenctype_text *result = (struct pgenctype_text*) palloc(len + sizeof(*result));

	SET_VARSIZE(result, len + sizeof(*result));
	result->header.flags = 0;
	memcpy(result->data, inputText, len);

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


PG_FUNCTION_INFO_V1(enctext_out);
/* Internal representation to external string. */
Datum
enctext_out(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_text *in = (struct pgenctype_text*) PG_DETOAST_DATUM(in_packed);

	if (is_key_set()) {
		unsigned len = VARSIZE_ANY(in) - sizeof(*in);
		char *out = palloc(len + 1);

		enctypes_decrypt_if_needed((struct pgenctype_block**)&in);

		memcpy(out, in->data, len);
		out[len] = '\0';

		return PointerGetDatum(out);
	} else {
		return enctypes_dump((struct pgenctype_block*)in);
	}
}

/* ************************************************************** encbigint */

PG_FUNCTION_INFO_V1(encbigint_in);
/* External textual representation to internal encrypted integer. */
Datum
encbigint_in(PG_FUNCTION_ARGS)
{
	char *inputText = PG_GETARG_CSTRING(0);
	struct pgenctype_bigint *result = (struct pgenctype_bigint*) palloc(sizeof(*result));

	SET_VARSIZE(result, sizeof(*result));
	result->header.flags = 0;
	result->data = strtoll(inputText, NULL, 10);

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


PG_FUNCTION_INFO_V1(encbigint_out);
/* Internal encrypted int representation to external textual representation. */
Datum
encbigint_out(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_bigint *in = (struct pgenctype_bigint*) PG_DETOAST_DATUM(in_packed);

	if (is_key_set()) {
		char strrep[24];
		char *out;

		enctypes_decrypt_if_needed((struct pgenctype_block**)&in);

		if (sprintf(strrep, "%lld", (long long)(in->data)) <= 0)
			ereport(ERROR, 
				(errcode(ERRCODE_INTERNAL_ERROR), 
				 errmsg("asprintf() error")));
		out = pstrdup(strrep);

		return PointerGetDatum(out);
	} else {
		return enctypes_dump((struct pgenctype_block*)in);
	}
}


PG_FUNCTION_INFO_V1(encbigint_to_int8);
/* Cast encbigint to int8 */
Datum
encbigint_to_int8(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_bigint *in = (struct pgenctype_bigint*) PG_DETOAST_DATUM(in_packed);

	enctypes_decrypt_if_needed((struct pgenctype_block**)&in);
	PG_RETURN_INT64(in->data);
}


PG_FUNCTION_INFO_V1(encbigint_from_int8);
/* Cast int8 to encbigint */
Datum
encbigint_from_int8(PG_FUNCTION_ARGS)
{
	int64 arg = PG_GETARG_INT64(0);
	struct pgenctype_bigint *result = (struct pgenctype_bigint*) palloc(sizeof(*result));

	SET_VARSIZE(result, sizeof(*result));
	result->header.flags = 0;
	result->data = arg;

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


PG_FUNCTION_INFO_V1(encbigint_to_int4);
/* Cast encbigint to int4 */
Datum
encbigint_to_int4(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_bigint *in = (struct pgenctype_bigint*) PG_DETOAST_DATUM(in_packed);

	enctypes_decrypt_if_needed((struct pgenctype_block**)&in);
/*
	elog(NOTICE, "decoded: %d", (int)(in->data));
	dump_data(in, VARSIZE_ANY(in), "ebi");
*/
	PG_RETURN_INT32(in->data);
}


PG_FUNCTION_INFO_V1(encbigint_from_int4);
/* Cast int4 to encbigint */
Datum
encbigint_from_int4(PG_FUNCTION_ARGS)
{
	int64 arg = PG_GETARG_INT32(0);
	struct pgenctype_bigint *result = (struct pgenctype_bigint*) palloc(sizeof(*result));

	SET_VARSIZE(result, sizeof(*result));
	result->header.flags = 0;
	result->data = arg;

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


/* ************************************************************** encdouble */


PG_FUNCTION_INFO_V1(encdouble_in);
/* External textual representation to internal encrypted double. */
Datum
encdouble_in(PG_FUNCTION_ARGS)
{
	char *inputText = PG_GETARG_CSTRING(0);
	struct pgenctype_double *result = (struct pgenctype_double*) palloc(sizeof(*result));
	char *end;

	SET_VARSIZE(result, sizeof(*result));
	result->header.flags = 0;
	result->data = strtod(inputText, &end);

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


PG_FUNCTION_INFO_V1(encdouble_out);
/* Internal encrypted double representation to external textual representation. */
Datum
encdouble_out(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_double *in = (struct pgenctype_double*) PG_DETOAST_DATUM(in_packed);

	if (is_key_set()) {
		char *out = palloc(25);

		enctypes_decrypt_if_needed((struct pgenctype_block**)&in);
		snprintf(out, 25, "%.*g", DBL_DIG + extra_float_digits, in->data);

		return PointerGetDatum(out);
	} else {
		return enctypes_dump((struct pgenctype_block*)in);
	}
}



PG_FUNCTION_INFO_V1(encdouble_to_float8);
/* Cast encdouble to float8 */
Datum
encdouble_to_float8(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_double *in = (struct pgenctype_double*) PG_DETOAST_DATUM(in_packed);

	enctypes_decrypt_if_needed((struct pgenctype_block**)&in);
	PG_RETURN_FLOAT8(in->data);
}


PG_FUNCTION_INFO_V1(encdouble_from_float8);
/* Cast float8 to encdouble */
Datum
encdouble_from_float8(PG_FUNCTION_ARGS)
{
	float8 arg = PG_GETARG_FLOAT8(0);
	struct pgenctype_double *result = (struct pgenctype_double*) palloc(sizeof(*result));

	SET_VARSIZE(result, sizeof(*result));
	result->header.flags = 0;
	result->data = arg;

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


PG_FUNCTION_INFO_V1(encdouble_to_float4);
/* Cast encdouble to float4 */
Datum
encdouble_to_float4(PG_FUNCTION_ARGS)
{
	struct varlena *in_packed = (struct varlena*) DatumGetPointer(PG_GETARG_DATUM(0));
	struct pgenctype_double *in = (struct pgenctype_double*) PG_DETOAST_DATUM(in_packed);

	enctypes_decrypt_if_needed((struct pgenctype_block**)&in);
	PG_RETURN_FLOAT4(in->data);
}


PG_FUNCTION_INFO_V1(encdouble_from_float4);
/* Cast float4 to encdouble */
Datum
encdouble_from_float4(PG_FUNCTION_ARGS)
{
	float8 arg = PG_GETARG_FLOAT4(0);
	struct pgenctype_double *result = (struct pgenctype_double*) palloc(sizeof(*result));

	SET_VARSIZE(result, sizeof(*result));
	result->header.flags = 0;
	result->data = arg;

	enctypes_encrypt((struct pgenctype_block**)&result);

	PG_RETURN_POINTER(result);
}


/* ********************************************************* key management */

PG_FUNCTION_INFO_V1(pgenctypes_set_key);
/* Convenience function for setting the key before other operations */
Datum
pgenctypes_set_key(PG_FUNCTION_ARGS)
{
	char *arg = TextDatumGetCString(PG_GETARG_DATUM(0));

	reset_key(arg, strlen(arg));
	PG_RETURN_BOOL(1);
}

/* ****************************************************** utility functions */

static void
dump_data(unsigned char *data, unsigned size, char *msg)
{
	char buf[100];
	unsigned i;

	sprintf(buf, "%s(%u): ", msg, size);
	for (i = 0; i < size; i++) {
		char b2[5];
		sprintf(b2, "%02x ", data[i]);
		strcat(buf, b2);
	}
	strcat(buf, "| ");
	for (i = 0; i < size; i++) {
		char b2[2];
		b2[1] = 0;
		if (data[i] < 32 || data[i] > 127)
			b2[0] = '.';
		else
			b2[0] = data[i];
		strcat(buf, b2);
	}
	elog(NOTICE, "%s", buf);
}

/* Encryption and binary data format engine */

static unsigned char *user_key = NULL;
static unsigned user_key_size = 0;
static unsigned char *enc_key = NULL;
static unsigned char enc_key_size = 0;
static unsigned warning_flags = 0;
AES_KEY aes_enc_key;

#define AES_BITS 256
#define AES_BLOCK 128
#define MIN(a,b) ((a) < (b) ? (a) : (b))


/** Check if the user key is set */
static inline int
is_key_set() {
	return user_key[0] != '\0';
}


/** Initialize crypto keys from the given user key material */
static void
init_crypto()
{
	if (user_key == NULL) {
		elog(ERROR, "pgenctypes: Fatal: user_key is NULL");
		user_key_size = 0;
		return;
	}
	if (!is_key_set()) {
		if ((warning_flags & 1) == 0) {
			elog(WARNING, "pgenctypes: The encryption key is not set.");
			warning_flags |= 1;
		}
	}
	if (enc_key == NULL && user_key != NULL) {
		enc_key_size = AES_BITS / 8;
		enc_key = malloc(enc_key_size);
		SHA256(user_key, user_key_size, enc_key);
		AES_set_encrypt_key(enc_key, AES_BITS, &aes_enc_key);
	}
}


static int
enctext_to_cstring(struct pgenctype_text **in, char **out, unsigned *len)
{
	unsigned data_size = VARSIZE_ANY(*in) - sizeof(**in);

	if ((*in)->header.flags != 0)
		return RESULT_ERROR;

	memcpy(out, (*in)->data, data_size);
	*len = data_size;
	return RESULT_OK;
}


static void
enctext_to_iv(struct pgenctype_block *in, unsigned char *iv)
{
	memcpy(iv, in, VARHDRSZ);
	memcpy(iv + VARHDRSZ, in->iv, sizeof(in->iv));
	memset(iv + VARHDRSZ + sizeof(in->iv), 0, AES_BLOCK / 8 - (VARHDRSZ + sizeof(in->iv)));
}


/** Decryptes a pgenctype_text */
static int
enctypes_decrypt_if_needed(struct pgenctype_block **in)
{
	unsigned data_size = VARSIZE_ANY(*in) - sizeof(**in);
	unsigned char iv[AES_BLOCK / 8];
	int num = 0;

	enctext_to_iv(*in, iv);

	if ((*in)->flags & PGENCTYPE_FLAG_AES) {
		struct pgenctype_block *out = palloc(VARSIZE_ANY(*in));
		memcpy(out, *in, sizeof(*out));

		init_crypto();
		AES_cfb128_encrypt((*in)->data, out->data, data_size, &aes_enc_key, iv, &num, 0); /* Decrypt */
		out->flags &= ~PGENCTYPE_FLAG_AES;
		*in = out;
	}
	if ((*in)->flags & PGENCTYPE_FLAG_LZF) {
	}

	return RESULT_OK;
}


/** Encrypts a pgenctype_text */
static int
enctypes_encrypt(struct pgenctype_block **in)
{
	unsigned data_size = VARSIZE_ANY(*in) - sizeof(**in);
	unsigned char iv[AES_BLOCK / 8];
	int num = 0;

	if ((*in)->flags & PGENCTYPE_FLAG_AES)
		return RESULT_ERROR;

	RAND_bytes((*in)->iv, sizeof((*in)->iv));
	enctext_to_iv(*in, iv);

	init_crypto();
	AES_cfb128_encrypt((*in)->data, (*in)->data, data_size, &aes_enc_key, iv, &num, 1);	/* Encrypt */
	(*in)->flags |= PGENCTYPE_FLAG_AES;
	(*in)->unpacked_size = 0;

	return RESULT_OK;
}


static Datum
enctypes_dump(struct pgenctype_block *in)
{
	char *out = palloc(VARSIZE_ANY(in) * 2 + 1);
	char *po = out;
	unsigned char *d = (unsigned char*) in;
	int i;

	for (i = 0; i < VARSIZE_ANY(in); i++) {
		unsigned b = (*d) >> 4;
		*(po++) = b > 9 ? b + 0x37 + 0x20 : b + 0x30;
		b = (*d++) & 0x0f;
		*(po++) = b > 9 ? b + 0x37 + 0x20 : b + 0x30;
	}
	(*po) = '\0';

	return PointerGetDatum(out);
}


/** Resets the encryption key from the user's key material */
static void
reset_key(const char *new_key, unsigned new_key_size)
{
	if (new_key != NULL) {
		if (user_key != NULL)
			free(user_key);
		user_key = (unsigned char*) strdup(new_key);
		user_key_size = new_key_size;
	}
	if (enc_key != NULL) {
		free(enc_key);
		enc_key = NULL;
		enc_key_size = 0;
	}
}

/**
 * user_key change hook.
 */
static void
user_key_assign_hook(const char *new_key, void *extra)
{
	reset_key(new_key, strlen(new_key));
}


/**
 * Module bootstrap.
 */
void
_PG_init()
{
	DefineCustomStringVariable(
		"pgenctypes.key",
		"Plain text encryption key for encrypted data types",
		NULL,
		(char**) &user_key,
		"",
		PGC_USERSET,
		0,
		NULL,
		user_key_assign_hook,
		NULL
	);
/*	set_config_option("pgenctypes.key", "tk2",
					  PGC_USERSET,
					  PGC_S_SESSION,
					  GUC_ACTION_SET,
					  true);*/
}

