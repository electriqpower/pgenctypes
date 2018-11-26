/*-
 * Copyright (c) 2011. Ivan Voras
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

#ifndef _PGENCTYPES_H_
#define _PGENCTYPES_H_

#include <stdint.h>


#define	PGENCTYPE_FLAG_AES	0x01
#define PGENCTYPE_FLAG_LZF	0x80

/**
 * The basic header structure describing encrypted data. Unfortunately,
 * a large IV would drastically increase the storage space needed for
 * enctext, so the actual IV is only 64 bits. Fortunately, we can use
 * other fields from the structure (varlena_size) to extend the IV a bit.
 */
struct pgenctype_block {
	char			varlena_size[VARHDRSZ];
	unsigned int		flags :8;
	unsigned int		unpacked_size :24;
	unsigned char		iv[8];
	unsigned char		data[];
} __packed;


/**
 * Encrypted text datum.
 */
struct pgenctype_text {
	struct pgenctype_block	header;
	unsigned char		data[];
} __packed;


/**
 * Encrypted int8 datum.
 */
struct pgenctype_bigint {
	struct pgenctype_block	header;
	int64_t			data;
} __packed;


/**
 * Encrypted double datum.
 */
struct pgenctype_double {
	struct pgenctype_block	header;
	double			data;
} __packed;

#endif
