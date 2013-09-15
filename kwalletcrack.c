/* KDE KWallet brute forcer.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <gcrypt.h>
#include "common.h"
#include <openssl/sha.h>
#include <openssl/blowfish.h>

#define KWMAGIC "KWALLET\n\r\0\r\n"
#define KWMAGIC_LEN 12

#define KWALLET_VERSION_MAJOR           0
#define KWALLET_VERSION_MINOR           0

#define KWALLET_CIPHER_BLOWFISH_CBC     0
#define KWALLET_CIPHER_3DES_CBC         1	// unsupported

#define KWALLET_HASH_SHA1               0
#define KWALLET_HASH_MD5                1	// unsupported
#define N 128

static int count;
static unsigned char encrypted[0x10000];
static unsigned char buffer[0x10000];
static long encrypted_size;


/* helper functions for byte order conversions, header values are stored
 * in big-endian byte order */
static uint32_t fget32_(FILE * fp)
{
	uint32_t v = fgetc(fp) << 24;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 8;
	v |= fgetc(fp);
	return v;
}

#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}
#endif

#define MIN(x,y) ((x) < (y) ? (x) : (y))
static void password2hash(const char *password, unsigned char *hash, int *key_size)
{
	SHA_CTX ctx;
	unsigned char output[20 * 4];
	unsigned char buf[20];
	int i, j, oindex = 0;
	int plength = strlen(password);

	// divide the password into blocks of size 16 and hash the resulting
	// individually!
	for (i = 0; i <= plength; i += 16) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, password + i, MIN(plength - i, 16));
		// To make brute force take longer
		for (j = 0; j < 2000; j++) {
			SHA1_Final(buf, &ctx);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, buf, 20);
		}
		memcpy(output + oindex, buf, 20);
		oindex += 20;
	}

	if (plength < 16) {
		// key size is 20
		memcpy(hash, output, 20);
		*key_size = 20;
	}
	else if (plength < 32) {
		// key size is 40 (20/20)
		memcpy(hash, output, 40);
		*key_size = 40;
	}
	else if (plength < 48) {
		// key size is 56 (20/20/16 split)
		memcpy(hash, output, 56);
		*key_size = 56;
	}
	else {
		// key size is 56 (14/14/14 split)
		memcpy(hash + 14 * 0, output +  0, 14);
		memcpy(hash + 14 * 1, output + 20, 14);
		memcpy(hash + 14 * 2, output + 40, 14);
		*key_size = 56;
	}
}

static void process_file(const char *fname)
{
	FILE *fp;
	unsigned char buf[1024];
	int offset = 0;
	size_t i, j;
	long size;
	if (!(fp = fopen(fname, "rb"))) {
		fprintf(stderr, "%s : %s\n", fname, strerror(errno));
		return;
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	count = fread(buf, KWMAGIC_LEN, 1, fp);
	if (memcmp(buf, KWMAGIC, KWMAGIC_LEN) != 0) {
		fprintf(stderr, "%s : Not a KDE KWallet file!\n", fname);
		exit(1);
	}
	assert(count == 1);
	offset += KWMAGIC_LEN;
	count = fread(buf, 4, 1, fp);
	assert(count == 1);
	offset += 4;

	// First byte is major version, second byte is minor version
	if (buf[0] != KWALLET_VERSION_MAJOR) {
		// unknown version
		fprintf(stderr, "%s : Unknown version!\n", fname);
		exit(2);
	}

	if (buf[1] != KWALLET_VERSION_MINOR) {
		// unknown version
		fprintf(stderr, "%s : Unknown version!\n", fname);
		exit(3);
	}

	if (buf[2] != KWALLET_CIPHER_BLOWFISH_CBC) {
		// unknown cipher
		fprintf(stderr, "%s : Unsupported cipher\n", fname);
		exit(4);
	}

	if (buf[3] != KWALLET_HASH_SHA1) {
		// unknown hash
		fprintf(stderr, "%s : Unsupported hash\n", fname);
		exit(5);
	}
	// Read in the hashes
	uint32_t n = fget32_(fp);
	if (n > 0xffff) {	// sanity check
		fprintf(stderr, "%s : sanity check failed!\n", fname);
		exit(6);
	}
	offset += 4;
	for (i = 0; i < n; ++i) {
		count = fread(buf, 16, 1, fp);
		assert(count == 1);
		offset += 16;
		uint32_t fsz = fget32_(fp);
		offset += 4;
		for (j = 0; j < fsz; ++j) {
			count = fread(buf, 16, 1, fp);
			assert(count == 1);
			offset += 16;

		}
	}
	// Read in the rest of the file.
	encrypted_size = size - offset;
	count = fread(encrypted, encrypted_size, 1, fp);
	assert(count == 1);
	if ((encrypted_size % 8) != 0) {
		// invalid file structure
		fprintf(stderr, "%s : invalid file structure!\n", fname);
		exit(7);
	}
}


int verify_passphrase(char *passphrase)
{
	unsigned char key[56]; /* 56 seems to be the max. key size */
	SHA_CTX ctx;
	BF_KEY bf_key;
	int sz;
	int i;
	int key_size = 0;
	unsigned char testhash[20];
	const char *t;
	long fsize;
	password2hash(passphrase, key, &key_size);
	memcpy(buffer, encrypted, encrypted_size);

	/* Blowfish implementation in KWallet is wrong w.r.t endianness
	 * Well, that is why we had bad_blowfish_plug.c originally ;) */
	alter_endianity(buffer, encrypted_size);
	/* decryption stuff */
	BF_set_key(&bf_key, key_size, key);
	for(i = 0; i < encrypted_size; i += 8) {
		BF_ecb_encrypt(buffer + i, buffer + i, &bf_key, 0);
	}
	alter_endianity(buffer, encrypted_size);

	/* verification stuff */
	t = (char *) buffer;

	// strip the leading data
	t += 8;	// one block of random data

	// strip the file size off
	fsize = 0;
	fsize |= ((long) (*t) << 24) & 0xff000000;
	t++;
	fsize |= ((long) (*t) << 16) & 0x00ff0000;
	t++;
	fsize |= ((long) (*t) << 8) & 0x0000ff00;
	t++;
	fsize |= (long) (*t) & 0x000000ff;
	t++;
	if (fsize < 0 || fsize > (long) (encrypted_size) - 8 - 4) {
		// file structure error
		return -1;
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, t, fsize);
	SHA1_Final(testhash, &ctx);
	// compare hashes
	sz = encrypted_size;
	for (i = 0; i < 20; i++) {
		if (testhash[i] != buffer[sz - 20 + i]) {
			return -2;
		}
	}
	return 0;
}


int main(int argc, char **argv)
{
	int l, r;
	char passphrase[N];
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <.kwl file>\n", argv[0]);
		exit(-1);
	}
	process_file(argv[1]);

	while (fgets(passphrase, N, stdin) != NULL) {
		l = strlen(passphrase);
		passphrase[l - 1] = 0;
		r = verify_passphrase(passphrase);
		if (r == 0) {
			printf("Password Found : %s\n", passphrase);
			exit(0);
		}
	}
	return 0;
}
