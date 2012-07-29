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
#include <openssl/sha.h>
#include "blowfish.h"
#include "cbc.h"

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
static int password2hash(const char *password, unsigned char *hash)
{
	SHA_CTX ctx;
	unsigned char block1[20] = { 0 };
	int i;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password, MIN(strlen(password), 16));
	// To make brute force take longer
	for (i = 0; i < 2000; i++) {
		SHA1_Final(block1, &ctx);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, block1, 20);
	}
	memcpy(hash, block1, 20);

	/*if (password.size() > 16) {

	   sha.process(password.data() + 16, qMin(password.size() - 16, 16));
	   QByteArray block2(shasz, 0);
	   // To make brute force take longer
	   for (int i = 0; i < 2000; i++) {
	   memcpy(block2.data(), sha.hash(), shasz);
	   sha.reset();
	   sha.process(block2.data(), shasz);
	   }

	   sha.reset();

	   if (password.size() > 32) {
	   sha.process(password.data() + 32, qMin(password.size() - 32, 16));

	   QByteArray block3(shasz, 0);
	   // To make brute force take longer
	   for (int i = 0; i < 2000; i++) {
	   memcpy(block3.data(), sha.hash(), shasz);
	   sha.reset();
	   sha.process(block3.data(), shasz);
	   }

	   sha.reset();

	   if (password.size() > 48) {
	   sha.process(password.data() + 48, password.size() - 48);

	   QByteArray block4(shasz, 0);
	   // To make brute force take longer
	   for (int i = 0; i < 2000; i++) {
	   memcpy(block4.data(), sha.hash(), shasz);
	   sha.reset();
	   sha.process(block4.data(), shasz);
	   }

	   sha.reset();
	   // split 14/14/14/14
	   hash.resize(56);
	   memcpy(hash.data(),      block1.data(), 14);
	   memcpy(hash.data() + 14, block2.data(), 14);
	   memcpy(hash.data() + 28, block3.data(), 14);
	   memcpy(hash.data() + 42, block4.data(), 14);
	   block4.fill(0);
	   } else {
	   // split 20/20/16
	   hash.resize(56);
	   memcpy(hash.data(),      block1.data(), 20);
	   memcpy(hash.data() + 20, block2.data(), 20);
	   memcpy(hash.data() + 40, block3.data(), 16);
	   }
	   block3.fill(0);
	   } else {
	   // split 20/20
	   hash.resize(40);
	   memcpy(hash.data(),      block1.data(), 20);
	   memcpy(hash.data() + 20, block2.data(), 20);
	   }
	   block2.fill(0);
	   } else {
	   // entirely block1
	   hash.resize(20);
	   memcpy(hash.data(), block1.data(), 20);
	   }

	   block1.fill(0); */
	return 0;
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
	unsigned char key[20];
	password2hash(passphrase, key);
	SHA_CTX ctx;
	BlowFish _bf;
	int sz;
	int i;
	unsigned char testhash[20];
	CipherBlockChain bf(&_bf);
	bf.setKey((void *) key, 20 * 8);
	memcpy(buffer, encrypted, encrypted_size);
	bf.decrypt(buffer, encrypted_size);
	const char *t = (char *) buffer;

	// strip the leading data
	t += 8;	// one block of random data

	// strip the file size off

	long fsize = 0;
	fsize |= (long (*t) << 24) &0xff000000;
	t++;
	fsize |= (long (*t) << 16) &0x00ff0000;
	t++;
	fsize |= (long (*t) << 8) &0x0000ff00;
	t++;
	fsize |= long (*t) & 0x000000ff;
	t++;
	if (fsize < 0 || fsize > long (encrypted_size) - 8 - 4) {
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
