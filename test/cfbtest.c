#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
 
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
	printf("%s\n", buf);
}

char enc_key[256/8];
AES_KEY aes_enc_key;

static void init_key(char *key, int key_size)
{
	SHA256(key, key_size, enc_key);
	AES_set_encrypt_key(enc_key, 256, &aes_enc_key);
}

int main(int argc, char **argv) 
{
	const char *str = "blaaaaaaa";
	int str_size = strlen(str) + 1;
	int num;
	unsigned char iv[16];
	unsigned char buf[100];

	init_key("keykey", 6);

	memcpy(buf, str, str_size);
	dump_data(buf, str_size, "1");

	num = 0;
	memset(iv, 0, sizeof(iv));
	AES_cfb8_encrypt(buf, buf, str_size, &aes_enc_key, iv, &num, AES_ENCRYPT);
	dump_data(buf, str_size, "2");

	num = 0;
	memset(iv, 0, sizeof(iv));
	AES_cfb8_encrypt(buf, buf, str_size, &aes_enc_key, iv, &num, AES_DECRYPT);
	dump_data(buf, str_size, "3");
}
