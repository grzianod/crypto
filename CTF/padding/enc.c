#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>


#define ENCRYPT 1
#define DECRYPT 0

int main()
{
    unsigned char key_string[] = "0123456789ABCDEF0123456789ABCDEF";
    unsigned char iv_string[]  = "11111111111111111111111111111111";

    unsigned char key[strlen(key_string)/2];
    for(int i=0; i<strlen(key_string)/2; i++)
        sscanf(&(key_string[2*i]), "%2hhx", &(key[i]));

    unsigned char iv[strlen(iv_string)/2];
    for(int i=0; i<strlen(iv_string)/2; i++)
        sscanf(&(iv_string[2*i]), "%2hhx", &(iv[i]));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT);    //16 bytes-block


    unsigned char plaintext[] = "This is the plaintext to encrypt"; //length 32 (must be a multiple of 16 since no padding should be added!)
    unsigned char ciphertext[48];

    int update_len, final_len;
    int ciphertext_len=0;

    EVP_CipherUpdate(ctx,ciphertext,&update_len,plaintext,strlen(plaintext));
    ciphertext_len+=update_len;

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}

