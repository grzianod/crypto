#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>


#define ENCRYPT 1
#define DECRYPT 0

int main()
{

//int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

//  int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//  int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

    unsigned char key_string[] = "0123456789abcdef0123456789abcdef";
    unsigned char iv_string[]  = "11111111111111112222222222222222";
    unsigned char ciphertext_hex[] = "c47c3d88f142d8295e6993a74df2cf2aa1d3caa0d535f3a863461bfce34e94fc";

    unsigned char key[strlen(key_string)/2];
    unsigned char iv[strlen(iv_string)/2];

    for(int i=0; i<strlen(key_string)/2; i++) {
        sscanf(&(key_string[2*i]), "%2hhx", &(key[i]));
        sscanf(&(iv_string[2*i]), "%2hhx", &(iv[i]));
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_aria_128_cbc(), key, iv, DECRYPT);
    
    // convert hexstring into bytes
    int ciphertext_len = strlen(ciphertext_hex)/2;
    unsigned char ciphertext_binary[ciphertext_len];
    for(int i = 0; i < ciphertext_len;i++){
        sscanf(&ciphertext_hex[2*i], "%2hhx", &ciphertext_binary[i]);
    }

    unsigned char decrypted[ciphertext_len]; //may be larger than needed due to padding

    int update_len, final_len;
    int decrypted_len=0;
    EVP_CipherUpdate(ctx,decrypted,&update_len,ciphertext_binary,ciphertext_len);
    decrypted_len+=update_len;

    EVP_CipherFinal_ex(ctx,decrypted+decrypted_len,&final_len);
    decrypted_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    for(int i = 0; i < decrypted_len; i++)
        printf("%c", decrypted[i]);
    printf("\n");

    return 0;
}

