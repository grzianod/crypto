#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>


#define ENCRYPT 1
#define DECRYPT 0

//int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

//  int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//  int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int main() {

    unsigned char key[] = "1234567890abcdef";
    unsigned char iv[]  = "abcdef1234567890";
    unsigned char ciphertext_hex[] = "fd7690b89b624bef09221f14797abbed600ece075027fe8abf8960c53180ed4f6b5625de02e61f536d0dc1ebdabf4d5c62694a58e161fae881098eeb6348e7ba";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, DECRYPT);

    // convert hexstring into bytes
    int ciphertext_len = strlen(ciphertext_hex)/2;

    unsigned char ciphertext_binary[ciphertext_len];
    for(int i = 0; i < ciphertext_len;i++){
        sscanf(&ciphertext_hex[2*i],"%2hhx", &ciphertext_binary[i]);
    }

    printf("Binary ciphertext: ");
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext_binary[i]);
    printf("\n");


    unsigned char decrypted[ciphertext_len]; //may be larger than needed due to padding

    int tmp_len;
    int decrypted_len=0;

    EVP_CipherUpdate(ctx,decrypted,&tmp_len,ciphertext_binary,ciphertext_len);
    decrypted_len+=tmp_len;

    EVP_CipherFinal_ex(ctx,decrypted+decrypted_len,&tmp_len);
    decrypted_len+=tmp_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Plaintext size: %d\n",decrypted_len);
    printf("Plaintext binary: ");
    for(int i = 0; i < decrypted_len; i++)
        printf("%2x", decrypted[i]);

    printf("\nPlaintext: ");
    for(int i = 0; i < decrypted_len; i++)
        printf("%c", decrypted[i]);
    printf("\n");

    return 0;
}

