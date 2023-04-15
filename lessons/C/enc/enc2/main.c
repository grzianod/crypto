#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

//int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

//  int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//  int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) EVP_CIPHER_CTX_new();  //define a new context

    unsigned char key[] = "1234567890abcdef";   //16 bytes (ASCII characters)
    unsigned char iv[] = "abcdef1234567890";    //16 bytes (ASCII characters)

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))   //initialize the encipher context specifying all the parameters
        handle_errors();

    unsigned char plaintext[] = "This is an ecnryption sample from the cryptographic course";   //56 bytes
    unsigned char ciphertext[64];

    int length;
    int ciphertext_len=0; //overall size of ciphertext

    if(!EVP_CipherUpdate(ctx, ciphertext, &length, plaintext, strlen(plaintext)))
        handle_errors();
    ciphertext_len += length;

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length))   //finalize operations
        handle_errors();
    ciphertext_len +=length;

    printf("Ciphertext size: %d\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext: ");
    for(int i=0; i<ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
