#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

#define ENCRYPT 1

int main() {

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) EVP_CIPHER_CTX_new();  //define a new context

    unsigned char key[] = "1234567890abcdef";   //16 bytes (ASCII characters)
    unsigned char iv[] = "abcdef1234567890";    //16 bytes (ASCII characters)

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);   //initialize the encipher context specifying all the parameters

    unsigned char plaintext[] = "This is an ecnryption sample from the cryptographic course";   //56 bytes
    unsigned char ciphertext[64];

    int length;
    int ciphertext_len=0; //overall size of ciphertext

    EVP_CipherUpdate(ctx, ciphertext, &length, plaintext, strlen(plaintext));
    ciphertext_len += length;

    EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length);   //finalize operations
    ciphertext_len +=length;

    printf("Ciphertext size: %d\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext: ");
    for(int i=0; i<ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
