#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0

int main() {

    EVP_CIPHER_CTX *ctx = EVP_CIPHERCTX_new();  //define a new context

    unsigned char key[] = "1234567890abcdef";   //16 bytes (ASCII characters)
    unsigned char iv[] = "abcdef1234567890";    //16 bytes (ASCII characters)

    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);   //initialize the encipher context specifying all the parameters

    unsigned char plaintext[] = "This variable contains data to encrypt";   //38 bytes
    unsigned char ciphertext[48];

    int length;
    int ciphertext_len; //overall size of ciphertext
    EVP_CipherUpdate(ctx, ciphertext, &length, plaintext, strlen(plaintext));

    printf("After update: %d\n", length);
    ciphertext_len += length;
    EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length);   //finalize operations
    printf("After final: %d\n", length);

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext = %d\n", ciphertext_len);
    for(int i=0; i<ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
