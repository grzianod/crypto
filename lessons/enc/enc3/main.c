#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAXSIZE 1024

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


//argv[1] -> input file
//argv[2] -> key    (hexstring)
//argv[3] -> iv     (hexstring)
//save in a buffer in memory the result of encryption

int main(int argc, char **argv) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc!= 4) {
        fprintf(stderr, "Invalid parameters.\nUsage: %s input_file key IV\n\n", argv[0]);
        exit(1);
    }

    FILE *fp;
    if((fp=fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the file. Check that the file exists!");
        exit(2);
    }

    if(strlen(argv[2]) != 32) {
        fprintf(stderr, "Wrong key length: %s\n", argv[2]);
        exit(3);
    }

    unsigned char key[strlen(argv[2])/2];
    for(int i=0; i<strlen(argv[2])/2; i++)
        sscanf(&(argv[2][2*i]), "%2hhx", &(key[i]));

    if(strlen(argv[3]) != 32) {
        fprintf(stderr, "Wrong IV length: %s\n", argv[3]);
        exit(4);
    }

    unsigned char iv[strlen(argv[3])/2];
    for(int i=0; i<strlen(argv[3])/2; i++)
        sscanf(&(argv[3][2*i]), "%2hhx", &(iv[i]));

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) EVP_CIPHER_CTX_new();  //define a new context
    if(ctx == NULL)  handle_errors();

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXSIZE];
    unsigned char ciphertext[100 * MAXSIZE];
    int length, ciphertext_len = 0;

    while((n_read=fread(buffer, 1, MAXSIZE, fp)) >0) {
        //if there is the risk to overflow the ciphertext buffer, EXIT BEFORE
        if(ciphertext_len >= 100 * MAXSIZE - n_read - 16) {
            fprintf(stderr, "The file to encipher is larger than expected!");
            exit(5);
        }

        if(!EVP_CipherUpdate(ctx, ciphertext+ciphertext_len, &length, buffer, n_read))
            handle_errors();
        ciphertext_len+=length;
    }

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length))
        handle_errors();
    ciphertext_len+=length;

    EVP_CIPHER_CTX_free(ctx);
    printf("Ciphertext size: %d\n", ciphertext_len);

    printf("Ciphertext: ");
    for(int i=0; i<ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");



    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(fp);

    exit(0);
}
