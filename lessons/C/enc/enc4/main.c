#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAXSIZE 4096

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
//argv[4] -> output file
//save in a buffer in memory the result of encryption

int main(int argc, char **argv) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc!= 5) {
        fprintf(stderr, "Invalid parameters.\nUsage: %s input_file key IV output_file\n\n", argv[0]);
        exit(1);
    }

    FILE *fp_in;
    if((fp_in=fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the file \"%s\". Check that the file exists!", argv[1]);
        exit(2);
    }

    FILE *fp_out;
    if((fp_out=fopen(argv[4], "wb+")) == NULL) {
        fprintf(stderr, "Error opening the file \"%s\". Check that the file exists!", argv[4]);
        exit(3);
    }


    if(strlen(argv[2]) != 32) {
        fprintf(stderr, "Wrong key length: %s\n", argv[2]);
        exit(4);
    }

    unsigned char key[strlen(argv[2])/2];
    for(int i=0; i<strlen(argv[2])/2; i++)
        sscanf(&(argv[2][2*i]), "%2hhx", &(key[i]));

    if(strlen(argv[3]) != 32) {
        fprintf(stderr, "Wrong IV length: %s\n", argv[3]);
        exit(5);
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
    unsigned char ciphertext[MAXSIZE + 16];
    int length, ciphertext_len = 0;

    while((n_read=fread(buffer, 1, MAXSIZE, fp_in)) >0) {
        if(!EVP_CipherUpdate(ctx, ciphertext+ciphertext_len, &length, buffer, n_read))
            handle_errors();
        ciphertext_len+=length;

        if(fwrite(ciphertext, 1, length, fp_out) < length) {
            fprintf(stderr, "Error writing the file \"%s\".\n\n", argv[5]);
            exit(6);
        }
    }

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length))
        handle_errors();
    ciphertext_len+=length;

    if(fwrite(ciphertext, 1, length, fp_out) < length) {
        fprintf(stderr, "Error writing the file \"%s\".\n\n", argv[5]);
        exit(6);
    }

    EVP_CIPHER_CTX_free(ctx);
    printf("Ciphertext size: %d\n", ciphertext_len);

    printf("Ciphertext: ");
    for(int i=0; i<ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");



    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    fclose(fp_in);
    fclose(fp_out);

    exit(0);
}
