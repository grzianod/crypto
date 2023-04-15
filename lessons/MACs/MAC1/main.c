#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#define MAXBUF 1024

void handle_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 2) {
        fprintf(stderr, "Invalid arguments. Usage: %s message\n", argv[0]);
        exit(1);
    }

    FILE *fp;

    if((fp = fopen(argv[1], "r")) == NULL) {
        printf("Error opening the file \"%s\".\n\n", argv[1]);
        exit(2);
    }

    EVP_MD_CTX *md = (EVP_MD_CTX *) EVP_MD_CTX_new();
    if(md == NULL) handle_error();

    if(!EVP_DigestInit(md, EVP_sha1())) handle_error();

    int n=0;
    unsigned char buffer[MAXBUF];

    while((n=fread(buffer, 1, MAXBUF, fp)) > 0) {
        if(!EVP_DigestUpdate(md, buffer, n)) handle_error();
    }

    unsigned char md_value[EVP_MD_size(EVP_sha1())]; //since SHA1 returns 160 bits digests -> 20 bytes
    int md_len = 0;

    if(!EVP_DigestFinal(md, md_value, &md_len)) handle_error();
    EVP_MD_CTX_free(md);

    printf("SHA1(%s) = ", argv[1]);
    for(int i=0; i<md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    fclose(fp);
    exit(0);
}
