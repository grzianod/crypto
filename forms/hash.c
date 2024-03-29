#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int main(){
       
        EVP_MD_CTX *md;

        char message[] = "Cryptography class 31-03-23";



       //EVP_MD_CTX *EVP_MD_CTX_new(void);
		md = EVP_MD_CTX_new();

        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        EVP_DigestInit(md, EVP_sha3_384());


        // int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
        EVP_DigestUpdate(md, message, strlen(message));


        unsigned char md_value[EVP_MD_size(EVP_sha3_384())];
        printf("%d\n", EVP_MD_size(EVP_sha3_384()));
        int md_len;

        //int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
        EVP_DigestFinal(md, md_value, &md_len);

        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		EVP_MD_CTX_free(md);

        printf("The digest is: ");
        for(int i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("\n");

	return 0;

}