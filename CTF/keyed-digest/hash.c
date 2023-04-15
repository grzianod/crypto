#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024
#define BLOCK_SIZE 64

int main(int argc, char **argv){
       
      
        if(argc != 2){
            fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
            exit(1);
        }


        FILE *f_in;
        if((f_in = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }

        unsigned char secret[] = "this_is_my_secret";
        
       //EVP_MD_CTX *EVP_MD_CTX_new(void);
		EVP_MD_CTX *md = EVP_MD_CTX_new();

        int n;
        unsigned char buffer[MAXBUF] = {0};

        //printf("%s", to_hash);
        // for(int i=0; i<BLOCK_SIZE*10; i++)
        // printf("%02x", to_hash[i]);

        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        EVP_DigestInit(md, EVP_sha512());

        EVP_DigestUpdate(md, secret, strlen(secret));

        n = fread(buffer,1, MAXBUF, f_in);
        EVP_DigestUpdate(md, buffer, n);

        EVP_DigestUpdate(md, secret, strlen(secret));
        
        unsigned char md_value[EVP_MD_size(EVP_sha512())];
        int md_len;
        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
        EVP_DigestFinal_ex(md, md_value, &md_len);

        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		EVP_MD_CTX_free(md);

        printf("CRYPTO23{");
        for(int i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("}\n");

	return 0;

}
