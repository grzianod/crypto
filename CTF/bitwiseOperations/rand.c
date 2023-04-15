#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

int main(){

    unsigned char rand1_string[] = "633b6d07651a09317a4fb4aaef3f7a55d03393521e81fb631126ed9e8ea710f6639deb9290eb760b905aebb475d3a1cfd29139c189328422124e77574d258598";
    unsigned char rand2_string[] = "9205d8b5fa8597b622f4bd2611cf798cdb4a2827bbd331567416dfcbf561a79d18c26392f1cbc36d2b7719aa21078efe8b1a4f7d706ea47bc86830431250301e";

    unsigned char rand1[strlen(rand1_string)];
    unsigned char rand2[strlen(rand2_string)];
    for(int i=0; i<strlen(rand1_string); i++) {
        sscanf(&(rand1_string[2*i]), "%2hhx", &(rand1[i]));
        sscanf(&(rand2_string[2*i]), "%2hhx", &(rand2[i]));
    }


    unsigned char key[strlen(rand1_string)];
    for(int i=0; i<strlen(rand1); i++) {
        printf("%02x-",((rand1[i] | rand2[i]) ^ (rand1[i] & rand2[i])));
    }

}