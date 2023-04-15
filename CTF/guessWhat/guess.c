#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <string.h>
#include <openssl/rsa.h>
#include <ctype.h>

int main() {
    const unsigned char c = ':';
    unsigned char first_string[] = "00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51";
    unsigned char second_string[] = "00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07";


    unsigned char *n_string = (unsigned char*)malloc(strlen(first_string) * sizeof(unsigned char));
    unsigned char *p_string = (unsigned char*)malloc(strlen(second_string) * sizeof(unsigned char));

    unsigned int w=0;
    for(int i=0; i<strlen(first_string); i++) {
        if((i+1)%3 == 0) continue;
        n_string[w++] = first_string[i];
    }

    for(int i=0, w=0; i<strlen(second_string); i++) {
        if((i+1)%3 == 0) continue;
        p_string[w++] = second_string[i];
    }

    BIGNUM *n = BN_new();
    BIGNUM *p = BN_new();
    BN_hex2bn(&n, n_string);
    BN_hex2bn(&p, p_string);

    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();
    BN_div(q, r, n, p, BN_CTX_new());

    unsigned char *q_string = BN_bn2hex(q);
    unsigned char *third_string = (unsigned char*)malloc(strlen(second_string)*sizeof(unsigned char));
    for(int i=0, w=0; i<strlen(second_string); i++) {
        if((i+1)%3 == 0) third_string[i]=':';
        else third_string[i] = q_string[w++];
    }

    printf("CRYPTO23{");
    for(int i=0; i<strlen(third_string)-1; i++)
        printf("%c", tolower(third_string[i]));
    printf("}\n");

    BN_free(n);
    BN_free(p);
    free(p_string);
    free(n_string);
    exit(0);
}