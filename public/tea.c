#include <stdint.h>
#include <stdio.h>

void encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;
    uint32_t delta=0x9E3779B9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i<32; i++) {
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }
    v[0]=v0; v[1]=v1;
}

void decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;
    uint32_t delta=0x9E3779B9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i<32; i++) {
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }
    v[0]=v0; v[1]=v1;
}

int main(int argc, char** argv) {
	unsigned char data2[] = "This\0\0\0\0";
	unsigned char data[] = "This is ";
	unsigned char key1[] = "0123456789ABCDEF";
    unsigned char key[] = "\x4D\x0E\x7E\x3C\x53\x3E\xF8\x54\x4D\x0E\x7E\x3C\x53\x3E\xF8\x54";
	encrypt((uint32_t *)(data2), (uint32_t *)(key));
    for (int i = 0; i < sizeof data2 - 1; i++) {
        printf(" %02x", data2[i]);
    }
	decrypt((uint32_t *)(data2), (uint32_t *)(key));
    printf("\n%s\n", data2);
	encrypt((uint32_t *)(data), (uint32_t *)(key));
    for (int i = 0; i < sizeof data - 1; i++) {
        printf(" %02x", data[i]);
    }
	decrypt((uint32_t *)(data), (uint32_t *)(key));
    printf("\n%s\n", data);
}

// "This" yields
//      ec 05 28 00 2e 5f b9 fc
// "This is " yields
//      bd dd f1 d8 48 fd 39 d5
