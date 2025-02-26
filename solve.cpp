#include <iostream>
#include <fstream>

using namespace std;

#define ROUNDS 10485760
// Convert a single hex digit to its integer value.
uint8_t hexVal(char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

// Convert a hex string to a byte array.
void hexStringToBytes(const char *hex, uint8_t **out, size_t *outLen) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        *out = NULL;
        *outLen = 0;
        return;
    }
    *outLen = len / 2;
    *out = (uint8_t *) malloc(*outLen);
    for (size_t i = 0; i < *outLen; i++) {
        (*out)[i] = (hexVal(hex[2*i]) << 4) | hexVal(hex[2*i + 1]);
    }
}

void decode(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0x13a00000;
    const uint32_t delta = 0x9e3779b9;
    
    for (uint32_t i = 0; i < ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    
    v[0] = v0;
    v[1] = v1;
}

void code(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9e3779b9;
    
    for (uint32_t i = 0; i < ROUNDS; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    
    v[0] = v0;
    v[1] = v1;
}

int main(void) {
    FILE* fp = freopen("flag_enc", "rb", stdin);
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t fileSize = 169472;

    // cout << fileSize << endl;
    fseek(fp, 0, SEEK_SET);

    uint8_t* flag_bytes = (uint8_t*)malloc(fileSize);

    
    size_t bytesRead = fread(flag_bytes, 1, fileSize, fp);
    if (bytesRead != fileSize) {
        fprintf(stderr, "Failed to read entire file\n");
        free(flag_bytes);
        return 1;
    }

    for (int i = 0; i < fileSize; i++) {
        *(flag_bytes + i) ^= i;
    }
    

    int idx = 0;
    for (int i = 0; i < fileSize; i += 8) {
        uint32_t v0 = (flag_bytes[i] << 0) | (flag_bytes[i + 1] << 8) | (flag_bytes[i + 2] << 16) | (flag_bytes[i + 3] << 24);
        uint32_t v1 = (flag_bytes[i + 4] << 0) | (flag_bytes[i + 5] << 8) | (flag_bytes[i + 6] << 16) | (flag_bytes[i + 7] << 24);
        uint32_t v[2] = { v0, v1 };
        uint32_t key[4] = { 0xa341316c, 0xc8013ea4, 0x3c6ef372, 0x14292967 };
        decode(v, key);
        idx += 2;
        printf("%08x%08x", v[0], v[1]);
    }
    return 0;
}
