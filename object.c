#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void hash_to_hex(const ObjectID *id, char *hex_out) {
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < HASH_SIZE; i++) {
        hex_out[i * 2] = hex[(id->hash[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex[id->hash[i] & 0xF];
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;

    for (int i = 0; i < HASH_SIZE; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        id_out->hash[i] = (hi << 4) | lo;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);

    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, id_out->hash, &out_len);

    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);

    snprintf(path_out, path_size, "%s/%c%c/%s",
             OBJECTS_DIR,
             hex[0], hex[1],
             hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    char type_str[16];

    if (type == OBJ_BLOB) {
        strcpy(type_str, "blob");
    } else if (type == OBJ_TREE) {
        strcpy(type_str, "tree");
    } else if (type == OBJ_COMMIT) {
        strcpy(type_str, "commit");
    } else {
        return -1;
    }

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    size_t total_len = header_len + len;
    unsigned char *full_obj = malloc(total_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header, header_len);
    memcpy(full_obj + header_len, data, len);

    compute_hash(full_obj, total_len, id_out);

    if (object_exists(id_out)) {
        free(full_obj);
        return 0;
    }

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    mkdir(PES_DIR, 0777);
    mkdir(OBJECTS_DIR, 0777);

    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%c%c", OBJECTS_DIR, hex[0], hex[1]);
    mkdir(dir_path, 0777);

    char path[512];
    object_path(id_out, path, sizeof(path));

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        free(full_obj);
        return -1;
    }

    if (fwrite(full_obj, 1, total_len, fp) != total_len) {
        fclose(fp);
        free(full_obj);
        return -1;
    }

    fclose(fp);
    free(full_obj);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }

    rewind(fp);

    unsigned char *buf = malloc((size_t)file_size);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (fread(buf, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(buf);
        return -1;
    }

    fclose(fp);

    /* Integrity check */
    ObjectID computed_id;
    compute_hash(buf, (size_t)file_size, &computed_id);
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    char *header_end = memchr(buf, '\0', (size_t)file_size);
    if (!header_end) {
        free(buf);
        return -1;
    }

    size_t header_len = (size_t)(header_end - (char *)buf);

    char type_str[16];
    size_t data_len;
    if (sscanf((char *)buf, "%15s %zu", type_str, &data_len) != 2) {
        free(buf);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0) {
        *type_out = OBJ_BLOB;
    } else if (strcmp(type_str, "tree") == 0) {
        *type_out = OBJ_TREE;
    } else if (strcmp(type_str, "commit") == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(buf);
        return -1;
    }

    if (header_len + 1 + data_len > (size_t)file_size) {
        free(buf);
        return -1;
    }

    *data_out = malloc(data_len);
    if (!*data_out) {
        free(buf);
        return -1;
    }

    memcpy(*data_out, buf + header_len + 1, data_len);
    *len_out = data_len;

    free(buf);
    return 0;
}
