#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define TYPE_A 1
#define CLASS_IN 1

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

typedef struct {
    uint16_t len;
    char *data;
} String;

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authorities;
    uint16_t num_additionals;
};

struct dns_question {
    uint16_t type_;
    uint16_t class_;
};

struct dns_record {
    uint16_t type_;
    uint16_t class_;
    uint32_t ttl;
    union {
        uint16_t data_len;
        String data;
    };
};

static_assert(sizeof(String) == 16, "wrong size");
static_assert(sizeof(struct dns_header) == 12, "wrong size");
static_assert(sizeof(struct dns_question) == 4, "wrong size");
static_assert(sizeof(struct dns_record) == 24, "wrong size");

static char *encode_dns_name(const char *domain_name) {
    int encoded_len = 0;
    {
        char *_domain_name = strdup(domain_name);
        char *tok = strtok(_domain_name, ".");
        while (tok) {
            encoded_len += 1 + strlen(tok);
            tok = strtok(NULL, ".");
        }
        free(_domain_name);
        encoded_len += 1; // terminating NULL
    }
    char *out = malloc(encoded_len);
    if (!out) die("malloc");
    {
        char *_domain_name = strdup(domain_name);
        char *tok = strtok(_domain_name, ".");
        char *ptr = out;
        while (tok) {
            int len = strlen(tok);
            ptr[0] = len;
            memcpy(ptr + 1, tok, len);
            ptr += 1 + len;
            tok = strtok(NULL, ".");
        }
        free(_domain_name);
        ptr[0] = '\0';
    }
    return out;
}

static char *decode_dns_name(int sock_fd) {
    char *out = NULL;
    int prev_len = 0;
    uint8_t field_len = 0;
    if (recvfrom(sock_fd, &field_len, 1, 0, NULL, NULL) == -1)
        die("recvfrom");
    while (field_len != 0) {
        if ((field_len & 0xc0) == 0xc0) {
            uint8_t next_byte;
            if (recvfrom(sock_fd, &next_byte, 1, 0, NULL, NULL) == -1)
                die("recvfrom");
            uint16_t ptr = (next_byte << 8) | (field_len & 0x3f);
        } else {
            out = realloc(out, prev_len + field_len + 1);
            if (!out) die("malloc");
            if (recvfrom(sock_fd, &out[prev_len], field_len, 0, NULL, NULL) == -1)
                die("recvfrom");
            out[prev_len + field_len] = '.';
            prev_len += field_len + 1;
        }
        if (recvfrom(sock_fd, &field_len, 1, 0, NULL, NULL) == -1)
            die("recvfrom");
    }
    out[prev_len - 1] = '\0';
    return out;
}

static char *build_query(const char *domain_name, int record_type, int *query_size) {
    uint16_t id = 0x8298;
    uint16_t RECURSION_DESIRED = 1 << 8;
    struct dns_header header = {
        .id = htons(id),
        .flags = htons(RECURSION_DESIRED),
        .num_questions = htons(1),
    };
    struct dns_question question = {
        .type_ = htons(record_type),
        .class_ = htons(CLASS_IN),
    };
    char *name = encode_dns_name(domain_name);
    int name_len = strlen(name) + 1;
    int size = sizeof header + name_len + sizeof question;
    char *out = malloc(size);
    if (!out) die("malloc");
    char *ptr = out;
    memcpy(ptr, &header, sizeof header);
    ptr += sizeof header;
    strcpy(ptr, name);
    ptr += name_len;
    memcpy(ptr, &question, sizeof question);
    free(name);
    *query_size = size;
    return out;
}

static struct dns_header *parse_header(int sock_fd) {
    struct dns_header *out = malloc(sizeof *out);
    if (!out) die("malloc");
    if (recvfrom(sock_fd, out, sizeof *out, 0, NULL, NULL) == -1)
        die("recvfrom");
    *out = (struct dns_header){
        .id = ntohs(out->id),
        .flags = ntohs(out->flags),
        .num_questions = ntohs(out->num_questions),
        .num_answers = ntohs(out->num_answers),
        .num_authorities = ntohs(out->num_authorities),
        .num_additionals = ntohs(out->num_additionals),
    };
    return out;
}

static struct dns_question *parse_question(int sock_fd) {
    struct dns_question *out = malloc(sizeof *out);
    if (!out) die("malloc");
    if (recvfrom(sock_fd, out, sizeof *out, 0, NULL, NULL) == -1)
        die("recvfrom");
    *out = (struct dns_question){
        .type_ = ntohs(out->type_),
        .class_ = ntohs(out->class_),
    };
    return out;
}

static struct dns_record *parse_record(int sock_fd) {
    char *name = decode_dns_name(sock_fd);
    struct dns_record *out = malloc(sizeof *out);
    if (!out) die("malloc");
    *out = (struct dns_record){
        .type_ = ntohs(out->type_),
        .class_ = ntohs(out->class_),
        .ttl = ntohl(out->ttl),
        .data.len = ntohs(out->data_len),
    };
    out->data.data = malloc(out->data.len);
    if (!out->data.data) die("malloc");
    if (recvfrom(sock_fd, out->data.data, out->data.len, 0, NULL, NULL) == -1)
        die("recvfrom");
    return out;
}

int main() {
    char reply_buf[1024];
    int query_size;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1)
        die("socket");
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
    };
    if (inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: can't convert address\n");
        exit(1);
    }
    char *query = build_query("www.example.com", TYPE_A, &query_size);
    if (sendto(sock_fd, query, query_size, 0, (const struct sockaddr *)&addr, sizeof addr) == -1)
        die("sendto");
    if (recvfrom(sock_fd, reply_buf, sizeof reply_buf, 0, NULL, NULL) == -1)
        die("recvfrom");
    free(query);
    close(sock_fd);
}
