#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define TYPE_A     1
#define TYPE_NS    2
#define TYPE_CNAME 5
#define CLASS_IN   1
#define DNS_PORT   53

#define IPV4_ADDR(a, b, c, d) (((d) << 24) | ((c) << 16) | ((b) << 8) | ((a) << 0))
#define ROOT_NS IPV4_ADDR(198, 41, 0, 4)

#define _cleanup_(f) __attribute__((cleanup(f)))

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

typedef struct {
    uint16_t len;
    char *data;
} String;

typedef struct {
    uint16_t pos;
    char *data;
} Stream;

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
    const char *name;
};

struct dns_record {
    uint16_t type_;
    uint16_t class_;
    uint32_t ttl;
    union {
        uint16_t data_len;
        String data;
    };
    const char *name;
};

struct dns_packet {
    struct dns_header header;
    struct dns_question *questions;
    struct dns_record *answers;
    struct dns_record *authorities;
    struct dns_record *additionals;
};

static_assert(sizeof(String) == 16, "wrong size");
static_assert(sizeof(Stream) == 16, "wrong size");
static_assert(sizeof(struct dns_header) == 12, "wrong size");
static_assert(sizeof(struct dns_question) == 16, "wrong size");
static_assert(sizeof(struct dns_record) == 32, "wrong size");
static_assert(sizeof(struct dns_packet) == 48, "wrong size");

static void read_stream(void *dst, Stream *src, size_t n) {
    memcpy(dst, src->data + src->pos, n);
    src->pos += n;
}

static void write_stream(Stream *dst, const void *src, size_t n) {
    memcpy(dst->data + dst->pos, src, n);
    dst->pos += n;
}

static uint16_t tell_stream(const Stream *stream) {
    return stream->pos;
}

static void seek_stream(Stream *stream, uint16_t pos) {
    stream->pos = pos;
}

static const char *encode_dns_name(const char *domain_name) {
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

static const char *decode_dns_name(Stream *);

static const char *decode_compressed_name(Stream *stream, uint8_t field_len) {
    uint8_t next_byte;
    read_stream(&next_byte, stream, 1);
    uint16_t ptr = ((field_len & 0x3f) << 8) | next_byte;
    uint16_t cur = tell_stream(stream);
    seek_stream(stream, ptr);
    const char *out = decode_dns_name(stream);
    seek_stream(stream, cur);
    return out;
}

static const char *decode_dns_name(Stream *stream) {
    char *out = NULL;
    int prev_len = 0;
    uint8_t field_len;
    read_stream(&field_len, stream, 1);
    while (field_len != 0) {
        if ((field_len & 0xc0) != 0) {
            const char *res = decode_compressed_name(stream, field_len);
            int res_len = strlen(res);
            out = realloc(out, prev_len + res_len + 1);
            if (!out) die("malloc");
            memcpy(&out[prev_len], res, res_len);
            out[prev_len + res_len] = '.';
            prev_len += res_len + 1;
            free((void *)res);
            break;
        } else {
            out = realloc(out, prev_len + field_len + 1);
            if (!out) die("malloc");
            read_stream(&out[prev_len], stream, field_len);
            out[prev_len + field_len] = '.';
            prev_len += field_len + 1;
        }
        read_stream(&field_len, stream, 1);
    }
    out[prev_len - 1] = '\0';
    return out;
}

static const char *build_query(const char *domain_name, int record_type, int *query_size) {
    uint16_t id = random() & 0xffff;
    uint16_t flags = 0;
    struct dns_header header = {
        .id = htons(id),
        .flags = htons(flags),
        .num_questions = htons(1),
    };
    struct dns_question question = {
        .type_ = htons(record_type),
        .class_ = htons(CLASS_IN),
    };
    const char *name = encode_dns_name(domain_name);
    int name_len = strlen(name) + 1;
    int size = sizeof header + name_len + 4;
    char *out = malloc(size);
    if (!out) die("malloc");
    Stream stream = { .pos = 0, .data = out };
    write_stream(&stream, &header, sizeof header);
    write_stream(&stream, name, name_len);
    write_stream(&stream, &question, 4);
    free((void *)name);
    *query_size = size;
    return out;
}

static void parse_header(Stream *stream, struct dns_header *out) {
    read_stream(out, stream, sizeof *out);
    *out = (struct dns_header){
        .id = ntohs(out->id),
        .flags = ntohs(out->flags),
        .num_questions = ntohs(out->num_questions),
        .num_answers = ntohs(out->num_answers),
        .num_authorities = ntohs(out->num_authorities),
        .num_additionals = ntohs(out->num_additionals),
    };
}

static void parse_question(Stream *stream, struct dns_question *out) {
    const char *name = decode_dns_name(stream);
    read_stream(out, stream, 4);
    *out = (struct dns_question){
        .type_ = ntohs(out->type_),
        .class_ = ntohs(out->class_),
        .name = name,
    };
}

static void parse_record(Stream *stream, struct dns_record *out) {
    const char *name = decode_dns_name(stream);
    read_stream(out, stream, 10);
    *out = (struct dns_record){
        .type_ = ntohs(out->type_),
        .class_ = ntohs(out->class_),
        .ttl = ntohl(out->ttl),
        .data.len = ntohs(out->data_len),
        .name = name,
    };
    if (out->type_ == TYPE_NS || out->type_ == TYPE_CNAME) {
        out->data.data = (char *)decode_dns_name(stream);
        out->data.len = strlen(out->data.data);
    } else {
        out->data.data = malloc(out->data.len);
        if (!out->data.data) die("malloc");
        read_stream(out->data.data, stream, out->data.len);
    }
}

static const struct dns_packet *parse_packet(Stream *stream) {
#define READ_RECORD(field, field_len, parse_fn) ({ \
    out->field = malloc(out->header.field_len * sizeof *out->field); \
    if (!out->field) die("malloc"); \
    for (int i = 0; i < out->header.field_len; i++) \
        parse_fn(stream, &out->field[i]); \
})
    struct dns_packet *out = malloc(sizeof *out);
    if (!out) die("malloc");
    parse_header(stream, &out->header);
    READ_RECORD(questions, num_questions, parse_question);
    READ_RECORD(answers, num_answers, parse_record);
    READ_RECORD(authorities, num_authorities, parse_record);
    READ_RECORD(additionals, num_additionals, parse_record);
    return out;
#undef READ_RECORD
}

static void free_question(struct dns_question *q) {
    free((void *)q->name);
    //free((void *)q);
}

static void free_record(struct dns_record *r) {
    free((void *)r->name);
    free(r->data.data);
    //free((void *)r);
}

static void free_packetp(const struct dns_packet **p) {
#define FREE_RECORD(field, field_len, free_fn) ({ \
    for (int i = 0; i < (*p)->header.field_len; i++) \
        free_fn(&(*p)->field[i]); \
    free((void *)(*p)->field); \
})
    FREE_RECORD(questions, num_questions, free_question);
    FREE_RECORD(answers, num_answers, free_record);
    FREE_RECORD(authorities, num_authorities, free_record);
    FREE_RECORD(additionals, num_additionals, free_record);
    free((void *)(*p));
#undef FREE_RECORD
}

static void freep(char **ptr) {
    free(*ptr);
}

static void print_question(const struct dns_question *q) {
    printf("(struct dns_question){ "
           ".name = \"%s\", "
           ".type = %d, "
           ".class = %d }\n",
           q->name, q->type_, q->class_);
}

static void print_dotted(const uint8_t *data, int len) {
    if (len == 0) return;
    printf("%d", data[0]);
    for (int i = 1; i < len; i++)
        printf(".%d", data[i]);
}

static void print_hex(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static void print_record(const struct dns_record *record) {
    printf("(struct dns_record){ "
           ".name = \"%s\", "
           ".type = %d, "
           ".class = %d, "
           ".ttl = %d, "
           ".data = ",
           record->name, record->type_, record->class_,
           record->ttl);
    if (record->type_ == TYPE_A) {
        print_dotted((const uint8_t *)record->data.data, record->data.len);
    } else if (record->type_ == TYPE_NS || record->type_ == TYPE_CNAME) {
        printf("\"%s\"", record->data.data);
    } else {
        print_hex((const uint8_t *)record->data.data, record->data.len);
    }
    printf(" }\n");
}

static void print_packet(const struct dns_packet *packet) {
#define PRINT_RECORD(print_fn, field, field_len, field_type) ({ \
    printf(field_type); \
    for (int i = 0; i < packet->header.field_len; i++) { \
        print_fn(&packet->field[i]); \
    } \
})
    PRINT_RECORD(print_question, questions, num_questions, "Questions:\n");
    PRINT_RECORD(print_record, answers, num_answers, "Answers:\n");
    PRINT_RECORD(print_record, authorities, num_authorities, "Authorities:\n");
    PRINT_RECORD(print_record, additionals, num_additionals, "Additionals:\n");
#undef PRINT_RECORD
}

const struct dns_packet *send_query(const char *domain_name, in_addr_t ns_addr) {
    char reply_buf[1024];
    int query_size, num_read;

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1)
        die("socket");

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = ns_addr,
    };

    const char *query = build_query(domain_name, TYPE_A, &query_size);
    if (sendto(sock_fd, query, query_size, 0, (const struct sockaddr *)&addr, sizeof addr) == -1)
        die("sendto");
    free((void *)query);

    if ((num_read = recvfrom(sock_fd, reply_buf, sizeof reply_buf, 0, NULL, NULL)) == -1)
        die("recvfrom");
    close(sock_fd);

    Stream stream = { .pos = 0, .data = reply_buf };
    const struct dns_packet *packet = parse_packet(&stream);

    return packet;
}

char *get_answer(const struct dns_packet *packet) {
    for (int i = 0; i < packet->header.num_answers; i++) {
        if (packet->answers[i].type_ == TYPE_A)
            return packet->answers[i].data.data;
    }
    return NULL;
}

char *get_ns_ip(const struct dns_packet *packet) {
    for (int i = 0; i < packet->header.num_additionals; i++) {
        if (packet->additionals[i].type_ == TYPE_A)
            return packet->additionals[i].data.data;
    }
    return NULL;
}

char *get_ns(const struct dns_packet *packet) {
    for (int i = 0; i < packet->header.num_authorities; i++) {
        if (packet->authorities[i].type_ == TYPE_NS)
            return packet->authorities[i].data.data;
    }
    return NULL;
}

char *get_cname(const struct dns_packet *packet) {
    for (int i = 0; i < packet->header.num_answers; i++) {
        if (packet->answers[i].type_ == TYPE_CNAME)
            return packet->answers[i].data.data;
    }
    return NULL;
}

in_addr_t resolve(const char *domain_name) {
    _cleanup_(freep) char *cname = NULL;
    in_addr_t ns_addr = ROOT_NS;

    while (1) {
        char *data = NULL;
        _cleanup_(free_packetp) const struct dns_packet *packet = NULL;

        printf("Querying ");
        print_dotted((const uint8_t *)&ns_addr, 4);
        printf(" for '%s'\n", domain_name);
        packet = send_query(domain_name, ns_addr);
        if ((data = get_answer(packet))) {
            in_addr_t out;
            memcpy(&out, data, 4);
            return out;
        } else if ((data = get_cname(packet))) {
            free(cname);
            cname = strdup(data);
            domain_name = cname;
            ns_addr = ROOT_NS;
        } else if ((data = get_ns_ip(packet))) {
            memcpy(&ns_addr, data, 4);
        } else if ((data = get_ns(packet))) {
            ns_addr = resolve(data);
        } else {
            fprintf(stderr, "ERROR: no recognized DNS record found in packet.\n");
            print_packet(packet);
            return -1;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <domain_name>\n", argv[0]);
        exit(1);
    }
    const char *domain_name = argv[1];

    srandom(time(NULL));

    in_addr_t addr = resolve(domain_name);
    print_dotted((const uint8_t *)&addr, 4);
    printf("\n");
}
