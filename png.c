#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

// Stolen from http://www.libpng.org/pub/png/spec/1.2/PNG-CRCAppendix.html

/* Table of CRCs of all 8-bit messages. */
unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
int crc_table_computed = 0;

/* Make the table for a fast CRC. */
void make_crc_table(void)
{
    unsigned long c;
    int n, k;

    for (n = 0; n < 256; n++) {
        c = (unsigned long) n;
        for (k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}

/* Update a running CRC with the bytes buf[0..len-1]--the CRC
   should be initialized to all 1's, and the transmitted value
   is the 1's complement of the final running CRC (see the
   crc() routine below)). */

unsigned long update_crc(unsigned long crc, unsigned char *buf,
                         int len)
{
    unsigned long c = crc;
    int n;

    if (!crc_table_computed)
        make_crc_table();
    for (n = 0; n < len; n++) {
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    return c;
}

/* Return the CRC of the bytes buf[0..len-1]. */
unsigned long crc(unsigned char *buf, int len)
{
    return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}

#define PNG_SIG_CAP 8
const uint8_t png_sig[PNG_SIG_CAP] = {137, 80, 78, 71, 13, 10, 26, 10};

#define read_bytes_or_panic(file, buf, buf_cap) read_bytes_or_panic_(file, buf, buf_cap, __FILE__, __LINE__)
void read_bytes_or_panic_(FILE *file, void *buf, size_t buf_cap, const char *source_file, int source_line)
{
    size_t n = fread(buf, buf_cap, 1, file);
    if (n != 1) {
        if (ferror(file)) {
            fprintf(stderr, "%s:%d: ERROR: could not read %zu bytes from file: %s\n",
                    source_file, source_line,
                    buf_cap, strerror(errno));
            exit(1);
        } else if (feof(file)) {
            fprintf(stderr, "%s:%d: ERROR: could not read %zu bytes from file: reached the end of file\n",
                    source_file, source_line,
                    buf_cap);
            exit(1);
        } else {
            assert(0 && "unreachable");
        }
    }
}

#define write_bytes_or_panic(file, buf, buf_cap) write_bytes_or_panic_(file, buf, buf_cap, __FILE__, __LINE__)
void write_bytes_or_panic_(FILE *file, void *buf, size_t buf_cap, const char *source_file, int source_line)
{
    size_t n = fwrite(buf, buf_cap, 1, file);
    if (n != 1) {
        if (ferror(file)) {
            fprintf(stderr, "%s:%d: ERROR: could not write %zu bytes to file: %s\n",
                    source_file, source_line,
                    buf_cap, strerror(errno));
            exit(1);
        } else {
            assert(0 && "unreachable");
        }
    }

}

void print_bytes(uint8_t *buf, size_t buf_cap)
{
    for (size_t i = 0; i < buf_cap; ++i) {
        printf("%u ", buf[i]);
    }
    printf("\n");
}

void reverse_bytes(void *buf0, size_t buf_cap)
{
    uint8_t *buf = buf0;
    for (size_t i = 0; i < buf_cap/2; ++i) {
        uint8_t t = buf[i];
        buf[i] = buf[buf_cap - i - 1];
        buf[buf_cap - i - 1] = t;
    }
}

bool chunk_is_valid(void *buf0) {
    uint8_t *chunk_type = buf0;
    if (*(uint32_t*)chunk_type == 0x52444849 ||
        *(uint32_t*)chunk_type == 0x54414449 ||
        *(uint32_t*)chunk_type == 0x444E4549) {
        return true;
    }
    return false;
}

void usage(FILE *file, char *program)
{
    fprintf(file, "Usage: %s -r <input.png> or \n"
                  "       %s -i <input.png> <output.png> <injected_msg>\n", 
            program, program);
}

#define CHUNK_BUF_CAP (32 * 1024)
uint8_t chunk_buf[CHUNK_BUF_CAP];

int main(int argc, char **argv)
{
    make_crc_table();

    (void) argc;
    assert(*argv != NULL);
    char *program = *argv++;

    if (*argv == NULL) {
        usage(stderr, program);
        fprintf(stderr, "ERROR: mode not specified\n");
        exit(1);
    }

    char *flag = *argv++;
    char mode;
    if (flag[0] != '-') {
        usage(stderr, program);
        fprintf(stderr, "ERROR: invalid mode selection\n");
        exit(1);
    }
    if (flag[1] == 'r') {
        mode = 'r';
    }
    else if (flag[1] == 'i') {
        mode = 'i';
    }
    else {
        usage(stderr, program);
        fprintf(stderr, "ERROR: invalid mode selection\n");
        exit(1);
    }
    if (*argv == NULL) {
        usage(stderr, program);
        fprintf(stderr, "ERROR: no input file is provided\n");
        exit(1);
    }

    char *input_filepath = *argv++;
    
    char *output_filepath = "tmp";
    char *injected_type = "imSG";
    char *injected_msg = "";
    if (mode == 'i') {
        if (*argv == NULL) {
            usage(stderr, program);
            fprintf(stderr, "ERROR: no output file is provided\n");
            exit(1);
        }

        output_filepath = *argv++;

        if (*argv == NULL) {
            usage(stderr, program);
            fprintf(stderr, "ERROR: no injection message is provided\n");
            exit(1);
        }

        injected_msg = *argv++;
    }
    FILE *input_file = fopen(input_filepath, "rb");
    if (input_file == NULL) {
        fprintf(stderr, "ERROR: could not open file %s: %s\n",
                input_filepath, strerror(errno));
        exit(1);
    }

    FILE *output_file = fopen(output_filepath, "wb");
    if (output_file == NULL) {
        fprintf(stderr, "ERROR: could not open file %s: %s\n",
                output_filepath, strerror(errno));
        exit(1);
    }

    uint8_t sig[PNG_SIG_CAP];
    read_bytes_or_panic(input_file, sig, PNG_SIG_CAP);
    write_bytes_or_panic(output_file, sig, PNG_SIG_CAP);
    if (mode == 'r') {
        printf("Signature: ");
        print_bytes(sig, PNG_SIG_CAP);
    }
    if (memcmp(sig, png_sig, PNG_SIG_CAP) != 0) {
        fprintf(stderr, "ERROR: %s does not appear to be a valid PNG image\n",
                input_filepath);
        exit(1);
    }

    bool quit = false;
    while (!quit) {
        uint32_t chunk_sz;
        read_bytes_or_panic(input_file, &chunk_sz, sizeof(chunk_sz));
        write_bytes_or_panic(output_file, &chunk_sz, sizeof(chunk_sz));
        reverse_bytes(&chunk_sz, sizeof(chunk_sz));

        uint8_t chunk_type[4];
        read_bytes_or_panic(input_file, chunk_type, sizeof(chunk_type));
        write_bytes_or_panic(output_file, chunk_type, sizeof(chunk_type));
        bool chunk_valid = chunk_is_valid(chunk_type);

        if (*(uint32_t*)chunk_type == 0x444E4549) {
            quit = true;
        }

        size_t n = chunk_sz;
        if (!chunk_valid) 
        {
            printf("Chunk msg:  ");
        }
        while (n > 0) {
            size_t m = n;
            if (m > CHUNK_BUF_CAP) {
                m = CHUNK_BUF_CAP;
            }
            read_bytes_or_panic(input_file, chunk_buf, m);
            write_bytes_or_panic(output_file, chunk_buf, m);
            if (mode == 'r' && !chunk_valid) {
                write_bytes_or_panic(stdout, chunk_buf, m);
            }
            n -= m;
        }

        uint32_t chunk_crc;
        read_bytes_or_panic(input_file, &chunk_crc, sizeof(chunk_crc));
        write_bytes_or_panic(output_file, &chunk_crc, sizeof(chunk_crc));

        if (*(uint32_t*)chunk_type == 0x52444849 && mode == 'i') {
            uint32_t injected_sz = strlen(injected_msg);
            printf("Injected chunk size: %d\n", injected_sz);
            reverse_bytes(&injected_sz, sizeof(injected_sz));
            write_bytes_or_panic(output_file, &injected_sz, sizeof(injected_sz));
            reverse_bytes(&injected_sz, sizeof(injected_sz));

            write_bytes_or_panic(output_file, injected_type, 4);

            write_bytes_or_panic(output_file, injected_msg, injected_sz);

            uint32_t injected_crc = 0;//crc("YEP", injected_sz);
            write_bytes_or_panic(output_file, &injected_crc, sizeof(injected_crc));
        }
        if (mode == 'r') {
            if (!chunk_is_valid(chunk_type)) putc('\n', stdout);
            printf("Chunk size: %u\n", chunk_sz);
            printf("Chunk type: %.*s (0x%08X)\n",
                (int) sizeof(chunk_type), chunk_type,
                *(uint32_t*) chunk_type);
            printf("Chunk CRC:  0x%08X\n", chunk_crc);
            printf("------------------------------\n");
        }
    }

    fclose(input_file);
    fclose(output_file);
    if (mode == 'r') {
        system("rm tmp");
    }
    return 0;
}
