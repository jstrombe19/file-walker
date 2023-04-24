#ifndef MAIN
#define MAIN

#include "utils.h"


typedef struct{
    char *syslog;
    char *overpass_list;
    char *all_files_list;
    char *range_log;
} LOKI_LogFileMessage_t;

struct chunk_alloc{
    size_t   index;
    size_t   size;
    uint8_t *ptr;
};

void write_buffer_to_file(uint8_t *buffer, int buffer_size);

void generate_file(char* filename, int length);

void strip_packet_header(struct chunk_alloc *chunks);


#endif