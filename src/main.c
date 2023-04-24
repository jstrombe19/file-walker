#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <limits.h>
#include <ftw.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "main.h"
#include "utils.h"

#define PRI_HEADER_SIZE 6
#define CORE_PACKET_SIZE 44
#define MAX_CHUNKS 30


void strip_packet_header(struct chunk_alloc *chunks) {
    int number_of_packets = 0;
    int partial_packets = 0;
    while (chunks[0].index + (CORE_PACKET_SIZE + PRI_HEADER_SIZE) <= chunks[0].size) {
        uint8_t *packet = &chunks[0].ptr[chunks[0].index];
        uint8_t *data = &packet[PRI_HEADER_SIZE];
        size_t data_size = CORE_PACKET_SIZE;

        write_buffer_to_file(data, data_size);

        number_of_packets++;
        chunks[0].index += (data_size + PRI_HEADER_SIZE);
        printf("%s | chunks[0].index: %ld\n", __func__, chunks[0].index);
    }

    if (chunks[0].index < chunks[0].size) {
        uint8_t *packet = &chunks[0].ptr[chunks[0].index];
        size_t packet_size = chunks[0].size - chunks[0].index;
        uint8_t *data = &packet[PRI_HEADER_SIZE];
        size_t data_size = packet_size - PRI_HEADER_SIZE;

        write_buffer_to_file(data, data_size);
        partial_packets++;
    }
    
    printf("%s | number of packets: %d\n", __func__, number_of_packets);
    printf("%s | partial packets:   %d\n", __func__, partial_packets);
}

void decrypt_packet_payload(uint8_t *packet_data, int length) {
    // TODO: decryption handling here; for now, halve values
    for (int i = 0; i < length; i++) {
        // packet_data[i] /= 2;
    }
}

void generate_file(char* filename, int length) {
    int i;
    FILE *fp = fopen(filename, "wb");

    if (fp == NULL) {
        printf("%s | Failed to create file %s\n", __func__, filename);
        return;
    }

    for (i = 0; i < length; i++) {
        uint8_t data = i & 0xFF;
        fwrite(&data, sizeof(data), 1, fp);
    }

    fclose(fp);
}

void write_buffer_to_file(uint8_t *buffer, int buffer_size) {
    if (buffer == NULL) {
        printf("%s | Error: buffer is NULL; failed to write to file.\n", __func__);
    }

    FILE *fp = fopen("processed", "ab");
    // int fp = open("processed", O_CREAT | O_APPEND);

    // for (int i = 0; i < buffer_size; i++) {
    fwrite(buffer, sizeof(uint8_t), buffer_size, fp);
        // int bytes_written = write(fp, &buffer, 1);
        // printf("%s | bytes_written: %d\n", __func__, bytes_written);
    // }

    fclose(fp);
}

void print_buffer_content(uint8_t *buffer, int buffer_size) {
    printf("%s | sizeof(int): %ld\n", __func__, sizeof(int));
    printf("%s | sizeof(buffer): %d\n", __func__, buffer_size);
    for (int i = 0; i < buffer_size; i++) {
        printf("%d  ", buffer[i]);
    }
    printf("\n");
}

int main() {
    char filename[] = "sample";
    int length = 512;
    bool ret = true;
    generate_file(filename, length);

    if (filename != NULL) {
        printf("Generated %s file\n", filename);
    } else {
        printf("Failed to create file\n");
    }

    // reverse-process file assuming defined parameters above
    // FILE *input_file;
    // char buffer[(CORE_PACKET_SIZE + PRI_HEADER_SIZE) * sizeof(int)];
    uint8_t buffer[CORE_PACKET_SIZE + PRI_HEADER_SIZE];
    size_t num_bytes_read = 0;
    struct chunk_alloc *chunks = calloc(MAX_CHUNKS, sizeof(*chunks));

    if (!load_file(filename, &chunks[0].ptr, &chunks[0].size)) {
        printf("Unable to load file %s\n", filename);
        ret = false;
        // goto free_individual_chunks;
    }



    // input_file = fopen(filename, "rb");
    // if (input_file == NULL) {
    //     printf("Error: failed to open input file %s.\n", filename);
    //     return 1;
    // }
    // write_buffer_to_file(chunks[0].ptr, chunks[0].size);

    // uint8_t *packet_data = chunks[0].ptr;
    // for (int i = 0; i < chunks[0].size; i+= CORE_PACKET_SIZE + PRI_HEADER_SIZE) {
    //     printf("%s | packet_data: %d\n", __func__, *packet_data);
    //     printf("%s | sizeof(buffer): %ld\n", __func__, sizeof(chunks[0]));
    //     // print_buffer_content(packet_data, chunks[0].size);
    //     while (packet_data < buffer + num_bytes_read) {
    //         strip_packet_header(packet_data, sizeof(buffer));
    //         // decrypt_packet_payload(packet_data + PRI_HEADER_SIZE, chunks[0].size - PRI_HEADER_SIZE); 
    //         // strip secondary header here
    //         // ...
    //         write_buffer_to_file(packet_data, chunks[0].size);
    //         packet_data += CORE_PACKET_SIZE;
    //     }
    // }

    strip_packet_header(chunks);

    //compare with original input here
    // ...

    // fclose(input_file);
    free(chunks);

    return 0;
}