#ifndef PE_HELPER_C_H
#define PE_HELPER_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "include/wine/windef.h"

typedef struct {
    char *filename;
    int fd;
    bool file_read;
    struct stat sb;
    uint8_t *_base;
    size_t _base_size;

    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *pe;
    IMAGE_SECTION_HEADER *sections;
} ExeState_C;

/* Functions */
void ExeState_C_Init(ExeState_C *self, const char *filename);
void ExeState_C_Destroy(ExeState_C *self);

uint8_t* ExeState_C_base(ExeState_C *self);

uint32_t ExeState_C_rva_to_raw(ExeState_C *self, uint32_t rva, bool relative);
uint32_t ExeState_C_va_to_raw(ExeState_C *self, uint32_t va);

uint32_t ExeState_C_raw_to_rva(ExeState_C *self, uint32_t raw, bool relative);
uint32_t ExeState_C_raw_to_va(ExeState_C *self, uint32_t raw);

uint32_t ExeState_C_rva_to_va(ExeState_C *self, uint32_t va);

IMAGE_SECTION_HEADER* ExeState_C_find_section(ExeState_C *self, const char *section_name);

#ifdef __cplusplus
}
#endif

#endif
