#include "pe_helper_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

void ExeState_C_Init(ExeState_C *self, const char *filename) {
    self->filename = strdup(filename);
    self->fd = -1;
    self->file_read = false;
    self->_base = NULL;
    self->_base_size = 0;
    self->dos = NULL;
    self->pe = NULL;
    self->sections = NULL;

    self->fd = open(self->filename, O_RDONLY | O_BINARY);
    if (self->fd == -1) {
        return;
    }

    if (fstat(self->fd, &self->sb) == -1) {
        close(self->fd);
        self->fd = -1;
        return;
    }

    self->_base_size = self->sb.st_size;

    /* Using mmap for simplicity and performance */
#ifdef _WIN32
    /* MinGW mmap implementation or simple read */
    /* For standard POSIX mmap */
    /* If strict ISO C is required without mman, we would use malloc + fread */
    /* Assuming a standard UNIX-like environment or MinGW with mman support or fallback */
    /* Let's implement a malloc fallback if MMAP is not available/desired for library usage */
#endif

    /* Using malloc + read to be safer and more portable as a library function */
    self->_base = (uint8_t*)malloc(self->_base_size);
    if (!self->_base) {
        close(self->fd);
        self->fd = -1;
        return;
    }

    if (read(self->fd, self->_base, self->_base_size) != (ssize_t)self->_base_size) {
        free(self->_base);
        self->_base = NULL;
        close(self->fd);
        self->fd = -1;
        return;
    }

    self->file_read = true;

    if (self->_base_size > sizeof(IMAGE_DOS_HEADER)) {
        self->dos = (IMAGE_DOS_HEADER*)self->_base;
        if (self->dos->e_magic == 0x5A4D) { /* MZ */
             if (self->dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) < self->_base_size) {
                 self->pe = (IMAGE_NT_HEADERS32*)(self->_base + self->dos->e_lfanew);
                 self->sections = IMAGE_FIRST_SECTION(self->pe);
             }
        }
    }
}

void ExeState_C_Destroy(ExeState_C *self) {
    if (self->_base) {
        free(self->_base);
        self->_base = NULL;
    }
    if (self->fd != -1) {
        close(self->fd);
        self->fd = -1;
    }
    if (self->filename) {
        free(self->filename);
        self->filename = NULL;
    }
}

uint8_t* ExeState_C_base(ExeState_C *self) {
    return self->_base;
}

uint32_t ExeState_C_rva_to_raw(ExeState_C *self, uint32_t rva, bool relative) {
    if (!self->pe || !self->sections) return 0;

    for (int i = 0; i < self->pe->FileHeader.NumberOfSections; i++) {
        if (rva >= self->sections[i].VirtualAddress &&
            rva < self->sections[i].VirtualAddress + self->sections[i].Misc.VirtualSize) {

            return rva - self->sections[i].VirtualAddress + self->sections[i].PointerToRawData;
        }
    }
    return 0;
}

uint32_t ExeState_C_va_to_raw(ExeState_C *self, uint32_t va) {
    /* VA = ImageBase + RVA */
    if (!self->pe) return 0;
    return ExeState_C_rva_to_raw(self, va - self->pe->OptionalHeader.ImageBase, true);
}

uint32_t ExeState_C_raw_to_rva(ExeState_C *self, uint32_t raw, bool relative) {
     if (!self->pe || !self->sections) return 0;

    for (int i = 0; i < self->pe->FileHeader.NumberOfSections; i++) {
        if (raw >= self->sections[i].PointerToRawData &&
            raw < self->sections[i].PointerToRawData + self->sections[i].SizeOfRawData) {

            return raw - self->sections[i].PointerToRawData + self->sections[i].VirtualAddress;
        }
    }
    return 0;
}

uint32_t ExeState_C_raw_to_va(ExeState_C *self, uint32_t raw) {
    if (!self->pe) return 0;
    return ExeState_C_raw_to_rva(self, raw, true) + self->pe->OptionalHeader.ImageBase;
}

uint32_t ExeState_C_rva_to_va(ExeState_C *self, uint32_t rva) {
    if (!self->pe) return 0;
    return rva + self->pe->OptionalHeader.ImageBase;
}

IMAGE_SECTION_HEADER* ExeState_C_find_section(ExeState_C *self, const char *section_name) {
    if (!self->pe || !self->sections) return NULL;

    for (int i = 0; i < self->pe->FileHeader.NumberOfSections; i++) {
        /* Section names are not necessarily null terminated if they fill 8 chars */
        if (strncmp((const char*)self->sections[i].Name, section_name, 8) == 0) {
            return &self->sections[i];
        }
    }
    return NULL;
}
