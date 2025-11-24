#include "harbour_helper_c.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* --- executable_hb_symbol_c --- */

void executable_hb_symbol_c_Init(executable_hb_symbol_c *self, const char *name, intptr_t scope, intptr_t value, intptr_t dynsym) {
    memset(self, 0, sizeof(executable_hb_symbol_c));
    executable_hb_symbol_c_SetName(self, name);
    self->base.scope.value = (uint16_t)scope;
    self->base.value.pCodeFunc = (void*)value;
    self->base.pDynSym = (void*)dynsym;
}

void executable_hb_symbol_c_Destroy(executable_hb_symbol_c *self) {
    if (self->szName_copy) {
        free(self->szName_copy);
        self->szName_copy = NULL;
    }
    if (self->pcode) {
        free(self->pcode);
        self->pcode = NULL;
    }
}

const char* executable_hb_symbol_c_Name(executable_hb_symbol_c *self) {
    return self->szName_copy;
}

void executable_hb_symbol_c_SetName(executable_hb_symbol_c *self, const char *newName) {
    if (self->szName_copy) {
        free(self->szName_copy);
        self->szName_copy = NULL;
    }
    if (newName) {
        self->szName_copy = strdup(newName);
        self->base.szName = self->szName_copy; /* Keep HB_SYMB member in sync if used */
    }
}

bool executable_hb_symbol_c_is_symbol_function(executable_hb_symbol_c *self) {
    return (self->base.scope.value & HB_FS_LOCAL) ? true : false;
}

/* --- executable_hb_c --- */

void executable_hb_c_Init(executable_hb_c *self, ExeState_C *exe_state) {
    self->exe_state = exe_state;
    self->BCC = false;
    self->MINGW = false;
    self->hb_source_name = NULL;
    self->hb_symbols = NULL;
    self->hb_symbols_count = 0;
    self->hb_symbols_capacity = 0;
    self->hb_symbols_functions_sorted = NULL;
    self->hb_symbols_functions_sorted_count = 0;
}

void executable_hb_c_Destroy(executable_hb_c *self) {
    if (self->hb_source_name) {
        free(self->hb_source_name);
        self->hb_source_name = NULL;
    }

    if (self->hb_symbols) {
        for (size_t i = 0; i < self->hb_symbols_count; i++) {
            executable_hb_symbol_c_Destroy(self->hb_symbols[i]);
            free(self->hb_symbols[i]);
        }
        free(self->hb_symbols);
        self->hb_symbols = NULL;
    }

    if (self->hb_symbols_functions_sorted) {
        free(self->hb_symbols_functions_sorted);
        self->hb_symbols_functions_sorted = NULL;
    }
}

/* memmem implementation helper since it might be missing */
static void *my_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    const char *h = (const char*)haystack;
    const char *n = (const char*)needle;
    if (needlelen == 0) return (void *)h;
    if (haystacklen < needlelen) return NULL;

    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

bool executable_hb_c_find_hb_source_name(executable_hb_c *self) {
    const char *search_key = ".prg";
    uint8_t *src_name_search = (uint8_t*)my_memmem(
        self->exe_state->_base,
        self->exe_state->_base_size,
        search_key,
        strlen(search_key) + 1 /* include null terminator for search? Original code uses length+1 */
    );

    if (src_name_search) {
        uint8_t *src_ptr = src_name_search;
        uint32_t src_name_len = 0;

        while (*(--src_ptr) != 0) {
            src_name_len++;
        }
        src_name_search = src_name_search - src_name_len;
        src_name_len += 4; /* .prg */

        if (self->hb_source_name) free(self->hb_source_name);
        self->hb_source_name = (char*)malloc(src_name_len + 1);
        memcpy(self->hb_source_name, src_name_search, src_name_len);
        self->hb_source_name[src_name_len] = 0;

        return true;
    }
    return false;
}

uint32_t executable_hb_c_pe_find_hb_symbols_table(executable_hb_c *self) {
    uint32_t hb_symbols_table_raw_offset = 0;
    const char *bcc_hook_name = "fb:C++HOOK\x90\xE9";
    size_t bcc_hook_len = 12;

    void *cpp_debug_hook_offset = my_memmem(self->exe_state->_base, self->exe_state->_base_size, bcc_hook_name, bcc_hook_len);

    if (cpp_debug_hook_offset) {
        self->BCC = true;
        uint32_t *CPPdebugHook_va_address = (uint32_t*)((uint8_t*)cpp_debug_hook_offset + bcc_hook_len);
        uint32_t CPPdebugHook_offset_raw = ExeState_C_va_to_raw(self->exe_state, *CPPdebugHook_va_address);
        uint32_t *CPPdebugHook_offset_ptr = (uint32_t*)(self->exe_state->_base + CPPdebugHook_offset_raw);

        if (CPPdebugHook_offset_ptr[0] + CPPdebugHook_offset_ptr[1] + CPPdebugHook_offset_ptr[2] != 0) {
            return 0;
        }
        hb_symbols_table_raw_offset = CPPdebugHook_offset_raw + 12;
        return hb_symbols_table_raw_offset;
    }

    /* MINGW check */
    uint8_t MINGW_usual_padding_to_symbols_table = 0x20;
    IMAGE_SECTION_HEADER *data_section = ExeState_C_find_section(self->exe_state, ".data");

    if (!data_section) return 0;

    uint32_t *_data_start_raw_offset = (uint32_t*)(self->exe_state->_base + data_section->PointerToRawData);
    uint32_t _data_start_va = ExeState_C_rva_to_va(self->exe_state, data_section->VirtualAddress);

    size_t i = 20;
    while ((*_data_start_raw_offset - _data_start_va != MINGW_usual_padding_to_symbols_table)) {
        _data_start_raw_offset = (uint32_t*)(self->exe_state->_base + data_section->PointerToRawData + i * sizeof(uint32_t));
        _data_start_va = ExeState_C_raw_to_va(self->exe_state, data_section->PointerToRawData + i * sizeof(uint32_t));
        if (--i == 0) return 0;
    }

    if (*_data_start_raw_offset - _data_start_va == MINGW_usual_padding_to_symbols_table) {
        self->MINGW = true;
    } else {
        return 0;
    }

    hb_symbols_table_raw_offset = ExeState_C_va_to_raw(self->exe_state, *_data_start_raw_offset);
    return hb_symbols_table_raw_offset;
}

executable_hb_symbol_c* executable_hb_c_create_hb_symbol(executable_hb_c *self) {
    if (self->hb_symbols_count == self->hb_symbols_capacity) {
        size_t new_cap = self->hb_symbols_capacity == 0 ? 16 : self->hb_symbols_capacity * 2;
        executable_hb_symbol_c **new_arr = (executable_hb_symbol_c**)realloc(self->hb_symbols, new_cap * sizeof(executable_hb_symbol_c*));
        if (!new_arr) return NULL;
        self->hb_symbols = new_arr;
        self->hb_symbols_capacity = new_cap;
    }

    executable_hb_symbol_c *sym = (executable_hb_symbol_c*)malloc(sizeof(executable_hb_symbol_c));
    /* init will be called by caller or here? */
    /* Initialize with defaults just in case */
    executable_hb_symbol_c_Init(sym, NULL, 0, 0, 0);

    self->hb_symbols[self->hb_symbols_count++] = sym;
    return sym;
}

bool executable_hb_c_pe_read_hb_symbols_table(executable_hb_c *self, uint32_t hb_symbols_table_raw_offset) {
    uint32_t hb_symbols_table_va = ExeState_C_raw_to_va(self->exe_state, hb_symbols_table_raw_offset);
    uint32_t *hb_symb_ptr = (uint32_t*)(self->exe_state->_base + hb_symbols_table_raw_offset);
    uint32_t first_hb_symb_name_offset = 0;

    while (1) {
        if (hb_symb_ptr[0] + hb_symb_ptr[1] + hb_symb_ptr[2] + hb_symb_ptr[3] == 0) break; /* mingw end */
        if (hb_symb_ptr[0] == 0) break; /* mingw end alternate */
        if (hb_symb_ptr[0] == hb_symbols_table_va) break; /* bcc end */
        if (ExeState_C_va_to_raw(self->exe_state, hb_symb_ptr[0]) == 0) break; /* invalid */

        executable_hb_symbol_c *sym = executable_hb_c_create_hb_symbol(self);
        uint8_t *name_ptr = self->exe_state->_base + ExeState_C_va_to_raw(self->exe_state, hb_symb_ptr[0]);

        if (first_hb_symb_name_offset == 0) {
            first_hb_symb_name_offset = hb_symb_ptr[0];
        }

        executable_hb_symbol_c_SetName(sym, (char*)name_ptr);
        sym->base.scope.value = (uint16_t)hb_symb_ptr[1];
        sym->base.value.pCodeFunc = (void*)(uintptr_t)hb_symb_ptr[2];
        sym->base.pDynSym = (void*)(uintptr_t)hb_symb_ptr[3];

        if (executable_hb_symbol_c_is_symbol_function(sym)) {
            uint8_t *ev_func = self->exe_state->_base + ExeState_C_va_to_raw(self->exe_state, (uint32_t)(uintptr_t)sym->base.value.pCodeFunc);

            if (ev_func[0] == 0xA1 && ev_func[5] == 0x50 && ev_func[6] == 0x68) { /* BCC */
                uint32_t pcode_offset = *(uint32_t*)(ev_func + 7);
                sym->pcode_va_start = pcode_offset;
                sym->pcode_va_end = first_hb_symb_name_offset;
            }
            if (ev_func[0] == 0x83 && ev_func[3] == 0xA1 && ev_func[8] == 0xC7) { /* MINGW */
                uint32_t pcode_offset = *(uint32_t*)(ev_func + 11);
                sym->pcode_va_start = pcode_offset;
                sym->pcode_va_end = first_hb_symb_name_offset;
            }
        }

        hb_symb_ptr += 4;
    }

    return (self->hb_symbols_count > 0);
}

static int symbol_va_compare(const void *a, const void *b) {
    const executable_hb_symbol_c *s1 = *(const executable_hb_symbol_c**)a;
    const executable_hb_symbol_c *s2 = *(const executable_hb_symbol_c**)b;
    if (s1->pcode_va_start < s2->pcode_va_start) return -1;
    if (s1->pcode_va_start > s2->pcode_va_start) return 1;
    return 0;
}

bool executable_hb_c_hb_symbols_fill_pcode(executable_hb_c *self) {
    /* Collect function symbols */
    size_t func_count = 0;
    for (size_t i = 0; i < self->hb_symbols_count; i++) {
        if (executable_hb_symbol_c_is_symbol_function(self->hb_symbols[i])) {
            func_count++;
        }
    }

    self->hb_symbols_functions_sorted = (executable_hb_symbol_c**)malloc(func_count * sizeof(executable_hb_symbol_c*));
    self->hb_symbols_functions_sorted_count = 0;

    for (size_t i = 0; i < self->hb_symbols_count; i++) {
        if (executable_hb_symbol_c_is_symbol_function(self->hb_symbols[i])) {
            self->hb_symbols_functions_sorted[self->hb_symbols_functions_sorted_count++] = self->hb_symbols[i];
        }
    }

    /* Sort */
    qsort(self->hb_symbols_functions_sorted, self->hb_symbols_functions_sorted_count, sizeof(executable_hb_symbol_c*), symbol_va_compare);

    /* Fill sizes and pcode */
    for (size_t i = 0; i < self->hb_symbols_functions_sorted_count; i++) {
        executable_hb_symbol_c *sym = self->hb_symbols_functions_sorted[i];

        if (i < self->hb_symbols_functions_sorted_count - 1) {
            sym->pcode_va_end = self->hb_symbols_functions_sorted[i+1]->pcode_va_start;
        }

        sym->pcode_size = sym->pcode_va_end - sym->pcode_va_start;

        uint32_t raw_start = ExeState_C_va_to_raw(self->exe_state, sym->pcode_va_start);
        const uint8_t *pcode_ptr = self->exe_state->_base + raw_start;

        /* Trim trailing nulls? Original code does it */
        while (sym->pcode_size > 0 && pcode_ptr[sym->pcode_size - 1] == 0) {
            sym->pcode_size--;
        }

        sym->pcode = (char*)malloc(sym->pcode_size);
        memcpy(sym->pcode, pcode_ptr, sym->pcode_size);
    }

    return true;
}
