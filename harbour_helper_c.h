#ifndef HARBOUR_HELPER_C_H
#define HARBOUR_HELPER_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pe_helper_c.h"
#include "include/harbour/hbvmpub.h"
#include "include/harbour/hbpcode.h"
/* #include "include/harbour/hbpcode_awked.h" - Removed to avoid multiple definitions */
#include <stdint.h>

/* Declare extern if needed by others, but mostly likely only used by decompiler */
extern const HB_BYTE hb_comp_pcode_len[];

typedef struct {
    HB_SYMB base; /* Embed the HB_SYMB struct */

    char *szName_copy; /* Helper to store dynamic name if needed */

    /* PCODE info */
    char *pcode; /* Raw pcode bytes */
    size_t pcode_size;

    uint32_t pcode_va_start;
    uint32_t pcode_va_end;

} executable_hb_symbol_c;

/* Helper functions for symbol */
void executable_hb_symbol_c_Init(executable_hb_symbol_c *self, const char *name, intptr_t scope, intptr_t value, intptr_t dynsym);
void executable_hb_symbol_c_Destroy(executable_hb_symbol_c *self);
const char* executable_hb_symbol_c_Name(executable_hb_symbol_c *self);
void executable_hb_symbol_c_SetName(executable_hb_symbol_c *self, const char *newName);
bool executable_hb_symbol_c_is_symbol_function(executable_hb_symbol_c *self);

typedef struct {
    ExeState_C *exe_state;
    bool BCC;
    bool MINGW;
    char *hb_source_name;

    /* Array of pointers to symbols */
    executable_hb_symbol_c **hb_symbols;
    size_t hb_symbols_count;
    size_t hb_symbols_capacity;

    /* Array of pointers to symbols, sorted by VA */
    executable_hb_symbol_c **hb_symbols_functions_sorted;
    size_t hb_symbols_functions_sorted_count;

} executable_hb_c;

void executable_hb_c_Init(executable_hb_c *self, ExeState_C *exe_state);
void executable_hb_c_Destroy(executable_hb_c *self);

bool executable_hb_c_find_hb_source_name(executable_hb_c *self);
uint32_t executable_hb_c_pe_find_hb_symbols_table(executable_hb_c *self);
bool executable_hb_c_pe_read_hb_symbols_table(executable_hb_c *self, uint32_t hb_symbols_table_raw_offset);
executable_hb_symbol_c* executable_hb_c_create_hb_symbol(executable_hb_c *self);
bool executable_hb_c_hb_symbols_fill_pcode(executable_hb_c *self);

#ifdef __cplusplus
}
#endif

#endif
