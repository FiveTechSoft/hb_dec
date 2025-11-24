#include "harbour_decompiler_c.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef HB_DECOMPILER_STANDALONE

int main(int argc, char **argv) {
    if (argc == 1) {
        printf("usage: %s <hb_executable>\n", argv[0]);
        return 1;
    }

    ExeState_C state;
    ExeState_C_Init(&state, argv[1]);

    if (!state.file_read) {
        printf("Error reading file\n");
        return 1;
    }

    if (*(uint16_t*)ExeState_C_base(&state) != 0x5A4D) {
        printf("it is not PE file\n");
        return 1;
    }

    executable_hb_c hb_ctx;
    executable_hb_c_Init(&hb_ctx, &state);

    if (executable_hb_c_find_hb_source_name(&hb_ctx)) {
        printf("Found hb source filename: %s\n", hb_ctx.hb_source_name);
    } else {
        printf("Found hb source filename not found\n");
    }

    uint32_t first_hb_symb_offset_raw = executable_hb_c_pe_find_hb_symbols_table(&hb_ctx);
    if (!first_hb_symb_offset_raw) {
        printf("hb symbols find error\n");
        return 1;
    }

    if (!executable_hb_c_pe_read_hb_symbols_table(&hb_ctx, first_hb_symb_offset_raw)) {
        printf("hb symbols read error\n");
        return 1;
    }

    executable_hb_c_hb_symbols_fill_pcode(&hb_ctx);

    StringBuffer output;
    StringBuffer_Init(&output);

    harbour_decompiler_c decompiler;
    harbour_decompiler_c_Init(&decompiler, &hb_ctx, &output);

    for (size_t i = 0; i < hb_ctx.hb_symbols_functions_sorted_count; i++) {
        executable_hb_symbol_c *symbol = hb_ctx.hb_symbols_functions_sorted[i];
        printf("PCODE for local function %s pcode size %zX\n\n", executable_hb_symbol_c_Name(symbol), symbol->pcode_size);
        if (symbol->pcode_size) {
            harbour_decompiler_c_function_decompile(&decompiler, symbol);
        }
    }

    printf("%s", output.data);

    StringBuffer_Destroy(&output);
    executable_hb_c_Destroy(&hb_ctx);
    ExeState_C_Destroy(&state);

    return 0;
}

#else

/* Harbour Entry Point */
#include "hbapi.h"

HB_FUNC( HB_DEC_DECOMPILE ) {
    const char *filename = hb_parc(1);
    if (!filename) {
        hb_retc("");
        return;
    }

    ExeState_C state;
    ExeState_C_Init(&state, filename);

    if (!state.file_read) {
        hb_retc("");
        return;
    }

    executable_hb_c hb_ctx;
    executable_hb_c_Init(&hb_ctx, &state);

    /* Optional: Find source name (not critical for decompile string) */
    executable_hb_c_find_hb_source_name(&hb_ctx);

    uint32_t first_hb_symb_offset_raw = executable_hb_c_pe_find_hb_symbols_table(&hb_ctx);
    if (!first_hb_symb_offset_raw) {
        executable_hb_c_Destroy(&hb_ctx);
        ExeState_C_Destroy(&state);
        hb_retc("");
        return;
    }

    if (!executable_hb_c_pe_read_hb_symbols_table(&hb_ctx, first_hb_symb_offset_raw)) {
        executable_hb_c_Destroy(&hb_ctx);
        ExeState_C_Destroy(&state);
        hb_retc("");
        return;
    }

    executable_hb_c_hb_symbols_fill_pcode(&hb_ctx);

    StringBuffer output;
    StringBuffer_Init(&output);

    harbour_decompiler_c decompiler;
    harbour_decompiler_c_Init(&decompiler, &hb_ctx, &output);

    for (size_t i = 0; i < hb_ctx.hb_symbols_functions_sorted_count; i++) {
        executable_hb_symbol_c *symbol = hb_ctx.hb_symbols_functions_sorted[i];

        StringBuffer_AppendF(&output, "/* PCODE for local function %s pcode size %zX */\n\n", executable_hb_symbol_c_Name(symbol), symbol->pcode_size);

        if (symbol->pcode_size) {
            harbour_decompiler_c_function_decompile(&decompiler, symbol);
        }
    }

    /* Return the accumulated string */
    hb_retc(output.data);

    StringBuffer_Destroy(&output);
    executable_hb_c_Destroy(&hb_ctx);
    ExeState_C_Destroy(&state);
}

#endif
