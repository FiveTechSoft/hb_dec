#ifndef HARBOUR_DECOMPILER_C_H
#define HARBOUR_DECOMPILER_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include "harbour_helper_c.h"
#include "writer_c.h"

typedef struct {
    executable_hb_c *m_hb_ctx;
    writer_c m_writer;
    uint32_t m_offset;
} harbour_decompiler_c;

void harbour_decompiler_c_Init(harbour_decompiler_c *self, executable_hb_c *hb_ctx, StringBuffer *output_buffer);
void harbour_decompiler_c_function_decompile(harbour_decompiler_c *self, executable_hb_symbol_c *hb_symb_and_pcode);

#ifdef __cplusplus
}
#endif

#endif
