#ifndef WRITER_C_H
#define WRITER_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* Simple string buffer implementation */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} StringBuffer;

void StringBuffer_Init(StringBuffer *self);
void StringBuffer_Destroy(StringBuffer *self);
void StringBuffer_Append(StringBuffer *self, const char *str);
void StringBuffer_AppendF(StringBuffer *self, const char *fmt, ...);
void StringBuffer_Clear(StringBuffer *self);

typedef struct {
    char m_offset[32];
    char m_bytecode[128]; /* Fixed buffer for bytecode hex representation */
    char m_instructions[256];
    char m_comment[256];

    size_t BYTECODE_MAX_LENGHT;
    size_t INSTRUCTIONS_MAX_LEN;

    /* Accumulator for the full output */
    StringBuffer *output_buffer;

} writer_c;

void writer_c_Init(writer_c *self, StringBuffer *output_buffer);
void writer_c_offset(writer_c *self, uint32_t offset);
void writer_c_bytecode(writer_c *self, const uint8_t *src, size_t len);
void writer_c_bytecode_empty(writer_c *self);
void writer_c_instructions(writer_c *self, const char *format, ...);
void writer_c_comment(writer_c *self, const char *format, ...);
void writer_c_print(writer_c *self);
void writer_c_clear(writer_c *self);

#ifdef __cplusplus
}
#endif

#endif
