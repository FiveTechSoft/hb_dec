#include "writer_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

void StringBuffer_Init(StringBuffer *self) {
    self->size = 0;
    self->capacity = 1024;
    self->data = (char*)malloc(self->capacity);
    self->data[0] = 0;
}

void StringBuffer_Destroy(StringBuffer *self) {
    if (self->data) {
        free(self->data);
        self->data = NULL;
    }
}

void StringBuffer_Append(StringBuffer *self, const char *str) {
    size_t len = strlen(str);
    if (self->size + len + 1 > self->capacity) {
        size_t new_cap = self->capacity * 2;
        while (self->size + len + 1 > new_cap) new_cap *= 2;
        self->data = (char*)realloc(self->data, new_cap);
        self->capacity = new_cap;
    }
    memcpy(self->data + self->size, str, len);
    self->size += len;
    self->data[self->size] = 0;
}

void StringBuffer_AppendF(StringBuffer *self, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    int len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (len < 0) return;

    if (self->size + len + 1 > self->capacity) {
        size_t new_cap = self->capacity * 2;
        while (self->size + len + 1 > new_cap) new_cap *= 2;
        self->data = (char*)realloc(self->data, new_cap);
        self->capacity = new_cap;
    }

    va_start(args, fmt);
    vsnprintf(self->data + self->size, len + 1, fmt, args);
    va_end(args);

    self->size += len;
}

void StringBuffer_Clear(StringBuffer *self) {
    self->size = 0;
    if (self->data) self->data[0] = 0;
}

/* --- writer_c --- */

void writer_c_Init(writer_c *self, StringBuffer *output_buffer) {
    memset(self->m_offset, 0, sizeof(self->m_offset));
    memset(self->m_bytecode, 0, sizeof(self->m_bytecode));
    memset(self->m_instructions, 0, sizeof(self->m_instructions));
    memset(self->m_comment, 0, sizeof(self->m_comment));

    self->BYTECODE_MAX_LENGHT = 30;
    self->INSTRUCTIONS_MAX_LEN = 30;
    self->output_buffer = output_buffer;
}

void writer_c_offset(writer_c *self, uint32_t offset) {
    snprintf(self->m_offset, sizeof(self->m_offset), "%08x", offset);
}

void writer_c_bytecode(writer_c *self, const uint8_t *src, size_t len) {
    /* Format bytecode hex string */
    /* Only format up to buffer limits */

    char tmp[128];
    tmp[0] = 0;

    size_t max_len = self->BYTECODE_MAX_LENGHT;
    /* Adjust for "..." and spacing logic */
    /* Roughly simulating original logic */

    size_t current_len = 0;
    for (size_t i = 0; i < len; i++) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X%s", src[i], (i == len - 1) ? "" : " ");

        if (current_len + strlen(hex) >= max_len - 3) { /* leave room for ... */
             strcat(tmp, "...");
             break;
        }
        strcat(tmp, hex);
        current_len += strlen(hex);
    }

    /* Pad with spaces */
    snprintf(self->m_bytecode, sizeof(self->m_bytecode), "%-*s", (int)self->BYTECODE_MAX_LENGHT, tmp);
}

void writer_c_bytecode_empty(writer_c *self) {
    snprintf(self->m_bytecode, sizeof(self->m_bytecode), "%-*s", (int)self->BYTECODE_MAX_LENGHT, " ");
}

void writer_c_instructions(writer_c *self, const char *format, ...) {
    char tmp[256];
    va_list args;
    va_start(args, format);
    vsnprintf(tmp, sizeof(tmp), format, args);
    va_end(args);

    snprintf(self->m_instructions, sizeof(self->m_instructions), "%-*s", (int)self->INSTRUCTIONS_MAX_LEN, tmp);
}

void writer_c_comment(writer_c *self, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(self->m_comment, sizeof(self->m_comment), format, args);
    va_end(args);
}

void writer_c_print(writer_c *self) {
    if (self->output_buffer) {
        StringBuffer_AppendF(self->output_buffer, "%s  %s%s%s\n",
            self->m_offset,
            self->m_bytecode,
            self->m_instructions,
            self->m_comment);
    }
}

void writer_c_clear(writer_c *self) {
    self->m_offset[0] = 0;
    self->m_bytecode[0] = 0;
    self->m_instructions[0] = 0;
    self->m_comment[0] = 0;
}
