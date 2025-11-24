#include "harbour_decompiler_c.h"
#include "include/harbour/hbpcode_awked.h" /* Defined here */
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

void harbour_decompiler_c_Init(harbour_decompiler_c *self, executable_hb_c *hb_ctx, StringBuffer *output_buffer) {
    self->m_hb_ctx = hb_ctx;
    self->m_offset = 0;
    writer_c_Init(&self->m_writer, output_buffer);
}

void harbour_decompiler_c_function_decompile(harbour_decompiler_c *self, executable_hb_symbol_c *hb_symb_and_pcode) {
    const uint8_t *pcode_ptr = (const uint8_t*)hb_symb_and_pcode->pcode;
    const uint8_t *pcode_base = pcode_ptr;

    uint32_t bytecode_len = 0;
    uint32_t offset = 0;

    while (1) {
        writer_c_offset(&self->m_writer, offset);

        if (*pcode_ptr < HB_P_LAST_PCODE) {
            bytecode_len = hb_comp_pcode_len[*pcode_ptr];
            writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
        }

        switch (*pcode_ptr) {
            case HB_P_AND:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() & pop() )");
                writer_c_comment(&self->m_writer, "/* logical AND of two latest stack values */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ARRAYPUSH:
            {
                writer_c_instructions(&self->m_writer, "<ARRAY INDEX> = pop()");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                writer_c_offset(&self->m_writer, offset);
                writer_c_bytecode_empty(&self->m_writer);
                writer_c_instructions(&self->m_writer, "<ARRAY obj> = pop()");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                writer_c_offset(&self->m_writer, offset);
                writer_c_bytecode_empty(&self->m_writer);
                writer_c_instructions(&self->m_writer, "push <ARRAY obj>[<ARRAY INDEX>]");
                writer_c_comment(&self->m_writer, "/* push value from INDEX of ARRAY object variable to stack*/");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ARRAYPOP:
            {
                writer_c_instructions(&self->m_writer, "<ARRAY INDEX> = pop()");
                writer_c_comment(&self->m_writer, "/* mov value from stack to INDEX of ARRAY object variable*/");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                writer_c_offset(&self->m_writer, offset);
                writer_c_bytecode_empty(&self->m_writer);
                writer_c_instructions(&self->m_writer, "<ARRAY obj> = pop()");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                writer_c_offset(&self->m_writer, offset);
                writer_c_bytecode_empty(&self->m_writer);
                writer_c_instructions(&self->m_writer, "<ARRAY obj>[<ARRAY INDEX>] = pop()");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ARRAYDIM:
            {
                writer_c_instructions(&self->m_writer, "ARRAYDIM %d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* instruct VM to build an array with %d dimensions */", *(uint16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ARRAYGEN:
            {
                writer_c_instructions(&self->m_writer, "push <new ARRAY obj> = pop(%d)", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* creating an ARRAY object and pushing %d elements from stack */", *(uint16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_EQUAL:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() == pop()");
                writer_c_comment(&self->m_writer, "/* compare last two params (param == param1) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENDBLOCK:
            {
                writer_c_instructions(&self->m_writer, "ret");
                writer_c_comment(&self->m_writer, "/* end of CODEBLOCK */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENDPROC:
            {
                writer_c_instructions(&self->m_writer, "end proc");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_EXACTLYEQUAL:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() == pop() )");
                writer_c_comment(&self->m_writer, "/* compare last two params (param == param1) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FALSE:
            {
                writer_c_instructions(&self->m_writer, "push FALSE");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FORTEST:
            {
                writer_c_instructions(&self->m_writer, "FORTEST");
                writer_c_comment(&self->m_writer, "/* For STEP. If step > 1 less. If step < 1 greater */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FUNCTION:
            {
                writer_c_instructions(&self->m_writer, "call %X", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* call a function from stack saving its result */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                writer_c_offset(&self->m_writer, offset);
                writer_c_bytecode_empty(&self->m_writer);
                writer_c_instructions(&self->m_writer, "push eax");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FUNCTIONSHORT:
            {
                writer_c_instructions(&self->m_writer, "call %X", pcode_ptr[1]);
                writer_c_comment(&self->m_writer, "/* call a function from stack saving its result */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                writer_c_offset(&self->m_writer, offset);
                writer_c_bytecode_empty(&self->m_writer);
                writer_c_instructions(&self->m_writer, "push eax");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FRAME:
            {
                writer_c_instructions(&self->m_writer, "");
                writer_c_comment(&self->m_writer, "/* function frame has %d locals and %d parameters */", pcode_ptr[1], pcode_ptr[2]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_FUNCPTR:
            {
                writer_c_instructions(&self->m_writer, "push @FunPtr");
                writer_c_comment(&self->m_writer, "/* returns a function address pointer */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_GREATER:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() > pop() )");
                writer_c_comment(&self->m_writer, "/* compare last two params (param > param1)  */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_GREATEREQUAL:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() >= pop() )");
                writer_c_comment(&self->m_writer, "/* compare last two params (param >= param1)  */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DEC:
            {
                writer_c_instructions(&self->m_writer, "push --pop()");
                writer_c_comment(&self->m_writer, "/* decrements lats stack value*/");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DIVIDE:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() / pop() )");
                writer_c_comment(&self->m_writer, "/* divides the latest two values on the stack, removing them and leaving the result param1 / param */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DO:
            {
                writer_c_instructions(&self->m_writer, "call %X", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* call a function from STACK and discard the results */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DOSHORT:
            {
                writer_c_instructions(&self->m_writer, "call %X", pcode_ptr[1]);
                writer_c_comment(&self->m_writer, "/* call a function from STACK[-%d] and discard the results */", pcode_ptr[1]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DUPLICATE:
            {
                writer_c_instructions(&self->m_writer, "push STACK[-1]");
                writer_c_comment(&self->m_writer, "/* push copy of prev value one more time */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHTIMESTAMP:
            {
                writer_c_instructions(&self->m_writer, "push TIMESTAMP %" PRIx64, *(uint64_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* places a timestamp constant value on the virtual machine stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_INC:
            {
                writer_c_instructions(&self->m_writer, "push ++pop()");
                writer_c_comment(&self->m_writer, "/* increments last stack value*/");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_INSTRING:
            {
                writer_c_instructions(&self->m_writer, "push ( strstr( pop(), pop() ) > 0 )");
                writer_c_comment(&self->m_writer, "/* checks if last(-2) stack value is a substring of the latest one */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPNEAR:
            {
                writer_c_instructions(&self->m_writer, "jmp near %X", offset + (signed char)(pcode_ptr[1]) );
                writer_c_comment(&self->m_writer, "/* jump to EIP + ( %d ) = %X )*/",*(signed char *)(pcode_ptr + 1), offset + ( (signed char)(pcode_ptr[1]) ) );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMP:
            {
                writer_c_instructions(&self->m_writer, "jmp %X", offset + ( *(int16_t*)(pcode_ptr + 1) ) );
                writer_c_comment(&self->m_writer, "/* jump to EIP + ( %d ) = %X )*/",*(int16_t *)(pcode_ptr + 1), offset + ( *(int16_t*)(pcode_ptr + 1) ) );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPFAR:
            {
                int32_t jump_off = (pcode_ptr[1]) | (pcode_ptr[2]<<8) | (pcode_ptr[3]<<16);
                if (jump_off & 0x800000) jump_off |= 0xFF000000;
                writer_c_instructions(&self->m_writer, "jmp far %X", offset + jump_off);
                writer_c_comment(&self->m_writer, "/* jump to EIP + ( %d ) = %X )*/", jump_off, offset + jump_off );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPFALSENEAR:
            {
                writer_c_instructions(&self->m_writer, "jmp %X if ( ! pop() ) ", offset + ( (signed char)(pcode_ptr[1]) ));
                writer_c_comment(&self->m_writer, "/* jump on FALSE to EIP + ( %d ) = %X ) */",*(signed char *)(pcode_ptr + 1), offset + ( (signed char)(pcode_ptr[1]) ) );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPFALSE:
            {
                writer_c_instructions(&self->m_writer, "jmp %X if ( ! pop() ) ", offset + ( *(int16_t*)(pcode_ptr+1) ) );
                writer_c_comment(&self->m_writer, "/* jump on previous stack FALSE value to EIP + ( %d ) = %X ), if (not BOOL) -> jmp*/",*(int16_t*)(pcode_ptr + 1), offset + ( *(int16_t*)(pcode_ptr+1) ) );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPFALSEFAR:
            {
                int32_t jump_off = (pcode_ptr[1]) | (pcode_ptr[2]<<8) | (pcode_ptr[3]<<16);
                if (jump_off & 0x800000) jump_off |= 0xFF000000;
                writer_c_instructions(&self->m_writer, "jmp far %X if ( ! pop() )", offset + jump_off);
                writer_c_comment(&self->m_writer, "/* jump on FALSE to EIP + ( %d ) = %X )*/", jump_off, offset + jump_off );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPTRUENEAR:
            {
                writer_c_instructions(&self->m_writer, "jmp %X if ( pop() )", offset + ( (signed char)(pcode_ptr[1]) ));
                writer_c_comment(&self->m_writer, "/* jump on TRUE to EIP + ( %d ) = %X )*/",*(signed char *)(pcode_ptr + 1), offset + ( (signed char)(pcode_ptr[1]) ) );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPTRUE:
            {
                writer_c_instructions(&self->m_writer, "jmp %X if ( pop() )", offset + ( *(int16_t*)(pcode_ptr + 1) ));
                writer_c_comment(&self->m_writer, "/* jump on TRUE to EIP + ( %d ) = %X )*/", *(int16_t*)(pcode_ptr + 1), offset + ( *(int16_t*)(pcode_ptr + 1) ) );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_JUMPTRUEFAR:
            {
                int32_t jump_off = (pcode_ptr[1]) | (pcode_ptr[2]<<8) | (pcode_ptr[3]<<16);
                if (jump_off & 0x800000) jump_off |= 0xFF000000;
                writer_c_instructions(&self->m_writer, "jmp far %X if ( pop() )", offset + jump_off);
                writer_c_comment(&self->m_writer, "/* jump on TRUE to EIP + ( %d ) = %X )*/", jump_off, offset + jump_off );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LESSEQUAL:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() <= pop() )");
                writer_c_comment(&self->m_writer, "/* compare last two params (param <= param1) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LESS:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() < pop() )");
                writer_c_comment(&self->m_writer, "/* compare last two params (param < param1) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LINE:
            {
                writer_c_instructions(&self->m_writer, "");
                writer_c_comment(&self->m_writer, "/* currently compiled source code line number %d */", *(uint16_t*)&pcode_ptr[1]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LOCALNAME:
            {
                uint32_t name_len = strlen((const char*)(pcode_ptr+1)) + 1;
                writer_c_bytecode(&self->m_writer, pcode_ptr, name_len+1);
                writer_c_instructions(&self->m_writer, "");
                writer_c_comment(&self->m_writer, "/* sets the name of local variable \"%s\" */", pcode_ptr+1);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += (1 + name_len);
                offset += (1 + name_len);
                break;
            }
            case HB_P_MACROPOP:
            {
                writer_c_instructions(&self->m_writer, "MACROPOP");
                writer_c_comment(&self->m_writer, "/* compile and run - pop a value from the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPOPALIASED:
            {
                writer_c_instructions(&self->m_writer, "MACROPOPALIASED");
                writer_c_comment(&self->m_writer, "/* compile and run - pop a field value from the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPUSH:
            {
                writer_c_instructions(&self->m_writer, "MACROPUSH");
                writer_c_comment(&self->m_writer, "/* compile and run - leave the result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROARRAYGEN:
            {
                writer_c_instructions(&self->m_writer, "MACROARRAYGEN");
                writer_c_comment(&self->m_writer, "/* generate array from arguments set on HVM stack { &var } */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPUSHLIST:
            {
                writer_c_instructions(&self->m_writer, "MACROPUSHLIST");
                writer_c_comment(&self->m_writer, "/* compile and run - leave the result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPUSHINDEX:
            {
                writer_c_instructions(&self->m_writer, "MACROPUSHINDEX");
                writer_c_comment(&self->m_writer, "/* push array items using macro array index */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPUSHPARE:
            {
                writer_c_instructions(&self->m_writer, "MACROPUSHPARE");
                writer_c_comment(&self->m_writer, "/* compile and run - leave the result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPUSHALIASED:
            {
                writer_c_instructions(&self->m_writer, "MACROPUSHALIASED");
                writer_c_comment(&self->m_writer, "/* compile and run - leave the field value on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROSYMBOL:
            {
                writer_c_instructions(&self->m_writer, "MACROSYMBOL");
                writer_c_comment(&self->m_writer, "/* compile into a symbol name (used in function calls) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROTEXT:
            {
                writer_c_instructions(&self->m_writer, "MACROTEXT");
                writer_c_comment(&self->m_writer, "/* macro text substitution */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MESSAGE:
            {
                writer_c_instructions(&self->m_writer, "MESSAGE %d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* sends a message to an object */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MINUS:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() - pop() )");
                writer_c_comment(&self->m_writer, "/* subs the latest two values on the stack, removing them and leaving the result (param1 - param) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MODULUS:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() %% pop() )");
                writer_c_comment(&self->m_writer, "/* calculates the modulus of the two values on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MODULENAME:
            {
                uint32_t modulename_len = strlen((const char*)(pcode_ptr+1)) + 1;
                writer_c_bytecode(&self->m_writer, pcode_ptr, modulename_len+1);
                writer_c_instructions(&self->m_writer, "");
                writer_c_comment(&self->m_writer, " /* sets modulename \"%s\" for trace */", pcode_ptr+1);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += (1 + modulename_len);
                offset += (1 + modulename_len);
                break;
            }
            case HB_P_MMESSAGE:
            case HB_P_MPOPALIASEDFIELD:
            case HB_P_MPOPALIASEDVAR:
            case HB_P_MPOPFIELD:
            case HB_P_MPOPMEMVAR:
            case HB_P_MPUSHALIASEDFIELD:
            case HB_P_MPUSHALIASEDVAR:
            {
                writer_c_instructions(&self->m_writer, "MACRO_OP_%X", *pcode_ptr);
                writer_c_comment(&self->m_writer, "/* macro compiler opcode */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MPUSHBLOCK:
            {
                uint16_t blk_len = *(uint16_t*)(pcode_ptr+1);
                writer_c_bytecode(&self->m_writer, pcode_ptr, blk_len);
                writer_c_instructions(&self->m_writer, "MPUSHBLOCK size %d", blk_len);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += blk_len;
                offset += blk_len;
                break;
            }
            case HB_P_MPUSHFIELD:
            case HB_P_MPUSHMEMVAR:
            case HB_P_MPUSHMEMVARREF:
            case HB_P_MPUSHSYM:
            case HB_P_MPUSHVARIABLE:
            {
                writer_c_instructions(&self->m_writer, "MACRO_OP_%X", *pcode_ptr);
                writer_c_comment(&self->m_writer, "/* macro compiler opcode */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MULT:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() * pop() )");
                writer_c_comment(&self->m_writer, "/* multiplies the latest two values on the stack, removing them and leaving the result (param * param1) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_NEGATE:
            {
                writer_c_instructions(&self->m_writer, "push -pop()");
                writer_c_comment(&self->m_writer, "/* numerically negates the latest value on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_NOOP:
            {
                writer_c_instructions(&self->m_writer, "NOOP");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_NOT:
            {
                writer_c_instructions(&self->m_writer, "push !pop()");
                writer_c_comment(&self->m_writer, "/* logically negates the latest value on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_NOTEQUAL:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() != pop() )");
                writer_c_comment(&self->m_writer, "/* compare last two params (param != param1), put result to the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_OR:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() | pop() )");
                writer_c_comment(&self->m_writer, "/* performs the logical OR of two latest stack values */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PARAMETER:
            {
                writer_c_instructions(&self->m_writer, "PARAMETER");
                writer_c_comment(&self->m_writer, "/* creates PRIVATE variables and assigns values to functions parameters */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PLUS:
            {
                writer_c_instructions(&self->m_writer, "push ( pop() + pop() )");
                writer_c_comment(&self->m_writer, "/* adds the latest two values on the stack, removing them and leaving the result (param + param1) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POP:
            {
                writer_c_instructions(&self->m_writer, "pop()");
                writer_c_comment(&self->m_writer, "/* removes the latest value from the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPALIAS:
            {
                writer_c_instructions(&self->m_writer, "POPALIAS");
                writer_c_comment(&self->m_writer, "/* pops the item from the eval stack and selects the current workarea */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPALIASEDFIELD:
            {
                writer_c_instructions(&self->m_writer, "POPALIASEDFIELD");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPALIASEDFIELDNEAR:
            {
                writer_c_instructions(&self->m_writer, "POPALIASEDFIELDNEAR");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPALIASEDVAR:
            {
                writer_c_instructions(&self->m_writer, "POPALIASEDVAR");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPFIELD:
            {
                writer_c_instructions(&self->m_writer, "POPFIELD");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPLOCAL:
            {
                writer_c_instructions(&self->m_writer, "VAR_%d = pop()", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* pops the contents of the virtual machine stack onto a local variable */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPLOCALNEAR:
            {
                writer_c_instructions(&self->m_writer, "VAR_%d = pop()", (signed char)pcode_ptr[1]);
                writer_c_comment(&self->m_writer, "/* pop value from stack to local variable/function param %d)*/", (signed char)pcode_ptr[1]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POPMEMVAR:
            case HB_P_POPSTATIC:
            case HB_P_POPVARIABLE:
            {
                /* Access symbol name via ctx */
                /* C implementation needs to access array correctly */
                /* Assuming m_hb_ctx->hb_symbols index is correct */
                uint16_t idx = *(uint16_t*)(pcode_ptr + 1);
                /* Bounds check omitted for brevity but recommended */
                const char *name = (idx < self->m_hb_ctx->hb_symbols_count) ?
                                   executable_hb_symbol_c_Name(self->m_hb_ctx->hb_symbols[idx]) : "???";

                writer_c_instructions(&self->m_writer, "%s = pop()", name);
                writer_c_comment(&self->m_writer, "/* pop value from stack to local/static/memvar variable %u */", idx);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_POWER:
            {
                writer_c_instructions(&self->m_writer, "push pow( pop(), pop() )");
                writer_c_comment(&self->m_writer, "/* pows the latest two values on the stack, removing them and leaving the result pow(param1, param) */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHALIAS:
            {
                writer_c_instructions(&self->m_writer, "PUSHALIAS");
                writer_c_comment(&self->m_writer, "/* saves the current workarea number on the eval stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHALIASEDFIELD:
            {
                writer_c_instructions(&self->m_writer, "PUSHALIASEDFIELD");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHALIASEDFIELDNEAR:
            {
                writer_c_instructions(&self->m_writer, "PUSHALIASEDFIELDNEAR");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHALIASEDVAR:
            {
                writer_c_instructions(&self->m_writer, "PUSHALIASEDVAR");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHBLOCK:
            {
                bytecode_len = *(uint16_t*)(pcode_ptr + 1);
                writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
                writer_c_instructions(&self->m_writer, "push CODEBLOCK");
                writer_c_comment(&self->m_writer, "/* start of a codeblock definition, codeblock size: %d */", bytecode_len);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                StringBuffer_AppendF(self->m_writer.output_buffer, "{\n");
                {
                    uint16_t parameters = *(uint16_t*)(pcode_ptr + 3);
                    uint16_t locals = *(uint16_t*)(pcode_ptr + 5);
                    StringBuffer_AppendF(self->m_writer.output_buffer, "/* codeblock frame has %d locals and %d parameters */\n", locals, parameters);

                    executable_hb_symbol_c symb_clone;
                    executable_hb_symbol_c_Init(&symb_clone, executable_hb_symbol_c_Name(hb_symb_and_pcode),
                                                hb_symb_and_pcode->base.scope.value,
                                                (intptr_t)hb_symb_and_pcode->base.value.pCodeFunc,
                                                (intptr_t)hb_symb_and_pcode->base.pDynSym);

                    symb_clone.pcode_size = bytecode_len - (8 + (locals << 1));
                    symb_clone.pcode = (char*)malloc(symb_clone.pcode_size);
                    memcpy(symb_clone.pcode, pcode_ptr + 3 + 4 + (locals << 1), symb_clone.pcode_size);

                    harbour_decompiler_c decompiler_local;
                    harbour_decompiler_c_Init(&decompiler_local, self->m_hb_ctx, self->m_writer.output_buffer);
                    harbour_decompiler_c_function_decompile(&decompiler_local, &symb_clone);

                    executable_hb_symbol_c_Destroy(&symb_clone);
                }
                StringBuffer_AppendF(self->m_writer.output_buffer, "}\n");

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHBLOCKSHORT:
            {
                bytecode_len = pcode_ptr[1];
                writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
                writer_c_instructions(&self->m_writer, "push CODEBLOCK");
                writer_c_comment(&self->m_writer, "/* start of a codeblock definition, codeblock size: %d */", bytecode_len);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                StringBuffer_AppendF(self->m_writer.output_buffer, "{\n");
                {
                    executable_hb_symbol_c symb_clone;
                    executable_hb_symbol_c_Init(&symb_clone, executable_hb_symbol_c_Name(hb_symb_and_pcode),
                                                hb_symb_and_pcode->base.scope.value,
                                                (intptr_t)hb_symb_and_pcode->base.value.pCodeFunc,
                                                (intptr_t)hb_symb_and_pcode->base.pDynSym);

                    symb_clone.pcode_size = bytecode_len - 2;
                    symb_clone.pcode = (char*)malloc(symb_clone.pcode_size);
                    memcpy(symb_clone.pcode, pcode_ptr + 2, symb_clone.pcode_size);

                    harbour_decompiler_c decompiler_local;
                    harbour_decompiler_c_Init(&decompiler_local, self->m_hb_ctx, self->m_writer.output_buffer);
                    harbour_decompiler_c_function_decompile(&decompiler_local, &symb_clone);

                    executable_hb_symbol_c_Destroy(&symb_clone);
                }
                StringBuffer_AppendF(self->m_writer.output_buffer, "}\n");

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHFIELD:
            {
                writer_c_instructions(&self->m_writer, "PUSHFIELD");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHBYTE:
            {
                writer_c_instructions(&self->m_writer, "push %X", pcode_ptr[1]);
                writer_c_comment(&self->m_writer, "/* pushes byte integer 0x%X( %d ) to stack */", pcode_ptr[1], (int8_t)pcode_ptr[1]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHINT:
            {
                writer_c_instructions(&self->m_writer, "push %X", *(int16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* push int %d (0x%X) to stack*/", *(int16_t*)(pcode_ptr+1), *(int16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLOCAL:
            {
                writer_c_instructions(&self->m_writer, "push VAR_%d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* pushes the contents of a local variable %d to the stack */", *(uint16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLOCALNEAR:
            {
                writer_c_instructions(&self->m_writer, "push VAR_%d", pcode_ptr[1]);
                writer_c_comment(&self->m_writer, "/* pushes the contents of a local variable %d to the stack (function param) */", pcode_ptr[1]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLOCALREF:
            {
                writer_c_instructions(&self->m_writer, "push &VAR_%d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* pushes the reference of a local variable %d to the stack (function param or variable) */", *(uint16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLONG:
            {
                writer_c_instructions(&self->m_writer, "push %X", *(int32_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* push long %d (0x%X) to stack*/", *(int32_t*)(pcode_ptr+1), *(int32_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHMEMVAR:
            case HB_P_PUSHMEMVARREF:
            {
                uint16_t idx = *(uint16_t*)(pcode_ptr + 1);
                const char *name = (idx < self->m_hb_ctx->hb_symbols_count) ?
                                   executable_hb_symbol_c_Name(self->m_hb_ctx->hb_symbols[idx]) : "???";

                writer_c_instructions(&self->m_writer, "push %s", name);
                writer_c_comment(&self->m_writer, "/* push value from memvar variable %d to stack*/", idx);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHNIL:
            {
                writer_c_instructions(&self->m_writer, "push nill");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHDOUBLE:
            {
                writer_c_instructions(&self->m_writer, "push %lf", *(double*)(pcode_ptr + 1));
                writer_c_comment(&self->m_writer, "/* places a double number %lf (width:%d dec:%d) on the stack */",
                    *(double *)(pcode_ptr + 1),
                    *(int8_t *)(pcode_ptr + 1 + sizeof(double) ),
                    *(int8_t *)(pcode_ptr + 2 + sizeof(double) )
                );
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSELF:
            {
                writer_c_instructions(&self->m_writer, "push Self");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSTATIC:
            {
                writer_c_instructions(&self->m_writer, "push STATIC_%d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* pushes the contents of a static variable %d to the stack */", *(uint16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSTATICREF:
            {
                writer_c_instructions(&self->m_writer, "push &STATIC_%d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* pushes the static variable %d by reference */", *(uint16_t*)(pcode_ptr+1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSTR:
            {
                bytecode_len = 3 + *(uint16_t*)(pcode_ptr + 1);
                writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
                writer_c_instructions(&self->m_writer, "push offset\"%s\"", pcode_ptr + 3);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSTRSHORT:
            {
                bytecode_len = 2 + pcode_ptr[1];
                writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
                writer_c_instructions(&self->m_writer, "push offset \"%s\"", pcode_ptr + 2);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSYM:
            case HB_P_PUSHSYMNEAR:
            {
                /* 107/108 */
                uint16_t idx = ( *pcode_ptr == HB_P_PUSHSYM ) ? *(uint16_t*)(pcode_ptr + 1) : *(uint8_t*)(pcode_ptr + 1);
                const char *name = (idx < self->m_hb_ctx->hb_symbols_count) ?
                                   executable_hb_symbol_c_Name(self->m_hb_ctx->hb_symbols[idx]) : "???";

                writer_c_instructions(&self->m_writer, "push offset %s", name);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHVARIABLE:
            {
                uint16_t idx = *(uint16_t*)(pcode_ptr + 1);
                const char *name = (idx < self->m_hb_ctx->hb_symbols_count) ?
                                   executable_hb_symbol_c_Name(self->m_hb_ctx->hb_symbols[idx]) : "???";

                writer_c_instructions(&self->m_writer, "push offset %s", name);
                writer_c_comment(&self->m_writer, "/* push value from local variable %d to stack*/", pcode_ptr[1]);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_RETVALUE:
            {
                writer_c_instructions(&self->m_writer, "ret");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SEND:
            {
                writer_c_instructions(&self->m_writer, "SEND %d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* send operator */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SENDSHORT:
            {
                writer_c_instructions(&self->m_writer, "SEND %d", pcode_ptr[1]);
                writer_c_comment(&self->m_writer, "/* send operator */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SEQBEGIN:
            {
                writer_c_instructions(&self->m_writer, "SEQBEGIN");
                writer_c_comment(&self->m_writer, "/* BEGIN SEQUENCE */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SEQEND:
            {
                writer_c_instructions(&self->m_writer, "SEQEND");
                writer_c_comment(&self->m_writer, "/* END SEQUENCE */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SEQRECOVER:
            {
                writer_c_instructions(&self->m_writer, "SEQRECOVER");
                writer_c_comment(&self->m_writer, "/* RECOVER statement */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SFRAME:
            {
                writer_c_instructions(&self->m_writer, "SFRAME");
                writer_c_comment(&self->m_writer, "/* sets the statics frame for a function */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_STATICS:
            {
                writer_c_instructions(&self->m_writer, "STATICS");
                writer_c_comment(&self->m_writer, "/* defines the number of statics variables for a PRG */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_STATICNAME:
            {
                uint32_t name_len = strlen((const char*)(pcode_ptr+1)) + 1;
                writer_c_bytecode(&self->m_writer, pcode_ptr, name_len+1);
                writer_c_instructions(&self->m_writer, "");
                writer_c_comment(&self->m_writer, "/* sets the name of static variable \"%s\" */", pcode_ptr+1);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += (1 + name_len);
                offset += (1 + name_len);
                break;
            }
            case HB_P_SWAPALIAS:
            {
                writer_c_instructions(&self->m_writer, "SWAPALIAS");
                writer_c_comment(&self->m_writer, "/* restores the current workarea number from the eval stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_TRUE:
            {
                writer_c_instructions(&self->m_writer, "push TRUE");
                writer_c_comment(&self->m_writer, "/* pushes true on the virtual machine stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ZERO:
            {
                writer_c_instructions(&self->m_writer, "push 0");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ONE:
            {
                writer_c_instructions(&self->m_writer, "push 1");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROFUNC:
            {
                writer_c_instructions(&self->m_writer, "MACROFUNC");
                writer_c_comment(&self->m_writer, "/* execute a function saving its result */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACRODO:
            {
                writer_c_instructions(&self->m_writer, "MACRODO");
                writer_c_comment(&self->m_writer, "/* execute a function discarding its result */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MPUSHSTR:
            {
                uint16_t str_len = *(uint16_t*)(pcode_ptr+1);
                bytecode_len = 3 + str_len;
                writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
                writer_c_instructions(&self->m_writer, "MPUSHSTR \"%s\"", pcode_ptr + 3);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LOCALNEARADDINT:
            {
                writer_c_instructions(&self->m_writer, "VAR_%d += %d", pcode_ptr[1], *(uint16_t*)(pcode_ptr + 2));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROPUSHREF:
            {
                writer_c_instructions(&self->m_writer, "MACROPUSHREF");
                writer_c_comment(&self->m_writer, "/* Reference to macro variable @&mvar */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHLONGLONG:
            {
                writer_c_instructions(&self->m_writer, "push %" PRIx64, *(uint64_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* places an integer number on the virtual machine stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENUMSTART:
            {
                writer_c_instructions(&self->m_writer, "ENUMSTART");
                writer_c_comment(&self->m_writer, "/* Start of FOR EACH loop */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENUMNEXT:
            {
                writer_c_instructions(&self->m_writer, "ENUMNEXT");
                writer_c_comment(&self->m_writer, "/* Next item of FOR EACH loop */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENUMPREV:
            {
                writer_c_instructions(&self->m_writer, "ENUMPREV");
                writer_c_comment(&self->m_writer, "/* Previous item of FOR EACH loop */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ENUMEND:
            {
                writer_c_instructions(&self->m_writer, "ENUMEND");
                writer_c_comment(&self->m_writer, "/* End of FOR EACH loop */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SWITCH:
            {
                writer_c_instructions(&self->m_writer, "SWITCH");
                writer_c_comment(&self->m_writer, "/* SWITCH using long values */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHDATE:
            {
                writer_c_instructions(&self->m_writer, "PUSHDATE");
                writer_c_comment(&self->m_writer, "/* places a data constant value on the virtual machine stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PLUSEQPOP:
            {
                writer_c_instructions(&self->m_writer, "*pop() += pop()");
                writer_c_comment(&self->m_writer, "/* adds a value to the variable by reference */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MINUSEQPOP:
            {
                writer_c_instructions(&self->m_writer, "*pop() -= pop()");
                writer_c_comment(&self->m_writer, "/* subs a value from the variable reference */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MULTEQPOP:
            {
                writer_c_instructions(&self->m_writer, "*pop() *= pop()");
                writer_c_comment(&self->m_writer, "/* multiplies a variable reference by a value */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DIVEQPOP:
            {
                writer_c_instructions(&self->m_writer, "*pop() /= pop()");
                writer_c_comment(&self->m_writer, "/* divides the var reference by a value */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PLUSEQ:
            {
                writer_c_instructions(&self->m_writer, "*pop() += pop() (result on stack)");
                writer_c_comment(&self->m_writer, "/* adds a value to the variable reference, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MINUSEQ:
            {
                writer_c_instructions(&self->m_writer, "*pop() -= pop() (result on stack)");
                writer_c_comment(&self->m_writer, "/* subs a value from the variable reference, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MULTEQ:
            {
                writer_c_instructions(&self->m_writer, "*pop() *= pop() (result on stack)");
                writer_c_comment(&self->m_writer, "/* multiplies a variable reference by a value, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DIVEQ:
            {
                writer_c_instructions(&self->m_writer, "*pop() /= pop() (result on stack)");
                writer_c_comment(&self->m_writer, "/* divides the var reference by a value, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_WITHOBJECTSTART:
            {
                writer_c_instructions(&self->m_writer, "WITHOBJECTSTART");
                writer_c_comment(&self->m_writer, "/* start WITH OBJECT code */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_WITHOBJECTMESSAGE:
            {
                writer_c_instructions(&self->m_writer, "WITHOBJECTMESSAGE");
                writer_c_comment(&self->m_writer, "/* push message for WITH OBJECT */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_WITHOBJECTEND:
            {
                writer_c_instructions(&self->m_writer, "WITHOBJECTEND");
                writer_c_comment(&self->m_writer, "/* end WITH OBJECT code */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MACROSEND:
            {
                writer_c_instructions(&self->m_writer, "MACROSEND");
                writer_c_comment(&self->m_writer, "/* send operator with macro list params */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHOVARREF:
            {
                writer_c_instructions(&self->m_writer, "PUSHOVARREF");
                writer_c_comment(&self->m_writer, "/* pushes reference to object variable */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ARRAYPUSHREF:
            {
                writer_c_instructions(&self->m_writer, "ARRAYPUSHREF");
                writer_c_comment(&self->m_writer, "/* pushes reference to array element */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_VFRAME:
            {
                writer_c_instructions(&self->m_writer, "VFRAME");
                writer_c_comment(&self->m_writer, "/* frame with variable number of parameters */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LARGEFRAME:
            {
                writer_c_instructions(&self->m_writer, "LARGEFRAME");
                writer_c_comment(&self->m_writer, "/* frame with more then 255 locals */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LARGEVFRAME:
            {
                writer_c_instructions(&self->m_writer, "LARGEVFRAME");
                writer_c_comment(&self->m_writer, "/* frame with variable number of parameters and more then 255 locals */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHSTRHIDDEN:
            {
                bytecode_len = 3 + *(uint16_t*)(pcode_ptr + 1);
                writer_c_bytecode(&self->m_writer, pcode_ptr, bytecode_len);
                writer_c_instructions(&self->m_writer, "push hidden offset\"%s\"", pcode_ptr + 3);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LOCALADDINT:
            {
                writer_c_instructions(&self->m_writer, "LOCALADDINT");
                writer_c_comment(&self->m_writer, "/* Add/Subtract specified int into specified local without using the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MODEQPOP:
            {
                writer_c_instructions(&self->m_writer, "*pop() %= pop()");
                writer_c_comment(&self->m_writer, "/* calculates the modulus of var reference and a value */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_EXPEQPOP:
            {
                writer_c_instructions(&self->m_writer, "*pop() ^= pop()");
                writer_c_comment(&self->m_writer, "/* calculates the power of var reference and a value */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MODEQ:
            {
                writer_c_instructions(&self->m_writer, "*pop() %= pop() (result on stack)");
                writer_c_comment(&self->m_writer, "/* calculates the modulus of var reference and a value, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_EXPEQ:
            {
                writer_c_instructions(&self->m_writer, "*pop() ^= pop() (result on stack)");
                writer_c_comment(&self->m_writer, "/* calculates the power of var reference and a value, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DUPLUNREF:
            {
                writer_c_instructions(&self->m_writer, "DUPLUNREF");
                writer_c_comment(&self->m_writer, "/* places a copy of the latest virtual machine stack value on to the stack and unreference the source one */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_MPUSHBLOCKLARGE:
            case HB_P_MPUSHSTRLARGE:
            case HB_P_PUSHBLOCKLARGE:
            case HB_P_PUSHSTRLARGE:
            {
                uint32_t big_len = *(uint32_t*)(pcode_ptr + 1);
                bytecode_len = 1 + 4 + big_len;

                writer_c_bytecode(&self->m_writer, pcode_ptr, 1 + 4); /* Only print header */
                writer_c_instructions(&self->m_writer, "LARGE_OP_%X size %u", *pcode_ptr, big_len);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SWAP:
            {
                writer_c_instructions(&self->m_writer, "SWAP");
                writer_c_comment(&self->m_writer, "/* swap n+1 times two items starting from the most top one on the virtual machine stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHVPARAMS:
            {
                writer_c_instructions(&self->m_writer, "PUSHVPARAMS");
                writer_c_comment(&self->m_writer, "/* push variable function/method parameters on HVM stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHUNREF:
            {
                writer_c_instructions(&self->m_writer, "push *pop()");
                writer_c_comment(&self->m_writer, "/* push unreferenced top item on HVM stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SEQALWAYS:
            {
                writer_c_instructions(&self->m_writer, "SEQALWAYS");
                writer_c_comment(&self->m_writer, "/* set BEGIN SEQUENCE/ALWAYS section */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ALWAYSBEGIN:
            {
                writer_c_instructions(&self->m_writer, "ALWAYSBEGIN");
                writer_c_comment(&self->m_writer, "/* start ALWAYS section */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_ALWAYSEND:
            {
                writer_c_instructions(&self->m_writer, "ALWAYSEND");
                writer_c_comment(&self->m_writer, "/* finish ALWAYS section */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DECEQPOP:
            {
                writer_c_instructions(&self->m_writer, "--*pop()");
                writer_c_comment(&self->m_writer, "/* decrements the var reference */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_INCEQPOP:
            {
                writer_c_instructions(&self->m_writer, "++*pop()");
                writer_c_comment(&self->m_writer, "/* increments the var reference */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_DECEQ:
            {
                writer_c_instructions(&self->m_writer, "(--*pop()) (result on stack)");
                writer_c_comment(&self->m_writer, "/* decrements the var reference, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_INCEQ:
            {
                writer_c_instructions(&self->m_writer, "(++*pop()) (result on stack)");
                writer_c_comment(&self->m_writer, "/* increments the var reference, leave result on the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LOCALDEC:
            {
                writer_c_instructions(&self->m_writer, "--VAR_%d", *(uint16_t*)(pcode_ptr + 1));
                writer_c_comment(&self->m_writer, "/* decrements the local variable %d (0x%X) */", *(uint16_t*)(pcode_ptr + 1), *(uint16_t*)(pcode_ptr + 1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_LOCALINCPUSH:
            {
                writer_c_instructions(&self->m_writer, "push ++VAR_%d", *(uint16_t*)(pcode_ptr + 1));
                writer_c_comment(&self->m_writer, "/* increments the local variable %d (0x%X) and push it to the stack */", *(uint16_t*)(pcode_ptr + 1), *(uint16_t*)(pcode_ptr + 1));
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHFUNCSYM:
            {
                uint16_t idx = *(uint16_t*)(pcode_ptr + 1);
                const char *name = (idx < self->m_hb_ctx->hb_symbols_count) ?
                                   executable_hb_symbol_c_Name(self->m_hb_ctx->hb_symbols[idx]) : "???";

                writer_c_instructions(&self->m_writer, "push offset %s", name);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_HASHGEN:
            {
                writer_c_instructions(&self->m_writer, "HASHGEN %d", *(uint16_t*)(pcode_ptr+1));
                writer_c_comment(&self->m_writer, "/* instructs the virtual machine to build a hash and load element from the stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_SEQBLOCK:
            {
                writer_c_instructions(&self->m_writer, "SEQBLOCK");
                writer_c_comment(&self->m_writer, "/* set BEQIN SEQUENCE WITH block */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_THREADSTATICS:
            {
                uint32_t count = *(uint32_t*)(pcode_ptr + 1);
                bytecode_len = 1 + 4 + (count * 4);

                writer_c_bytecode(&self->m_writer, pcode_ptr, 1+4);
                writer_c_instructions(&self->m_writer, "THREADSTATICS count %u", count);
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);

                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            case HB_P_PUSHAPARAMS:
            {
                writer_c_instructions(&self->m_writer, "PUSHAPARAMS");
                writer_c_comment(&self->m_writer, "/* push array items on HVM stack */");
                writer_c_print(&self->m_writer);
                writer_c_clear(&self->m_writer);
                pcode_ptr += bytecode_len;
                offset += bytecode_len;
                break;
            }
            default:
            {
                if (*pcode_ptr < HB_P_LAST_PCODE) {
                    if (bytecode_len) {
                        writer_c_instructions(&self->m_writer, "<= !");
                        writer_c_print(&self->m_writer);
                        writer_c_clear(&self->m_writer);
                        pcode_ptr += bytecode_len;
                        offset += bytecode_len;
                        break;
                    }
                } else {
                     StringBuffer_AppendF(self->m_writer.output_buffer, "pcode %d (0x%X) is too big\n", *pcode_ptr, *pcode_ptr);
                }

                StringBuffer_AppendF(self->m_writer.output_buffer, "\t");
                uint32_t columns = 0;
                uint32_t i;
                size_t size = hb_symb_and_pcode->pcode_size - (pcode_ptr - pcode_base);

                for (i = 0; i < size; i++, pcode_ptr++, columns++) {
                    StringBuffer_AppendF(self->m_writer.output_buffer, "%X ", *pcode_ptr);
                    if (columns == 15) {
                        StringBuffer_AppendF(self->m_writer.output_buffer, "\n\t");
                        columns = 0;
                    }
                }
                StringBuffer_AppendF(self->m_writer.output_buffer, "\n");
                break;
            }
        }

        if ((size_t)(pcode_ptr - pcode_base) >= hb_symb_and_pcode->pcode_size) {
            StringBuffer_AppendF(self->m_writer.output_buffer, "\n");
            break;
        }
    }
}
