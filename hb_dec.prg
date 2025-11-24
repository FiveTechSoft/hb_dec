PROCEDURE Main( cFileName )

   IF Empty( cFileName )
      ? "Usage: hb_dec <executable_file>"
      RETURN
   ENDIF

   ? HB_DEC_DECOMPILE( cFileName )

   RETURN
