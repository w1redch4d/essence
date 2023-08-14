/* Linker script to create multiboo2 loader.  */

SECTIONS
{
   . = 0x106000;

   .kernel_params (NOLOAD) : { *(.kernel_params) }

   . = 0x140000;

   .paging_table (NOLOAD) : { *(.paging_table) }

   . = 0x160000;

   .memory_map (NOLOAD) : { *(.memory_map) }

   . = 0x180000;

  .text :
  {
    *(.text)
  }
  .data :
  {
    *(.data)
    *(.rdata)
    *(.pdata)
  }
  .bss :
  {
    *(.bss)
    *(COMMON)
  }
  .edata :
  {
    *(.edata)
  }
  .stab :
  {
    *(.stab)
  }
  .stabstr :
  {
    *(.stabstr)
  }

   . = 0x1c0000;

   .kernel_paging_table (NOLOAD) : { *(.kernel_paging_table) }

   . = 0x1f0000;

   .stack (NOLOAD) : { *(.stack) }

   /DISCARD/ : {
     *(.dynamic)
     *(.comment)
     *(.note.gnu.build-id)
   }
}
