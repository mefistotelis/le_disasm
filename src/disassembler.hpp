/*
 * le_disasm - Linear Executable disassembler
 */
/** @file disassembler.hpp
 *     Header file for disassembler.cpp, with declaration of Disassembler class.
 * @par Purpose:
 *     Storage for Disassembler class which handles communication with the
 *     disassembler library.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_DISASSEMBLER_H
#define LEDISASM_DISASSEMBLER_H

#include <inttypes.h>
#include <string>

// Some versions of libopcodes require prior inclusion of config.h
#include "config.h"
#include "dis-asm.h"

struct disassemble_info;
class Instruction;

class Disassembler
{
protected:
  disassemble_info *info;
  disassembler_ftype print_insn;

protected:
  static int receive_instruction_text (void *context, const char *fmt, ...);
# ifdef HAVE_LIBOPCODES_DISASSEMBLER_STYLE
  static int receive_instruction_styled_text (void *context,
                enum disassembler_style style, const char *fmt, ...);
# endif
  static void print_address (bfd_vma address, disassemble_info *info);
  void set_target_and_type (uint32_t addr, const void *data,
      Instruction *inst);
  
public:
  Disassembler (void);
  Disassembler (const Disassembler &other);
  ~Disassembler (void);
  Disassembler &operator= (const Disassembler &other);
  Instruction disassemble (uint32_t addr, const std::string &data);
  void disassemble (uint32_t addr, const void *data, size_t length,
                    Instruction *ret);
};

#endif // LEDISASM_DISASSEMBLER_H
