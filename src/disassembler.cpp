/*
 * le_disasm - Linear Executable disassembler
 */
/** @file disassembler.cpp
 *     Implementation of Disassembler class methods.
 * @par Purpose:
 *     Implementation of Disassembler class methods which handle
 *     communication with the disassembler library.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstdarg>
#include <sstream>
#include <stdexcept>

#include "disassembler.hpp"
#include "instruction.hpp"
#include "util.hpp"

static std::string
strip (std::string str)
{
  std::string::size_type n;

  n = str.find_first_not_of (" \t\r\n");
  if (n == std::string::npos)
    return "";

  str = str.substr (n);
  n = str.find_last_not_of (" \t\r\n");
  if (n == std::string::npos)
    return str;

  return str.substr (0, n + 1);
}

static std::string
lower (const std::string &str)
{
  std::string out;

  out.reserve (str.length ());
  std::transform (str.begin (), str.end (), std::back_inserter (out),
                  tolower);

  return out;
}


struct DisassemblerContext
{
  std::ostringstream string;
};


Disassembler::Disassembler (void)
{
  this->info = new disassemble_info;

  init_disassemble_info (this->info, NULL,
#ifdef HAVE_LIBOPCODES_DISASSEMBLER_STYLE
    &Disassembler::receive_instruction_text,
    &Disassembler::receive_instruction_styled_text);
#else
    &Disassembler::receive_instruction_text);
#endif

  this->info->arch               = bfd_arch_i386;
  this->info->mach               = bfd_mach_i386_i386;
  //this->info->disassembler_options = "intel-mnemonic"; // for intel syntax
  this->info->print_address_func = &Disassembler::print_address;
  //disassemble_init_for_target(this->info); // is this really needed?
  this->print_insn = disassembler(this->info->arch, false, this->info->mach, NULL);
}

Disassembler::Disassembler (const Disassembler &other)
{
  *this = other;
}

Disassembler &
Disassembler::operator= (const Disassembler &other)
{
  this->info = new disassemble_info (*other.info);
  return *this;
}

Disassembler::~Disassembler (void)
{
  delete this->info;
}

Instruction
Disassembler::disassemble (uint32_t addr, const std::string &data)
{
  Instruction inst;

  this->disassemble (addr, data.data (), data.length (), &inst);
  return inst;
}

void
Disassembler::disassemble (uint32_t addr, const void *data, size_t length,
                           Instruction *inst)
{
  DisassemblerContext context;
  int size;

  assert (length > 0);

  this->info->buffer        = (bfd_byte *) data;
  this->info->buffer_length = length;
  this->info->buffer_vma    = addr;
  this->info->stream        = &context;

  size = this->print_insn (addr, this->info);
  if (size < 0)
    throw std::runtime_error ("Failed to disassemble, opcodes caused decoder error");

  inst->string = lower (strip (context.string.str ()));
  inst->size   = size;
  inst->type   = Instruction::MISC;
  inst->target = 0;

  if (size == 0)
    return;

  // If instruction cannot be decoded but didn't caused error, just return it
  // Upper level functions are expected to re-check and take action
  if (inst->string.compare("(bad)") == 0)
    return;

  set_target_and_type(addr, data, inst);
}

void
Disassembler::set_target_and_type (uint32_t addr, const void *data, Instruction *inst)
{
  uint8_t data0, data1 = 0;
  bool have_target;

  have_target = true;
  data0 = ((uint8_t *) data)[0];

  /* ignore prefixes for branch prediction (2e/3e) and for operand size (66/67) */
  if ((data0 == 0x2e) or (data0 == 0x3e) or (data0 == 0x66) or (data0 == 0x67))
    {
      if (inst->size > 1)
        data0 = ((uint8_t *) data)[1];

      if (inst->size > 2)
        data1 = ((uint8_t *) data)[2];
    }
  else
    {
      if (inst->size > 1)
        data1 = ((uint8_t *) data)[1];
    }

    if (data0 == 0x0f)
      {
        if (data1 >= 0x80 and data1 <= 0x8f) /* Jxx rel16/32 (jump near conditional) */
          inst->type = Instruction::COND_JUMP;
      }
    else if (data0 == 0xe8) /* call */
      inst->type = Instruction::CALL;
    else if (data0 == 0xe9) /* JMP rel16/rel32 (jump near) */
      inst->type = Instruction::JUMP;
    else if (data0 == 0xc2) /* retn */
      inst->type = Instruction::RET;
    else if (data0 == 0xca) /* lretn */
      inst->type = Instruction::RET;
    else if (data0 == 0xea) /* JMP ptr16:16/ptr16:32 (jump far) */
      inst->type = Instruction::JUMP;
    else if (data0 == 0xeb) /* JMP rel8 (jump short) */
      inst->type = Instruction::JUMP;
    else if (data0 >= 0x70 and data0 <= 0x7f) /* Jxx rel8 (jump short conditional) */
      inst->type = Instruction::COND_JUMP;
    else if (data0 >= 0xe0 and data0 <= 0xe2) /* loop */
      inst->type = Instruction::COND_JUMP;
    else if (data0 == 0xe3) /* JCXZ/JECXZ rel8 (jump short if (e)cx=0) */
      inst->type = Instruction::COND_JUMP;
    else if (data0 == 0xcf) /* iret */
      inst->type = Instruction::RET;
    else if (data0 == 0xc3) /* ret */
      inst->type = Instruction::RET;
    else if (data0 == 0xcb) /* lret */
      inst->type = Instruction::RET;
    else if (data0 == 0xff) /* JMP r/m16/m32 (jump near) or JMP m16:16/m16:32 (jump far) or call near indirect */
      {
        have_target = false;

        uint8_t reg_field = (data1 & 0x38) >> 3;
        if (reg_field == 2 or reg_field == 3) {
            inst->type = Instruction::CALL;
        } else if (reg_field == 4 or reg_field == 5) {
            inst->type = Instruction::JUMP;
        }
      }

  if (have_target
      and (inst->type == Instruction::COND_JUMP
           or inst->type == Instruction::JUMP
           or inst->type == Instruction::CALL))
    {
      if (inst->size < 5)
        inst->target =
          addr + inst->size
          + read_s8 ((uint8_t *) data + inst->size - sizeof (int8_t));
      else
        inst->target =
          addr + inst->size
          + read_le<int32_t> ((uint8_t *) data + inst->size - sizeof (int32_t));
    }
}

int
Disassembler::receive_instruction_text (void *context, const char *fmt, ...)
{
  va_list list;
  DisassemblerContext *ctx;
  char buffer[128];
  int ret;

  ctx = (DisassemblerContext *) context;

  va_start (list, fmt);
  ret = vsnprintf (buffer, sizeof (buffer) - 1, fmt, list);
  buffer[ret] = 0;
  va_end (list);

  ctx->string << buffer;

  return ret;
}

#ifdef HAVE_LIBOPCODES_DISASSEMBLER_STYLE
int
Disassembler::receive_instruction_styled_text (void *context,
                enum disassembler_style style, const char *fmt, ...)
{
  va_list list;
  DisassemblerContext *ctx;
  char buffer[128];
  int ret;

  ctx = (DisassemblerContext *) context;

  va_start (list, fmt);
  ret = vsnprintf (buffer, sizeof (buffer) - 1, fmt, list);
  buffer[ret] = 0;
  va_end (list);

  ctx->string << buffer;

  return ret;
}
#endif

void
Disassembler::print_address (bfd_vma address, disassemble_info *info)
{
  info->fprintf_func (info->stream, "0x%llx", (unsigned long long)address);
}
