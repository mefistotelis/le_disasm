/*
 * le_disasm - Linear Executable disassembler
 */
/** @file symbol.cpp
 *     Implements methods of Symbol class.
 * @par Purpose:
 *     The Symbol class stores information on a debug symbol entry.
 *     The debug symbol is basically a label with optional size.
 * @author   Mefistotelis <mefistotelis@gmail.com>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <iostream>

#include "symbol.hpp"
#include "util.hpp"

Symbol::Symbol (uint32_t address, Label::Type type,
         const std::string &name, uint32_t size)
    : Label(address, type, name)
{
  this->size = size;
}

Symbol::Symbol (void)
    : Label()
{
  this->size = 0;
}

bool
Symbol::has_size (void) const
{
  return (this->size != 0);
}

size_t
Symbol::get_size (void) const
{
  return this->size;
}

