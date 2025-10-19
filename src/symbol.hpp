/*
 * le_disasm - Linear Executable disassembler
 */
/** @file symbol.hpp
 *     Header file for symbol.cpp, with declaration of Label class.
 * @par Purpose:
 *     Storage for Symbol class which stores information on a debug
 *     symbol entry.
 * @author   Mefistotelis <mefistotelis@gmail.com>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_SYMBOL_H
#define LEDISASM_SYMBOL_H

#include <inttypes.h>
#include "le.hpp"

#include "label.hpp"

class LinearExecutable;
class Image;
class Region;

struct Symbol : public Label
{
protected:
  uint32_t size;

public:
  Symbol (uint32_t address, Label::Type type = UNKNOWN,
         const std::string &name = "", uint32_t size = 0);
  Symbol (void);

  std::string  get_name (void) const;
  std::string  get_full_name (void) const;
  bool     has_size (void) const;
  size_t   get_size (void) const;
};

#endif // LEDISASM_SYMBOL_H
