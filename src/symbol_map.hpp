/*
 * le_disasm - Linear Executable disassembler
 */
/** @file symbol_map.hpp
 *     Header file for symbol_map.cpp, with declaration of SymbolMap class.
 * @par Purpose:
 *     List of debug symbols, storing names of regions.
 *     Support of .MAP file loading.
 * @author   Klei1984
 * @date     2024-01-10 - 2025-10-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_SYMBOL_MAP_H
#define LEDISASM_SYMBOL_MAP_H

#include <inttypes.h>
#include <map>
#include <string>

#include "symbol.hpp"

class SymbolMap
{
public:
  SymbolMap ();

  const Symbol *get_symbol(uint32_t address);

protected:
    std::map<uint32_t, Symbol> map;
};

#endif // LEDISASM_SYMBOL_MAP_H
