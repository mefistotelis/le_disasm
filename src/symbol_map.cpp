/*
 * le_disasm - Linear Executable disassembler
 */
/** @file symbol_map.cpp
 *     List of debug symbols, storing names of regions.
 * @par Purpose:
 *     Implements methods for handling a list of symbols. Such lists can be
 *     created by loading debug info in various forms, the simplest of
 *     which are .MAP files.
 * @author   Klei1984
 * @date     2024-01-10 - 2025-10-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <iostream>
#include <map>

#include "symbol_map.hpp"
#include "symbol.hpp"
#include "util.hpp"

SymbolMap::SymbolMap ()
{
}

const Symbol *
SymbolMap::get_symbol(uint32_t address)
{
    const std::map<uint32_t, Symbol>::const_iterator item = this->map.find(address);

    if (item != this->map.end()) {
        return &item->second;
    }

    return NULL;
}

