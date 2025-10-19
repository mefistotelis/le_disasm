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
  using map_type = std::map<uint32_t, Symbol>;
  /* allow iterating over symbols stored in the internal map */
  struct iterator
  {
    using iterator_category = std::forward_iterator_tag;
    using value_type = Symbol;
    using pointer = const Symbol*;
    using reference = const Symbol&;
    using difference_type = map_type::iterator::difference_type ;

    reference operator* () const { return internal_iterator->second ; }
    pointer operator& () const { return std::addressof(**this) ; }
    iterator& operator++ () { ++internal_iterator ; return *this ; }
    iterator operator++ (int) { const iterator ov = *this ; ++*this ; return ov ; }
    bool operator== ( const iterator& that ) const noexcept { return internal_iterator == that.internal_iterator ; }
    bool operator!= ( const iterator& that ) const noexcept { return !( *this == that ) ; }

    private:
        map_type::const_iterator internal_iterator ;
        iterator( map_type::const_iterator iter ) : internal_iterator(iter) {}
        friend SymbolMap;
  };

public:

  SymbolMap ();

  const Symbol *get_symbol(uint32_t address);

  void load_file_map(std::string &fileName);

  iterator begin() const noexcept { return iterator{ map.begin() } ; }
  iterator end() const noexcept { return iterator{ map.end() } ; }

protected:
    map_type map;
};

#endif // LEDISASM_SYMBOL_MAP_H
