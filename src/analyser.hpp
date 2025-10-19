/*
 * le_disasm - Linear Executable disassembler
 */
/** @file analyser.hpp
 *     Header file for analyser.cpp, with declaration of Analyser class.
 * @par Purpose:
 *     Storage for Analyser class which binds together the disassembler
 *     and the binary image, being the central point of binary data analysis.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_ANALYSER_H
#define LEDISASM_ANALYSER_H

#include <deque>
#include <inttypes.h>
#include <map>
#include <string>

#include "disassembler.hpp"
#include "known_file.hpp"

class LinearExecutable;
class Image;
class Label;
class Region;
class SymbolMap;

class Analyser
{
public:
  typedef std::map<uint32_t, Region> RegionMap;
  typedef std::map<uint32_t, Label>  LabelMap;

protected:
  RegionMap            regions;
  LabelMap             labels;
  std::deque<uint32_t> code_trace_queue;
  LinearExecutable    *le;
  Image               *image;
  SymbolMap           *symbols;
  Disassembler         disasm;
  KnownFile::Type      known_type;

  friend class KnownFile;

protected:
  void  add_region (const Region &reg);

  void  add_initial_regions (void);
  void  add_eip_to_labels (void);
  void  add_symbols_to_labels (void);
  void  add_labels_to_trace_queue (void);
  void  add_code_trace_address (uint32_t addr);

  void  trace_code (void);
  void  trace_code_at_address (uint32_t start_addr);

  bool is_valid_acceptable_instruction (Instruction *inst);

  Region * get_previous_region (const Region *reg);
  Region * get_region_at_address (uint32_t address);
  Region * get_region (uint32_t address);

  void insert_region (Region *parent, const Region &reg);
  void check_merge_regions (uint32_t addr);

  void trace_vtables (void);
  void trace_remaining_relocs (void);

public:
  Analyser (void);
  Analyser (const Analyser &other);
  Analyser (LinearExecutable *le, Image *img, SymbolMap *syms);

  Analyser &operator= (const Analyser &other);

  Label * get_next_label (const Label *lab);
  Label * get_next_label (uint32_t addr);
  Region *get_next_region (const Region *reg);

  void insert_region (const Region &reg);
  void set_label (const Label &lab);
  void remove_label (uint32_t addr);
  void run (void);

  const RegionMap *  get_regions (void) const;
  const LabelMap *  get_labels (void) const;
  const Label *  get_label (uint32_t addr) const;
};

#endif // LEDISASM_ANALYSER_H
