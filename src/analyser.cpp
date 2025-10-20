/*
 * le_disasm - Linear Executable disassembler
 */
/** @file analyser.cpp
 *     Implementation of methods for Analyser class.
 * @par Purpose:
 *     Implementation of Analyser class methods which bind together the
 *     disassembler and the binary image, being the central point of
 *     binary data analysis.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <cassert>
#include <iostream>

#include "analyser.hpp"
#include "instruction.hpp"
#include "image.hpp"
#include "label.hpp"
#include "le.hpp"
#include "regions.hpp"
#include "symbol_map.hpp"

using std::ios;

void
Analyser::add_region (const Region &reg)
{
  this->regions[reg.get_address ()] = reg;
}

void
Analyser::add_initial_regions (void)
{
  const LEOH *ohdr;
  size_t n;
  Region::Type type;

  for (n = 0; n < this->le->get_object_count (); n++)
  {
    ohdr = this->le->get_object_header (n);

    if ((ohdr->flags & LEOH::EXECUTABLE) == 0)
    {
      type = Region::DATA;
      this->set_label (Label (ohdr->base_address, Label::DATA));
    }
    else
      type = Region::UNKNOWN;

    this->add_region (Region (ohdr->base_address,
                      ohdr->virtual_size, type));
  }
}

void
Analyser::add_eip_to_labels (void)
{
  const LEOH *ohdr;
  const LEH *hdr;
  uint32_t eip;

  hdr = this->le->get_header ();
  ohdr = this->le->get_object_header (hdr->eip_object_index);
  eip = ohdr->base_address + hdr->eip_offset;
  this->set_label (Label (eip, Label::FUNCTION, "_start"));
}

void
Analyser::add_symbols_to_labels (void)
{
  assert(this->symbols != NULL);

  for (auto it = this->symbols->begin(); it != this->symbols->end(); it++)
    {
      const Symbol *symbol = &(*it);

      this->set_label (Label (symbol->get_address(), symbol->get_type(), symbol->get_name()));
    }
}

void
Analyser::add_labels_to_trace_queue (void)
{
  for (auto it = this->labels.begin(); it != this->labels.end(); it++)
    {
      Label *label = &it->second;
      if (label->get_type() == Label::FUNCTION or
          label->get_type() == Label::JUMP or
          label->get_type() == Label::UNKNOWN)
        this->add_code_trace_address (label->get_address());
    }
}

void
Analyser::add_code_trace_address (uint32_t addr)
{
  this->code_trace_queue.push_back (addr);
}

void
Analyser::trace_code (void)
{
  uint32_t address;

  while (!this->code_trace_queue.empty ())
  {
    address = this->code_trace_queue.front ();
    this->code_trace_queue.pop_front ();
    this->trace_code_at_address (address);
  }
}

bool
Analyser::is_valid_acceptable_instruction (Instruction *inst)
{
    const char *invalids[] = {"(bad)", "ss", "gs"};
    std::string text = inst->get_string();

    for (size_t i = 0; i < sizeof(invalids)/sizeof(invalids[0]); ++i) {
        if (text.compare(invalids[i]) == 0) {
            return false;
        }
    }
    return true;
}

void
Analyser::trace_code_at_address (uint32_t start_addr)
{
  Region *reg;
  size_t end_addr;
  size_t addr;
  const Image::Object *obj;
  const Image::DataVector *data;
  Instruction inst;
  const void *data_ptr;
  Region::Type reg_type;

  reg = this->get_region_at_address (start_addr);
  if (reg == NULL)
    {
      std::cerr << "Warning: Tried to trace code at an unmapped address: 0x"
                << std::hex << start_addr << ".\n";
      return;
    }

  reg_type = reg->get_type ();
  if (reg_type != Region::UNKNOWN) /* already traced */
    return;

  end_addr = reg->get_end_address ();
  obj = this->image->get_object_at_address (start_addr);
  data = obj->get_data ();

  addr = start_addr;
  reg_type = Region::CODE; /* treat the region as code by default */

  while (addr < end_addr)
  {
    data_ptr = &data->front () + addr - obj->get_base_address ();
    this->disasm.disassemble (addr, data_ptr, end_addr - addr, &inst);

    if (!is_valid_acceptable_instruction (&inst)) {
        /* treating the region as code was wrong, make it data */
        reg_type = Region::DATA;
        addr += inst.get_size();
        goto end;
    }

    if (inst.get_target () != 0)
      {
        switch (inst.get_type ())
          {
          case Instruction::CALL:
            this->set_label (Label (inst.get_target (), Label::FUNCTION));
            this->add_code_trace_address (inst.get_target ());
            break;

          case Instruction::COND_JUMP:
          case Instruction::JUMP:
            this->set_label (Label (inst.get_target (), Label::JUMP));
            this->add_code_trace_address (inst.get_target ());
            break;

          default:
            break;
          }
      }

    addr += inst.get_size();

    switch (inst.get_type ())
      {
      case Instruction::JUMP:
      case Instruction::RET:
        goto end;

      default:
        break;
      }
  }

end:
  this->insert_region
    (reg, Region (start_addr, addr - start_addr, reg_type));
}

Region *
Analyser::get_previous_region (const Region *reg)
{
  return get_previous_value (&this->regions, reg->get_address ());
}

Region *
Analyser::get_region_at_address (uint32_t address)
{
  Analyser::RegionMap::iterator itr;

  if (this->regions.empty ())
    return NULL;

  itr = this->regions.lower_bound (address);

  if (itr == this->regions.end ())
    {
      --itr;
        
      if (itr->second.contains_address (address))
        return &itr->second;
      else
        return NULL;
    }

  if (itr->first == address)
    return &itr->second;

  if (itr == this->regions.begin ())
    return NULL;

  --itr;

  if (!itr->second.contains_address (address))
    return NULL;

  return &itr->second;
}

Region *
Analyser::get_region (uint32_t address)
{
  Analyser::RegionMap::iterator itr;

  itr = this->regions.find (address);
  if (itr == this->regions.end ())
    return NULL;

  return &itr->second;
}

void
Analyser::insert_region (Region *parent, const Region &reg)
{
  assert (parent->contains_address (reg.get_address ()));
  assert (parent->contains_address (reg.get_end_address () - 1));

  if (reg.get_end_address () != parent->get_end_address ())
    {
      this->add_region
        (Region (reg.get_end_address (),
                 parent->get_end_address () - reg.get_end_address (),
                 parent->get_type ()));
    }

  if (reg.get_address () != parent->get_address ())
    {
      this->add_region (reg);

      parent->size = reg.get_address () - parent->get_address ();
    }
  else
    *parent = reg;

  this->check_merge_regions (reg.address);
}

void
Analyser::check_merge_regions (uint32_t addr)
{
  Region *reg;
  Region *prev;
  Region *next;

  reg = this->get_region (addr);
  prev = this->get_previous_region (reg);
  next = this->get_next_region (reg);

  if (prev != NULL and prev->get_type () == reg->get_type ()
      and prev->get_end_address () == reg->get_address ())
    {
      prev->size += reg->size;
      this->regions.erase (addr);
      reg = prev;
    }

  if (next != NULL and reg->get_type () == next->get_type ()
      and reg->get_end_address () == next->get_address ())
    {
      reg->size += next->size;
      this->regions.erase (next->get_address ());
    }
}

void
Analyser::trace_vtables (void)
{
  const LEFM *fixups;
  LEFM::const_iterator itr;
  const Image::Object *obj;
  const uint8_t *data_ptr;
  Region *reg;
  size_t off;
  size_t size;
  size_t count;
  size_t n;
  uint32_t addr;
  const uint32_t *aptr;

  PUSH_IOS_FLAGS (&std::cerr);
  std::cerr.setf (ios::hex, ios::basefield);
  std::cerr.setf (ios::showbase);

  for (n = 0; n < this->le->get_object_count (); n++)
    {
      fixups = this->le->get_fixups_for_object (n);

      for (itr = fixups->begin (); itr != fixups->end (); ++itr)
        {
          reg = this->get_region_at_address (itr->second.address);
          if (reg == NULL)
            {
              std::cerr << "Warning: Reloc pointing to unmapped memory at "
                        << itr->second.address << ".\n";
              continue;
            }

          if (reg->get_type () != Region::UNKNOWN)
            continue;

          obj = this->image->get_object_at_address (reg->get_address ());
          if (!obj->is_executable ())
            continue;
          size = reg->get_end_address () - itr->second.address;
          aptr = get_next_value (this->le->get_fixup_addresses (),
                                 itr->second.address);
          if (aptr != NULL)
            size = std::min<size_t> (size, *aptr - itr->second.address);

          data_ptr = obj->get_data_at (itr->second.address);
          count = 0;
          off = 0;

          while (off + 4 <= size)
            {
              addr = read_le<uint32_t> (data_ptr + off);

              if (addr == 0
                  or fixups->find (itr->second.address + off
                                   - obj->get_base_address ())
                     != fixups->end ())
                {
                  count++;

                  if (addr != 0)
                    {
                      this->set_label (Label (addr, Label::FUNCTION));
                      this->add_code_trace_address (addr);
                    }
                }
              else
                break;

              off += 4;
            }

          if (count > 0)
            {
              this->insert_region (reg, Region (itr->second.address,
                                                4 * count, Region::VTABLE));
              this->set_label (Label (itr->second.address, Label::VTABLE));
              this->trace_code ();
            }
        }
    }
}

void
Analyser::trace_remaining_relocs (void)
{
  const LEFM *fixups;
  LEFM::const_iterator itr;
  Region *reg;
  size_t n;
  size_t guess_count = 0;
  const Label *label;

  PUSH_IOS_FLAGS (&std::cerr);
  std::cerr.setf (ios::hex, ios::basefield);
  std::cerr.setf (ios::showbase);

  for (n = 0; n < this->image->get_object_count (); n++)
    {
      fixups = this->le->get_fixups_for_object (n);

      for (itr = fixups->begin (); itr != fixups->end (); ++itr)
        {
          reg = this->get_region_at_address (itr->second.address);
          if (reg == NULL
              or (reg->get_type () != Region::UNKNOWN
                  and reg->get_type () != Region::DATA))
            continue;

          if (reg->get_type () == Region::UNKNOWN)
            {
              label = this->get_label (itr->second.address);

              if (label == NULL
                  or (label->get_type () != Label::FUNCTION
                      and label->get_type () != Label::JUMP))
                {
                  std::cerr << "Guessing that " << itr->second.address
                            << " is a function.\n";
                  guess_count++;
                  this->set_label (Label (itr->second.address,
                                          Label::FUNCTION));
                }

              this->add_code_trace_address (itr->second.address);
              this->trace_code ();
            }
          else
            {
              this->set_label (Label (itr->second.address,
                                      Label::DATA));
            }
        }
    }

  std::cerr.setf (ios::dec, ios::basefield);
  std::cerr.unsetf (ios::showbase);
  std::cerr << guess_count << " guess(es) to investigate.\n";
}

Analyser::Analyser (void)
{
  this->le    = NULL;
  this->image = NULL;
  this->symbols = NULL;
  this->known_type = KnownFile::NOT_KNOWN;
}

Analyser::Analyser (const Analyser &other)
{
  *this = other;
}

Analyser::Analyser (LinearExecutable *le, Image *img, SymbolMap *syms)
{
  this->le    = le;
  this->image = img;
  this->symbols = syms;
  this->add_initial_regions ();
  this->known_type = KnownFile::NOT_KNOWN;
}

Analyser &
Analyser::operator= (const Analyser &other)
{
  this->le     = other.le;
  this->image  = other.image;
  this->symbols = other.symbols;
  this->disasm = other.disasm;
  this->known_type = other.known_type;
  this->add_initial_regions ();
  return *this;
}

Label *
Analyser::get_next_label (const Label *lab)
{
  return get_next_value (&this->labels, lab->get_address ());
}

Label *
Analyser::get_next_label (uint32_t addr)
{
  return get_next_value (&this->labels, addr);
}

Region *
Analyser::get_next_region (const Region *reg)
{
  return get_next_value (&this->regions, reg->get_address ());
}

void
Analyser::insert_region (const Region &reg)
{
  Region *parent;
  parent = this->get_region_at_address (reg.get_address ());
  this->insert_region (parent, reg);
}

void
Analyser::set_label (const Label &lab)
{
  const Label *label;

  label = this->get_label (lab.get_address ());
  if (label != NULL)
    {
        this->improve_label(lab);
        return;
    }

  this->labels[lab.get_address ()] = lab;
}

void
Analyser::remove_label (uint32_t addr)
{
  this->labels.erase (addr);
}

Label *
Analyser::improve_label (const Label &lab)
{
  Analyser::LabelMap::iterator itr;
  Label *label;

  itr = this->labels.find (lab.get_address ());
  if (itr == this->labels.end ())
    return NULL;

  label = &itr->second;
  label->improve_from(lab);

  return label;
}

void
Analyser::run (void)
{
  this->add_symbols_to_labels ();
  this->add_eip_to_labels ();
  this->add_labels_to_trace_queue ();
  std::cerr << "Tracing code directly accessible from the entry point...\n";
  this->trace_code ();
  std::cerr << "Tracing text relocs for vtables...\n";
  this->trace_vtables ();
  std::cerr << "Tracing remaining relocs for functions and data...\n";
  this->trace_remaining_relocs ();
}

const Analyser::RegionMap *
Analyser::get_regions (void) const
{
  return &this->regions;
}

const Analyser::LabelMap *
Analyser::get_labels (void) const
{
  return &this->labels;
}

const Label *
Analyser::get_label (uint32_t addr) const
{
  Analyser::LabelMap::const_iterator itr;

  itr = this->labels.find (addr);
  if (itr == this->labels.end ())
    return NULL;

  return &itr->second;
}
