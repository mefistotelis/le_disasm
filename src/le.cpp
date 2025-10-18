/*
 * le_disasm - Linear Executable disassembler
 */
/** @file le.cpp
 *     Implementation of LinearExecutable class methods.
 * @par Purpose:
 *     Implements methods for parsing LE/LX headers,
 *     and preparing lists of objects stored within the executable.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <iostream>
#include <iomanip>
#include <memory>

#include "le.hpp"
#include "error.hpp"
#include "util.hpp"

using std::cerr;
using std::ios;
using std::istream;
using std::ostream;
using std::string;
using std::vector;


template <typename T>
bool
read_le (istream *is, T *ret)
{
  char buffer[sizeof (T)];

  is->read (buffer, sizeof (T));
  if (!is->good ())
    return false;

  *ret = read_le <T> (buffer);
  return true;
}

inline bool
read_u8 (istream *is, uint8_t *ret)
{
  is->read ((char *) ret, 1);
  return is->good ();
}


class LinearExecutable::Loader
{
protected:
  std::unique_ptr<LinearExecutable> le;
  //LinearExecutable *le;
  std::istream *is;
  uint32_t header_offset;
  vector<uint32_t> fixup_record_offsets;

protected:
  bool load_le_header_offset(void);
  bool load_header (void);
  bool load_object_table (void);
  bool load_object_header (ObjectHeader *hdr);
  bool load_object_page_table (void);
  bool load_object_page_header (ObjectPageHeader *hdr);
  bool load_fixup_record_offsets (void);
  bool load_fixup_record_table (void);
  bool load_fixup_record_pages (size_t oi);

public:
  LinearExecutable *load (istream *is, const std::string &name);
};


LinearExecutable *
LinearExecutable::Loader::load (istream *is, const std::string &name)
{
  this->is = is;

  if (!this->is->good ())
    {
      throw Error() << "Failed to open \"" << name << "\".";
    }

  this->le = std::unique_ptr<LinearExecutable>(new LinearExecutable);

  if (!this->load_header ())
    {
      throw Error() << "Failed to load LE header.";
    }

#ifdef DEBUG
  cerr << "LE Header:\n";
  cerr << this->le->header;
#endif

  if (!this->load_object_table ())
    {
      throw Error() << "Failed to load object table.";
    }

#ifdef DEBUG
  {
    PUSH_IOS_FLAGS (&cerr);

    cerr << "\n\n";
    cerr << "Object Table:\n";
    cerr << "\n";
    for (size_t n = 0; n < this->le->objects.size (); n++)
      {
        cerr << "Object " << std::hex << std::showbase << (n + 1) << ":\n";
        cerr << this->le->objects[n];
      }
  }

#endif

  if (!this->load_object_page_table ())
    {
      throw Error() << "Failed to load object page table.";
    }

#if 0
#ifdef DEBUG
  cerr << "\n\n";
  cerr << "Object Page Table:\n";
  cerr << "  Index  First Second Type\n";
  for (size_t n = 0; n < this->le->header.page_count; n++)
    cerr << std::setw (7) << (n + 1) << ' ' << this->le->object_pages[n] << '\n';
#endif
#endif

  if (!this->load_fixup_record_offsets ())
    {
      throw Error() << "Failed to load fixup page table.";
    }

  if (!this->load_fixup_record_table ())
    {
      throw Error() << "Failed to load fixup table.";
    }

  return this->le.release();
}

bool
LinearExecutable::Loader::load_le_header_offset(void)
{
  char id[2];
  uint16_t word;
  istream *is = this->is;
  LinearExecutable *le = this->le.get();

  is->seekg (0);
  is->read (id, 2);
  if (!is->good ())
    return false;

  // LE/LX header without MZ stub at start
  if ((string (id, 2) == "LE") or (string (id, 2) == "LX"))
    {
      this->header_offset = 0;
      return true;
    }

  if (string (id, 2) != "MZ")
    {
      cerr << "Invalid MZ signature\n";
      return false;
    }

  // Offset of relocation table; expected to have high enough value for new exec formats
  is->seekg (0x18);
  if (!read_le (is, &word))
    return false;

  // New executable info block starts at 0x1C, and has an offset to NE header within
  is->seekg (0x3c);
  if (!read_le (is, &this->header_offset))
    return false;

  // If there is no new exe header offset, we may still have LE with an embedded extender
  if (word < 0x40)
    {
      char str[0x1000];
      static char le_signature[] = "LE\0\0\0\0";
      is->seekg (0x240);
      is->read (str, 0x100);
      if (std::string(str, str+0x100).find("DOS/4G  ") != std::string::npos)
        {
            size_t pos;
            std::string signature_str(le_signature, le_signature+sizeof(le_signature));
            cerr << "Embedded DOS/4G identified\n";
            // Search for the LE head
            is->seekg (0x29000);
            is->read (str, 0x1000);
            pos = std::string(str, str+0x1000).find(signature_str);
            if (pos != std::string::npos and (pos & 3) == 0)
              {
                this->header_offset = 0x29000 + pos;
                return true;
              }
            cerr << "Not a LE executable, no signature found at expected offset range." << std::endl;
            return false;
        }
    }

  if (word < 0x40)
    {
      cerr << "Not a LE executable, at offset 0x18: expected 0x40 or more, got 0x" << std::hex << word << "." << std::endl;
      return false;
    }

  if (this->header_offset == 0)
    {
      cerr << "Not a LE executable, at offset 0x3c: new executable header offset is zero." << std::endl;
      return false;
    }

  return true;
}

bool
LinearExecutable::Loader::load_header (void)
{
  char id[2];
  uint8_t byte;
  istream *is = this->is;
  LinearExecutable *le = this->le.get();

  is->seekg (0);
  is->read (id, 2);
  if (!is->good ())
    return false;

  if (!this->load_le_header_offset())
    return false;

#ifdef DEBUG
  print_variable (&cerr, 40, "header_offset", this->header_offset);
  cerr << "\n";
#endif

  is->seekg (this->header_offset);
  is->read (id, 2);
  if (!is->good ())
    return false;

  if ((string (id, 2) != "LE") and (string (id, 2) != "LX"))
    {
      cerr << "Invalid LE signature at offset 0x" << std::hex << this->header_offset << std::endl;
      return false;
    }

  if (!read_u8 (is, &byte))
    return false;

  le->header.byte_order = (byte == 0 ? LITTLE_ENDIAN : BIG_ENDIAN);

  if (!read_u8 (is, &byte))
    return false;

  le->header.word_order = (byte == 0 ? LITTLE_ENDIAN : BIG_ENDIAN);

  if (le->header.byte_order != LITTLE_ENDIAN
      or le->header.word_order != LITTLE_ENDIAN)
    {
      cerr << "Unsupported LE byte or word endianness\n";
      return false;
    }

  read_le (is, &le->header.format_version);
  read_le (is, &le->header.cpu_type);
  read_le (is, &le->header.os_type);
  read_le (is, &le->header.module_version);
  read_le (is, &le->header.module_flags);
  read_le (is, &le->header.page_count);
  read_le (is, &le->header.eip_object_index);
  read_le (is, &le->header.eip_offset);
  read_le (is, &le->header.esp_object_index);
  read_le (is, &le->header.esp_offset);
  read_le (is, &le->header.page_size);
  read_le (is, &le->header.last_page_size);
  read_le (is, &le->header.fixup_section_size);
  read_le (is, &le->header.fixup_section_check_sum);
  read_le (is, &le->header.loader_section_size);
  read_le (is, &le->header.loader_section_check_sum);
  read_le (is, &le->header.object_table_offset);
  read_le (is, &le->header.object_count);
  read_le (is, &le->header.object_page_table_offset);
  read_le (is, &le->header.object_iterated_pages_offset);
  read_le (is, &le->header.resource_table_offset);
  read_le (is, &le->header.resource_entry_count);
  read_le (is, &le->header.resident_name_table_offset);
  read_le (is, &le->header.entry_table_offset);
  read_le (is, &le->header.module_directives_offset);
  read_le (is, &le->header.module_directives_count);
  read_le (is, &le->header.fixup_page_table_offset);
  read_le (is, &le->header.fixup_record_table_offset);
  read_le (is, &le->header.import_module_name_table_offset);
  read_le (is, &le->header.import_module_name_entry_count);
  read_le (is, &le->header.import_procedure_name_table_offset);
  read_le (is, &le->header.per_page_check_sum_table_offset);
  read_le (is, &le->header.data_pages_offset);
  read_le (is, &le->header.preload_pages_count);
  read_le (is, &le->header.non_resident_name_table_offset);
  read_le (is, &le->header.non_resident_name_entry_count);
  read_le (is, &le->header.non_resident_name_table_check_sum);
  read_le (is, &le->header.auto_data_segment_object_index);
  read_le (is, &le->header.debug_info_offset);
  read_le (is, &le->header.debug_info_size);
  read_le (is, &le->header.instance_pages_count);
  read_le (is, &le->header.instance_pages_demand_count);
  read_le (is, &le->header.heap_size);

  if (!is->good ())
    return false;

  if (le->header.format_version > 0)
    {
      cerr << "Unknown LE format version\n";
      return false;
    }

  le->header.eip_object_index--;
  le->header.esp_object_index--;

  return true;
}

bool
LinearExecutable::Loader::load_object_table (void)
{
  uint32_t n;

  this->le->objects.resize (this->le->header.object_count);
  this->is->seekg (this->header_offset
                  + this->le->header.object_table_offset);

  for (n = 0; n < this->le->header.object_count; n++)
    {
      if (!this->load_object_header (&this->le->objects[n]))
        return false;
    }

  return true;
}

bool
LinearExecutable::Loader::load_object_page_table (void)
{
  uint32_t n;

  this->le->object_pages.resize (this->le->header.page_count);
  this->is->seekg (this->header_offset
                   + this->le->header.object_page_table_offset);

  for (n = 0; n < this->le->header.page_count; n++)
    {
      if (!this->load_object_page_header (&this->le->object_pages[n]))
        return false;
    }

  return true;
}

bool
LinearExecutable::Loader::load_object_header (ObjectHeader *hdr)
{
  istream *is = this->is;

  read_le (is, &hdr->virtual_size);
  read_le (is, &hdr->base_address);
  read_le (is, &hdr->flags);
  read_le (is, &hdr->first_page_index);
  read_le (is, &hdr->page_count);
  read_le (is, &hdr->reserved);

  hdr->first_page_index--;

  return is->good ();
}

bool
LinearExecutable::Loader::load_object_page_header (ObjectPageHeader *hdr)
{
  uint8_t byte;
  istream *is = this->is;

  read_le (is, &hdr->first_number);
  read_u8 (is, &hdr->second_number);
  read_u8 (is, &byte);

  if (!is->good () or byte > 4)
    return false;

  hdr->type = (ObjectPageType) byte;

  return true;
}

bool
LinearExecutable::Loader::load_fixup_record_offsets (void)
{
  size_t n;
  istream *is = this->is;

  // The additional +1 record indicates the end of the Fixup Record Table
  this->fixup_record_offsets.resize (this->le->header.page_count + 1);
  is->seekg (this->header_offset
             + this->le->header.fixup_page_table_offset);

  for (n = 0; n <= this->le->header.page_count; n++)
    {
      if (!read_le (is, &this->fixup_record_offsets[n]))
        return false;
    }

  return true;
}

bool
LinearExecutable::Loader::load_fixup_record_pages (size_t oi)
{
  Fixup fixup;
  ObjectHeader *obj;
  size_t n;
  size_t offset;
  size_t end;
  uint8_t addr_flags;
  uint8_t reloc_flags;
  int16_t src_off;
  uint16_t dst_off_16;
  uint32_t dst_off_32;
  uint8_t obj_index;
  istream *is = this->is;

  obj = &this->le->objects[oi];

  for (n = obj->first_page_index;
       n < obj->first_page_index + obj->page_count; n++)
    {
#ifdef DEBUG
      // print object indices starting from 1 as defined by LE format
      std::cerr << "Loading fixups for object " << oi + 1 << " page " << n << "." << std::endl;
#endif
      offset = this->header_offset
               + this->le->header.fixup_record_table_offset
               + this->fixup_record_offsets[n];
      end    = offset
               + this->fixup_record_offsets[n + 1]
               - this->fixup_record_offsets[n];

      is->seekg (offset);

      while (offset < end)
        {
          if (end - offset < 2)
            return false;
#ifdef DEBUG
          std::cerr << "Loading fixup 0x" << std::hex << offset << " at page " << std::dec << n <<
              "/" << obj->page_count << ", offset 0x" << std::hex << offset << ": ";
#endif

          read_u8 (is, &addr_flags);
          read_u8 (is, &reloc_flags);

          if (!is->good ())
            return false;

          if ((addr_flags & 0x20) != 0)
            {
              cerr << "Fixup lists not supported.\n";
              return false;
            }

          if ((addr_flags & 0xf) != 0x7) /* 32-bit offset */
            {
              cerr << "Unsupported fixup type " << std::hex << std::showbase
                   << (addr_flags & 0xf) << ".\n";
              return false;
            }

          if ((reloc_flags & 0x3) != 0x0) /* internal ref */
            {
              cerr << "Unsupported reloc type " << std::hex << std::showbase
                   << (reloc_flags & 0x03) << ".\n";
            }

          if ((reloc_flags & 0x40) != 0) /* 16-bit Object Number/Module Ordinal Flag */
            {
              cerr << "16-bit object or module ordinal numbers are not supported.\n";
            }

          offset += 2;

          if (end - offset < 3)
            return false;

          read_le<int16_t> (is, &src_off);
          read_u8 (is, &obj_index);

          if (!is->good ())
            return false;

          if (obj_index < 1 or obj_index > this->le->objects.size ())
            return false;

          obj_index--;

          offset += 3;

          if ((reloc_flags & 0x10) != 0) /* 32-bit offset */
            {
              if (end - offset < 4)
                return false;

              read_le<uint32_t> (is, &dst_off_32);
              offset += 4;
            }
          else /* 16-bit offset */
            {
              if (end - offset < 2)
                return false;

              read_le<uint16_t> (is, &dst_off_16);
              dst_off_32 = dst_off_16;
              offset += 2;
            }

          if (!is->good ())
            return false;

          fixup.offset = (n - obj->first_page_index)
                           * this->le->header.page_size
                         + src_off;
          fixup.address = this->le->objects[obj_index].base_address
                          + dst_off_32;

#ifdef DEBUG
          std::cerr << "0x" << std::hex << fixup.offset << " -> 0x" << std::hex << fixup.address << std::endl;
#endif
          this->le->fixups[oi][fixup.offset] = fixup;
          this->le->fixup_addresses.insert (fixup.address);
        }
    }

  return true;
}

bool
LinearExecutable::Loader::load_fixup_record_table (void)
{
  size_t oi;

  this->le->fixups.resize (this->le->objects.size ());

  for (oi = 0; oi < this->le->objects.size (); oi++)
    {
      if (!load_fixup_record_pages (oi))
          return false;
    }

  return true;
}


const LinearExecutable::Header *
LinearExecutable::get_header (void) const
{
  return &this->header;
}

const LinearExecutable::FixupMap *
LinearExecutable::get_fixups_for_object (size_t index) const
{
  if (index > this->objects.size ())
    return NULL;

  return &this->fixups[index];
}

const LinearExecutable::AddressSet *
LinearExecutable::get_fixup_addresses (void) const
{
  return &this->fixup_addresses;
}

size_t
LinearExecutable::get_object_count (void) const
{
  return this->objects.size ();
}

const LinearExecutable::ObjectHeader *
LinearExecutable::get_object_header (size_t index) const
{
  if (index >= this->objects.size ())
    return NULL;

  return &this->objects[index];
}

const LinearExecutable::ObjectHeader *
LinearExecutable::get_object_header_at_address (uint32_t addr) const
{
  const ObjectHeader *hdr;
  size_t n;

  for (n = 0; n < this->objects.size (); n++)
    {
      hdr = &this->objects[n];

      if (hdr->base_address <= addr
          and addr < hdr->base_address + hdr->virtual_size)
        return hdr;
    }

  return NULL;
}

const LinearExecutable::ObjectPageHeader *
LinearExecutable::get_page_header (size_t index) const
{
  if (index >= this->object_pages.size ())
    return NULL;

  return &this->object_pages[index];
}

size_t
LinearExecutable::get_page_file_offset (size_t index) const
{
  const ObjectPageHeader *hdr;

  hdr = this->get_page_header (index);
  if (hdr == NULL)
    return 0;

  return ((hdr->first_number + hdr->second_number - 1)
          * this->header.page_size + this->header.data_pages_offset);
}

LinearExecutable *
LinearExecutable::load (std::istream *is, const std::string &name)
{
  Loader loader;
  return loader.load (is, name);
}


ostream &
operator<< (ostream &os, const LinearExecutable::Header &hdr)
{
  const size_t value_col = 40;

  print_variable (&os, value_col, "byte_order",
                  hdr.byte_order);
  print_variable (&os, value_col, "word_order",
                  hdr.word_order);
  print_variable (&os, value_col, "format_version",
                  hdr.format_version);
  print_variable (&os, value_col, "cpu_type",
                  hdr.cpu_type);
  print_variable (&os, value_col, "os_type",
                  hdr.os_type);
  print_variable (&os, value_col, "module_version",
                  hdr.module_version);
  print_variable (&os, value_col, "module_flags",
                  hdr.module_flags);
  print_variable (&os, value_col, "page_count",
                  hdr.page_count);
  print_variable (&os, value_col, "eip_object_index",
                  hdr.eip_object_index);
  print_variable (&os, value_col, "eip_offset",
                  hdr.eip_offset);
  print_variable (&os, value_col, "esp_object_index",
                  hdr.esp_object_index);
  print_variable (&os, value_col, "esp_offset",
                  hdr.esp_offset);
  print_variable (&os, value_col, "page_size",
                  hdr.page_size);
  print_variable (&os, value_col, "last_page_size",
                  hdr.last_page_size);
  print_variable (&os, value_col, "fixup_section_size",
                  hdr.fixup_section_size);
  print_variable (&os, value_col, "fixup_section_check_sum",
                  hdr.fixup_section_check_sum);
  print_variable (&os, value_col, "loader_section_size",
                  hdr.loader_section_size);
  print_variable (&os, value_col, "loader_section_check_sum",
                  hdr.loader_section_check_sum);
  print_variable (&os, value_col, "object_table_offset",
                  hdr.object_table_offset);
  print_variable (&os, value_col, "object_count",
                  hdr.object_count);
  print_variable (&os, value_col, "object_page_table_offset",
                  hdr.object_page_table_offset);
  print_variable (&os, value_col, "object_iterated_pages_offset",
                  hdr.object_iterated_pages_offset);
  print_variable (&os, value_col, "resource_table_offset",
                  hdr.resource_table_offset);
  print_variable (&os, value_col, "resource_entry_count",
                  hdr.resource_entry_count);
  print_variable (&os, value_col, "resident_name_table_offset",
                  hdr.resident_name_table_offset);
  print_variable (&os, value_col, "entry_table_offset",
                  hdr.entry_table_offset);
  print_variable (&os, value_col, "module_directives_offset",
                  hdr.module_directives_offset);
  print_variable (&os, value_col, "module_directives_count",
                  hdr.module_directives_count);
  print_variable (&os, value_col, "fixup_page_table_offset",
                  hdr.fixup_page_table_offset);
  print_variable (&os, value_col, "fixup_record_table_offset",
                  hdr.fixup_record_table_offset);
  print_variable (&os, value_col, "import_module_name_table_offset",
                  hdr.import_module_name_table_offset);
  print_variable (&os, value_col, "import_module_name_entry_count",
                  hdr.import_module_name_entry_count);
  print_variable (&os, value_col, "import_procedure_name_table_offset",
                  hdr.import_procedure_name_table_offset);
  print_variable (&os, value_col, "per_page_check_sum_table_offset",
                  hdr.per_page_check_sum_table_offset);
  print_variable (&os, value_col, "data_pages_offset",
                  hdr.data_pages_offset);
  print_variable (&os, value_col, "preload_pages_count",
                  hdr.preload_pages_count);
  print_variable (&os, value_col, "non_resident_name_table_offset",
                  hdr.non_resident_name_table_offset);
  print_variable (&os, value_col, "non_resident_name_entry_count",
                  hdr.non_resident_name_entry_count);
  print_variable (&os, value_col, "non_resident_name_table_check_sum",
                  hdr.non_resident_name_table_check_sum);
  print_variable (&os, value_col, "auto_data_segment_object_index",
                  hdr.auto_data_segment_object_index);
  print_variable (&os, value_col, "debug_info_offset",
                  hdr.debug_info_offset);
  print_variable (&os, value_col, "debug_info_size",
                  hdr.debug_info_size);
  print_variable (&os, value_col, "instance_pages_count",
                  hdr.instance_pages_count);
  print_variable (&os, value_col, "instance_pages_demand_count",
                  hdr.instance_pages_demand_count);
  print_variable (&os, value_col, "heap_size",
                  hdr.heap_size);

  return os;
}

ostream &
operator<< (ostream &os, const LinearExecutable::ObjectHeader &hdr)
{
  const size_t value_col = 40;

  print_variable (&os, value_col, "virtual_size", hdr.virtual_size);
  print_variable (&os, value_col, "base_address", hdr.base_address);
  print_variable (&os, value_col, "flags", hdr.flags);
  print_variable (&os, value_col, "first_page_index", hdr.first_page_index);
  print_variable (&os, value_col, "page_count", hdr.page_count);
  print_variable (&os, value_col, "reserved", hdr.reserved);

  return os;
}

ostream &
operator<< (ostream &os, const LinearExecutable::ObjectPageHeader &hdr)
{
  PUSH_IOS_FLAGS (&os);

  os.setf (ios::hex, ios::basefield);
  os.setf (ios::showbase);

  os << std::setw (6) << (uint32_t) hdr.first_number << ' '
     << std::setw (6) << (uint32_t) hdr.second_number << ' '
     << hdr.type;

  return os;
}

ostream &
operator<< (ostream &os, const LinearExecutable::ObjectPageType &type)
{
  typedef LinearExecutable LE;

  switch (type)
    {
    case LE::LEGAL:       os << "LEGAL";          break;
    case LE::ITERATED:    os << "ITERATED";       break;
    case LE::INVALID:     os << "INVALID";        break;
    case LE::ZERO_FILLED: os << "ZERO_FILLED";    break;
    case LE::LAST:        os << "LAST";           break;
    default:              os << "(invalid type)"; break;
    }

  return os;
}
