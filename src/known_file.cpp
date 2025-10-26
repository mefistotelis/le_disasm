/*
 * le_disasm - Linear Executable disassembler
 */
/** @file known_file.cpp
 *     Implementation of KnownFile class methods.
 * @par Purpose:
 *     Implementation of KnownFile class with static methods to recognize
 *     known binaries for which the tool has a special processing tweaks.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include "known_file.hpp"
#include "analyser.hpp"
#include "label.hpp"
#include "regions.hpp"

#include "le.hpp"

void
KnownFile::check(Analyser &anal, LinearExecutable *le)
{
  const LinearExecutable::Header *header = le->get_header();

  anal.known_type = KnownFile::NOT_KNOWN;

  if (header->eip_offset == 0xd581c &&
      header->esp_offset == 0x9ffe0 &&
      header->last_page_size == 0x34a &&
      header->fixup_section_size == 0x5d9ca &&
      header->loader_section_size == 0x5df3f &&
      header->object_count == 4)
    {
      if (le->get_object_header(0)->virtual_size == 0x12d030 &&
          le->get_object_header(0)->base_address == 0x10000 &&
          le->get_object_header(1)->virtual_size == 0x96 &&
          le->get_object_header(1)->base_address == 0x140000 &&
          le->get_object_header(2)->virtual_size == 0x9ffe0 &&
          le->get_object_header(2)->base_address == 0x150000 &&
          le->get_object_header(3)->virtual_size == 0x1b58 &&
          le->get_object_header(3)->base_address == 0x1f0000)
        {
          anal.known_type = KnownFile::KNOWN_SYNDWARS_FINAL_MAIN;
          return;
        }
    }
  if (header->eip_offset == 0x2d85c &&
      header->esp_offset == 0x13e60 &&
      header->last_page_size == 0xe39 &&
      header->fixup_section_size == 0x12ee9 &&
      header->loader_section_size == 0x130f6 &&
      header->object_count == 4)
    {
      if (le->get_object_header(0)->virtual_size == 0x3fdf4 &&
          le->get_object_header(0)->base_address == 0x10000 &&
          le->get_object_header(1)->virtual_size == 0x13e60 &&
          le->get_object_header(1)->base_address == 0x50000 &&
          le->get_object_header(2)->virtual_size == 0xc00 &&
          le->get_object_header(2)->base_address == 0x70000 &&
          le->get_object_header(3)->virtual_size == 0x1c632 &&
          le->get_object_header(3)->base_address == 0x80000)
        {
          anal.known_type = KnownFile::KNOWN_SYNDPLUS_FINAL_MAIN;
          return;
        }
    }
}

void
KnownFile::pre_anal_fixups_apply(Analyser &anal)
{
  const char *ident_str = NULL;

  switch (anal.known_type)
    {
    case KnownFile::KNOWN_SYNDWARS_FINAL_MAIN:
      ident_str = "Syndicate Wars Final `main.exe`";
      anal.insert_region (Region (0x0e581e,   0x76, Region::DATA));
      anal.insert_region (Region (0x0e5af1,    0xf, Region::DATA));
      anal.insert_region (Region (0x0e73e2,   0x4e, Region::DATA));
      anal.insert_region (Region (0x0ea128,  0x202, Region::DATA));
      anal.insert_region (Region (0x10ae19,   0x25, Region::DATA));
      anal.insert_region (Region (0x10aeb5,   0x25, Region::DATA));
      anal.insert_region (Region (0x117830,  0x200, Region::DATA));
      anal.insert_region (Region (0x1233f3,   0x40, Region::DATA));
      anal.insert_region (Region (0x12b3d0, 0x2450, Region::DATA));
      anal.set_label (Label (0x03cd08, Label::JUMP));
      anal.set_label (Label (0x03fdc8, Label::JUMP));
      anal.set_label (Label (0x035644, Label::JUMP));
      anal.set_label (Label (0x13c443, Label::JUMP));
      anal.set_label (Label (0x140096, Label::FUNCTION));
      break;
    case KnownFile::KNOWN_SYNDPLUS_FINAL_MAIN:
      ident_str = "Syndicate Plus Final `main.exe`";
      anal.insert_region (Region (0x014550,  0x018, Region::VTABLE));
      anal.insert_region (Region (0x014568,  0x0ac, Region::VTABLE));
      anal.insert_region (Region (0x015C0C,  0x034, Region::VTABLE));
      anal.insert_region (Region (0x015C40,  0x020, Region::VTABLE));
      anal.insert_region (Region (0x016508,  0x040, Region::VTABLE));
      anal.insert_region (Region (0x0175B0,  0x010, Region::VTABLE));
      anal.insert_region (Region (0x018238,  0x010, Region::VTABLE));
      anal.insert_region (Region (0x01BE1C,   0x9c, Region::VTABLE));
      anal.insert_region (Region (0x01D390,  0x0a8, Region::VTABLE));
      anal.insert_region (Region (0x01D438,  0x014, Region::VTABLE));
      anal.insert_region (Region (0x01FB50,   0x64, Region::VTABLE));
      anal.insert_region (Region (0x025830,  0x0b4, Region::VTABLE));
      anal.insert_region (Region (0x025920,  0x0ec, Region::VTABLE));
      anal.insert_region (Region (0x026EB0,  0x034, Region::VTABLE));
      anal.insert_region (Region (0x029760,  0x030, Region::VTABLE));
      anal.insert_region (Region (0x02C340,  0x044, Region::VTABLE));
      anal.insert_region (Region (0x02F980,  0x010, Region::VTABLE));
      anal.insert_region (Region (0x02FCE0,  0x040, Region::VTABLE));
      anal.insert_region (Region (0x02FE2C,  0x040, Region::VTABLE));
      anal.insert_region (Region (0x0312F8,  0x044, Region::VTABLE));
      anal.insert_region (Region (0x0346C0,  0x020, Region::VTABLE));
      anal.insert_region (Region (0x034A70,  0x020, Region::VTABLE));
      anal.insert_region (Region (0x034AB0,  0x020, Region::VTABLE));
      anal.insert_region (Region (0x0375C0,  0x010, Region::VTABLE));
      anal.insert_region (Region (0x0375D0,  0x030, Region::VTABLE));
      anal.insert_region (Region (0x040431,   0x25, Region::DATA)); // CSTRING
      anal.insert_region (Region (0x0404FB,   0x25, Region::DATA)); // CSTRING
      anal.insert_region (Region (0x04225E,  0x044, Region::VTABLE));
      anal.insert_region (Region (0x042ADE,   0x08, Region::DATA));
      anal.insert_region (Region (0x042AE6,   0x08, Region::DATA));
      anal.insert_region (Region (0x043992,   0x10, Region::VTABLE));
      anal.insert_region (Region (0x048794,   0x10, Region::VTABLE));
      anal.insert_region (Region (0x0488BD,   0x10, Region::VTABLE));
      anal.insert_region (Region (0x0489CC,   0x10, Region::VTABLE));
      anal.insert_region (Region (0x04A3A7,   0x10, Region::VTABLE));
      anal.insert_region (Region (0x04FC81,   0x40, Region::DATA));
      anal.insert_region (Region (0x04FD30,  0x028, Region::DATA));
      anal.insert_region (Region (0x04FDA3,  0x028, Region::DATA));
      anal.insert_region (Region (0x04FDE4,  0x010, Region::DATA)); // CSTRING
      break;
    case KnownFile::NOT_KNOWN:
      break;
    }
  if (ident_str != NULL)
    std::cerr << "Known file: " << ident_str << ".\n";
}

void
KnownFile::post_anal_fixups_apply(Analyser &anal)
{
  switch (anal.known_type)
    {
    case KnownFile::KNOWN_SYNDWARS_FINAL_MAIN:
      anal.remove_label (0x10000);
      break;
    case KnownFile::NOT_KNOWN:
      break;
    }
}
