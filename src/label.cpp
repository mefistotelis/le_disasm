/*
 * le_disasm - Linear Executable disassembler
 */
/** @file label.cpp
 *     Implementation of Label class methods.
 * @par Purpose:
 *     Implements methods for handling and printing the Label class instances.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <iostream>

#include "label.hpp"
#include "util.hpp"

Label::Label (uint32_t address, Label::Type type,
  const std::string &name)
{
  this->address = address;
  this->name    = name;
  this->type    = type;
}

Label::Label (void)
{
  this->address = 0;
  this->name    = "";
  this->type    = UNKNOWN;
}

Label::Label (const Label &other)
{
  *this = other;
}

void
Label::improve_from (const Label &lab)
{
  if (this->name.empty ())
      this->name = lab.get_name ();

  if (this->type == UNKNOWN and
      lab.get_type () != UNKNOWN)
    this->type = lab.get_type ();
}

uint32_t
Label::get_address (void) const
{
  return this->address;
}

Label::Type
Label::get_type (void) const
{
  return this->type;
}

std::string
Label::get_name (void) const
{
  return this->name;
}

std::ostream &
operator<< (std::ostream &os, const Label &label)
{
  PUSH_IOS_FLAGS (&os);

  if (label.get_name ().empty ())
    {
      std::string prefix;

      switch (label.get_type ())
        {
        case Label::FUNCTION: prefix = "func";    break;
        case Label::JUMP:     prefix = "jump";    break;
        case Label::DATA:     prefix = "data";    break;
        case Label::VTABLE:   prefix = "vtable";  break;
        default:              prefix = "unknown"; break;
        }

      os << prefix << "_" << std::hex << std::noshowbase
         << label.get_address ();
    }
  else
    os << label.get_name ();

  return os;
}
