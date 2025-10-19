/*
 * le_disasm - Linear Executable disassembler
 */
/** @file label.hpp
 *     Header file for label.cpp, with declaration of Label class.
 * @par Purpose:
 *     Storage for Label class which stores information on a labelled
 *     address within the binary code or data.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_LABEL_H
#define LEDISASM_LABEL_H

#include <inttypes.h>
#include <string>

class LinearExecutable;
class Image;
class Region;

class Label
{
public:
  enum Type
  {
    UNKNOWN,
    JUMP,
    FUNCTION,
    VTABLE,
    DATA
  };

protected:
  uint32_t address;
  std::string name;
  Label::Type type;

public:
  Label (uint32_t address, Label::Type type = UNKNOWN,
         const std::string &name = "");
  Label (void);
  Label (const Label &other);

  virtual uint32_t  get_address (void) const;
  virtual Label::Type  get_type (void) const;
  virtual std::string  get_name (void) const;

  void improve_from (const Label &lab);
};

std::ostream &operator<< (std::ostream &os, const Label &label);

#endif // LEDISASM_LABEL_H
