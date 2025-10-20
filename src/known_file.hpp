/*
 * le_disasm - Linear Executable disassembler
 */
/** @file known_file.hpp
 *     Header file for known_file.cpp, with declaration of KnownFile class.
 * @par Purpose:
 *     Storage for KnownFile class with static methods to recognize
 *     known binaries for which the tool has a special processing tweaks.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_KNOWN_FILE_H
#define LEDISASM_KNOWN_FILE_H

class Analyser;
class LinearExecutable;

class KnownFile
{
public:
  enum Type
  {
    NOT_KNOWN,
    KNOWN_SYNDWARS_FINAL_MAIN,
    KNOWN_SYNDPLUS_FINAL_MAIN,
  };

  static void check(Analyser &anal, LinearExecutable *le);
  static void pre_anal_fixups_apply(Analyser &anal);
  static void post_anal_fixups_apply(Analyser &anal);
};

#endif // LEDISASM_KNOWN_FILE_H
