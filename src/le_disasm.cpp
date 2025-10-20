/*
 * le_disasm - Linear Executable disassembler
 */
/** @file le_disasm.cpp
 *     Main function and printing capabilities.
 * @par Purpose:
 *     Implements main function of the tool, and functions required for
 *     printing the output. Assembly instructions are not formatted here
 *     though - they're received from Disassembler already in text form.
 * @author   Unavowed <unavowed@vexillium.org>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <cassert>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <getopt.h>

#include "analyser.hpp"
#include "error.hpp"
#include "image.hpp"
#include "instruction.hpp"
#include "known_file.hpp"
#include "label.hpp"
#include "le.hpp"
#include "le_image.hpp"
#include "regions.hpp"
#include "symbol_map.hpp"
#include "util.hpp"

using std::ios;

struct Options {
  std::string exefile;
  std::string mapfile;
};

static void
print_separator (void)
{
  int n;

  std::cout << "/*";

  for (n = 0; n < 64; n++)
    std::cout << '-';

  std::cout << "*/\n";
}

static void
print_label (const Label *lab)
{
  int indent;

  switch (lab->get_type ())
    {
    case Label::FUNCTION:
      std::cout << "\n\n";
      print_separator ();
      indent = 0;
      break;

    case Label::JUMP:
      indent = 1;
      break;

    case Label::DATA:
      indent = 0;
      break;

    case Label::VTABLE:
      indent = 0;
      std::cout << '\n';
      break;

    default:
      indent = 0;
      break;
    }

  while (indent-- > 0)
    std::cout << '\t';

  std::cout << *lab << ":";

  if (!lab->get_name ().empty ())
    {
      PUSH_IOS_FLAGS (&std::cout);
      std::cout.setf (ios::hex, ios::basefield);
      std::cout.setf (ios::showbase);

      std::cout << "\t/* " << lab->get_address () << " */";
    }

  std::cout << '\n';

  switch (lab->get_type ())
    {
    case Label::FUNCTION:
      print_separator ();
      break;

    default:
      break;
    }
}

static std::string
replace_addresses_with_labels (const std::string &str, Image *img,
                               LinearExecutable *le, Analyser *anal)
{
  std::ostringstream oss;
  const Label *lab;
  size_t n, start;
  uint32_t addr;
  std::string addr_str;
  std::string comment;

  n = str.find ("0x");
  if (n == std::string::npos)
    return str;

  start = 0;

  do
    {
      oss << str.substr (start, n - start);

      if (n + 2 >= str.length ())
        break;

      n += 2;
      start = n;

      while (n < str.length () and isxdigit (str[n]))
        n++;

      addr_str = str.substr (start, n - start);
      addr = strtol (addr_str.c_str (), NULL, 16);
      lab = anal->get_label (addr);
      if (lab != NULL)
        oss << *lab;
      else
        {
          oss << "0x" << addr_str;

          if (img->get_object_at_address (addr) != NULL
              and le->get_fixup_addresses ()->find (addr)
                  != le->get_fixup_addresses ()->end ())
            {
              comment = " /* Warning: address points to a valid object/reloc, "
                        "but no label found */";
            }
        }

      start = n;
      n = str.find ("0x", start);
    }
  while (n != std::string::npos);

  if (start < str.length ())
    oss << str.substr (start);

  if (!comment.empty ())
    oss << comment;

  return oss.str ();
}

static void
print_instruction (Instruction *inst, Image *img, LinearExecutable *le,
                   Analyser *anal)
{
  std::string str;
  std::string::size_type n;

  str = replace_addresses_with_labels (inst->get_string (), img, le, anal);

  n = str.find ("(287 only)");
  if (n != std::string::npos)
    {
      std::cout << "\t\t/* " << str << " -- ignored */\n";
      return;
    }

  /* Work around buggy libopcodes */
  if (str == "lar    %cx,%ecx")
    str = "lar    %ecx,%ecx";
  else if (str == "lsl    %ax,%eax")
    str = "lsl    %eax,%eax";

  std::cout << "\t\t" << str;

  if (str == "data16" or str == "data32")
    std::cout << " ";
  else
    std::cout << "\n";
}

static bool
data_is_address (const Image::Object *obj, uint32_t addr, size_t len,
                 LinearExecutable *le)
{
  uint32_t offset;
  const LEFM *fups;

  if (len < 4)
    return false;

  fups = le->get_fixups_for_object (obj->get_index ());
  offset = addr - obj->get_base_address ();

  if (fups->find (offset) == fups->end ())
    return false;

  return true;
}

static bool
data_is_zeros (const Image::Object *obj, uint32_t addr, size_t len, size_t *rlen)
{
  size_t x;
  const uint8_t *data;

  data = obj->get_data_at (addr);

  for (x = 0; x < len; x++)
    {
      if (data[x] != 0)
        break;
    }

  if (x < 4)
    return false;

  *rlen = x;
  return true;
}

static bool
data_is_string (const Image::Object *obj, uint32_t addr, size_t len, size_t *rlen,
                bool *zero_terminated)
{
  size_t x;
  const uint8_t *data;

  data = obj->get_data_at (addr);

  for (x = 0; x < len; x++)
    {
      if ((data[x] < 0x20 or data[x] >= 0x7f)
          and not (data[x] == '\t' or data[x] == '\n' or data[x] == '\r'))
        break;
    }

  if (x < 4)
    return false;

  if (x < len and data[x] == 0)
    {
      *zero_terminated = true;
      x += 1;
    }
  else
    *zero_terminated = false;

  *rlen = x;
  return true;
}

static void
print_escaped_string (const uint8_t *data, size_t len)
{
  size_t n;

  for (n = 0; n < len; n++)
    {
      if (data[n] == '\t')
        std::cout << "\\t";
      else if (data[n] == '\r')
        std::cout << "\\r";
      else if (data[n] == '\n')
        std::cout << "\\n";
      else if (data[n] == '\\')
        std::cout << "\\\\";
      else if (data[n] == '"')
        std::cout << "\\\"";
      else
        std::cout << (char) data[n];
    }
}

static void
print_region (const Region *reg, const Image::Object *obj, LinearExecutable *le,
              Image *img, Analyser *anal)
{
  const Label *label;
  size_t addr;
  int bytes_in_line;
  Disassembler disasm;
  Instruction inst;
  LEFM::const_iterator itr;
  bool warn_once;

#ifdef DEBUG
  std::cerr << "Region: " << *reg << std::endl;
#endif

  warn_once = true;
  obj = img->get_object_at_address (reg->get_address ());
  addr = reg->get_address ();

  switch (reg->get_type ())
    {
    case Region::CODE:
      while (addr < reg->get_end_address ())
        {
          label = anal->get_label (addr);
          if (label != NULL)
            print_label (label);

          disasm.disassemble (addr, obj->get_data_at (addr),
                              reg->get_end_address () - addr, &inst);
          print_instruction (&inst, img, le, anal);

          addr += inst.get_size ();
        }
      break;

    case Region::DATA:
      size_t len;
      size_t size;
      const Label *label;
      const LEFM *fups;
      bool zt;

      bytes_in_line = 0;

      fups = le->get_fixups_for_object (obj->get_index ());
      itr = fups->begin ();

      while (addr < reg->get_end_address ())
        {
          label = anal->get_label (addr);
          if (label != NULL)
            {
              if (bytes_in_line > 0)
                {
                  std::cout << "\"\n";
                  bytes_in_line = 0;
                }

              print_label (label);
            }

          len = reg->get_end_address () - addr;

          label = anal->get_next_label (addr);
          if (label != NULL)
            len = std::min (len, label->get_address () - addr);

          while (itr != fups->end ()
                 and itr->first <= addr - obj->get_base_address ())
            ++itr;

          if (itr != fups->end ())
            len = std::min<size_t> (len,
                                    itr->first
                                    - (addr - obj->get_base_address ()));

          while (len > 0)
            {
              if (data_is_address (obj, addr, len, le))
                {
                  const Label *dlabel;
                  uint32_t value;

                  if (bytes_in_line > 0)
                    {
                      std::cout << "\"\n";
                      bytes_in_line = 0;
                    }

                  value = read_le<uint32_t> (obj->get_data_at (addr));
                  dlabel = anal->get_label (value);
                  if (dlabel != NULL) {
                      std::cout << "\t\t.long   " << *dlabel << "\n";
                  } else {
                      if (warn_once) {
                          warn_once = false;
                          std::cerr << "Warning: Data is an address but destination has no label: 0x"
                            << std::hex << value << ".\n";
                      }

                      std::cout << " /* Warning: address points to a valid object/reloc, "
                            "destination has no label */" << "\n";
                      std::cout << "\t\t.long   0x" << std::hex << value << "\n";
                  }

                  addr += 4;
                  len -= 4;
                }
              else if (data_is_zeros (obj, addr, len, &size))
                {
                  PUSH_IOS_FLAGS (&std::cout);
                  std::cout.setf (ios::hex, ios::basefield);
                  std::cout.setf (ios::showbase);

                  if (bytes_in_line > 0)
                    {
                      std::cout << "\"\n";
                      bytes_in_line = 0;
                    }

                  std::cout << "\t\t.fill   " << size << "\n";
                  addr += size;
                  len -= size;
                }
              else if (data_is_string (obj, addr, len, &size, &zt))
                {
                  if (bytes_in_line > 0)
                    {
                      std::cout << "\"\n";
                      bytes_in_line = 0;
                    }

                  if (zt)
                    std::cout << "\t\t.string \"";
                  else
                    std::cout << "\t\t.ascii   \"";

                  print_escaped_string (obj->get_data_at (addr), size - zt);

                  std::cout << "\"\n";

                  addr += size;
                  len -= size;
                }
              else
                {
                  char buffer[8];

                  if (bytes_in_line == 0)
                    std::cout << "\t\t.ascii  \"";

                  snprintf (buffer, sizeof (buffer), "\\x%02x",
                            *obj->get_data_at (addr));
                  std::cout << buffer;

                  bytes_in_line += 1;
                  
                  if (bytes_in_line == 8)
                    {
                      std::cout << "\"\n";
                      bytes_in_line = 0;
                    }

                  addr++;
                  len--;
                }
            }
        }

      if (bytes_in_line > 0)
        std::cout << "\"\n";

      break;

    case Region::VTABLE:
      uint32_t func_addr;
      const Label *next_label;

      /* TODO: limit by relocs */

      next_label = anal->get_label (addr);
      if (next_label != NULL)
        {
          print_label (next_label);
        }
      else
        {
         std::cerr << "Warning: VTABLE has no label: 0x"
             << std::hex << addr << ".\n";

         std::cout << " /* Warning: Start of VTABLE, but has no label */" << "\n";
       }
      next_label = anal->get_next_label (addr);

      for (; addr < reg->get_end_address (); addr += 4)
        {
          if (next_label != NULL and addr == next_label->get_address ())
            {
              print_label (next_label);
              next_label = anal->get_next_label (addr);
            }

          func_addr = read_le<uint32_t> (obj->get_data_at (addr));

          if (func_addr == 0)
            {
              std::cout << "\t\t.long   0\n";
              continue;
            }

          label = anal->get_label (func_addr);

          if (label == NULL)
            {
              if (warn_once)
                {
                  warn_once = false;
                  std::cerr << "Warning: Some addresses in VTABLE have no label, first: 0x"
                      << std::hex << func_addr << ".\n";
                }
              continue;
            }
          std::cout << "\t\t.long   " << *label << "\n";
        }
      break;

    default:
      break;
    }
}

static void
print_code (LinearExecutable *le, Image *img, Analyser *anal)
{
  enum Section
  {
    NONE,
    TEXT,
    DATA
  };

  Analyser::RegionMap::const_iterator itr;
  const Analyser::RegionMap *regions;
  const Region *prev = NULL;
  const Region *next;
  const Region *reg;
  const Image::Object *obj;
  Section sec = NONE;

  regions = anal->get_regions ();

  std::cerr << "Region count: " << regions->size () << "\n";

  for (itr = regions->begin (); itr != regions->end (); ++itr)
    {
      reg = &itr->second;
      obj = img->get_object_at_address (reg->get_address ());

      if (reg->get_type () == Region::DATA)
        {
          if (sec != DATA)
            {
              std::cout << ".data\n";
              sec = DATA;
            }
        }
      else
        {
          if (sec != TEXT)
            {
              std::cout << ".text\n";
              sec = TEXT;
            }
        }

      print_region (reg, obj, le, img, anal);

      if (prev != NULL)
        assert (prev->get_end_address () <= reg->get_address ());

      next = anal->get_next_region (reg);
      if (next == NULL or next->get_address () > reg->get_end_address ())
        {
          const Label *l;

          l = anal->get_label (reg->get_end_address ());
          if (l != NULL)
            print_label (l);
        }

      prev = reg;
    }
}

void
debug_print_regions (Analyser *anal)
{
  const Analyser::RegionMap *map;
  Analyser::RegionMap::const_iterator itr;

  map = anal->get_regions ();

  std::cout << "---------- Regions -------------\n";

  for (itr = map->begin (); itr != map->end (); ++itr)
    std::cout << itr->second << "\n";
}

void
main_execute(Options &options)
{
  std::unique_ptr<LinearExecutable> le;
  std::unique_ptr<SymbolMap> syms;
  std::unique_ptr<Image> image;
  std::ifstream ifs;
  Analyser anal;

  syms = std::unique_ptr<SymbolMap>(
      new SymbolMap
  );

  if (!options.mapfile.empty())
    syms->load_file_map(options.mapfile);

  ifs.open (options.exefile, std::ios::binary);
  if(!ifs.is_open())
    {
      throw Error() << "Error opening file: " << options.exefile;
    }

  le = std::unique_ptr<LinearExecutable>(
      LinearExecutable::load (&ifs, options.exefile)
  );

  image = std::unique_ptr<Image>(
      create_image (&ifs, le.get())
  );

  anal = Analyser (le.get(), image.get(), syms.get());

  KnownFile::check(anal, le.get());
  KnownFile::pre_anal_fixups_apply(anal);

  anal.run ();

  KnownFile::post_anal_fixups_apply(anal);

  print_code (le.get(), image.get(), &anal);
}

int
main (int argc, char **argv)
{
  static const option longopts[] = {
      {"exefile", required_argument, NULL, 'e'},
      {"mapfile", required_argument, NULL, 'm'},
      {0}};
  bool show_usage = false;
  Options options;

  while (1)
    {
      const int opt = getopt_long(argc, argv, "he:m:", longopts, 0);

      if (opt == -1) {
          break;
      }

      switch (opt) {
        case 'e':
          options.exefile = optarg;
          break;
        case 'm':
          options.mapfile = optarg;
          break;
        case 'h':
        default: /* '?' */
          show_usage = true;
          break;
      }
    }

  if (options.exefile.empty())
    show_usage = true;

  if (show_usage)
    {
      std::cerr << "Usage: " << argv[0] << " -e <main.exe> [-m <symbols.map>]\n";
      return 1;
    }

  try
    {
      main_execute(options);
    }
  catch (const std::exception &e)
    {
      std::cerr << std::dec << e.what() << std::endl;
      return 1;
    }

  return 0;
}
