/* 
 * swdisasm - LE disassembler for Syndicate Wars
 * 
 * Copyright (C) 2010  Unavowed <unavowed@vexillium.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <algorithm>
#include <iostream>

#include "le_image.h"

using std::cerr;
using std::min;

static bool
apply_fixups (const LinearExecutable *lx, size_t oi, Image::DataVector *data)
{
  const LinearExecutable::FixupMap *fixups;
  LinearExecutable::FixupMap::const_iterator itr;
  LinearExecutable::Fixup fixup;
  void *ptr;

  fixups = lx->get_fixups_for_object (oi);

  for (itr = fixups->begin (); itr != fixups->end (); ++itr)
    {
      fixup = itr->second;

      if (fixup.offset + 4 >= data->size ())
	return false;

      ptr = &data->front () + fixup.offset;
      write_le<uint32_t> (ptr, fixup.address);
    }

  return true;
}

Image *
create_image (std::istream *is, const LinearExecutable *lx)
{
  typedef LinearExecutable::ObjectHeader OH;

  Image::DataVector data;
  std::vector<Image::Object> objects;
  const OH *ohdr;
  const LinearExecutable::Header *hdr;
  size_t oi;
  size_t size;
  size_t page_idx;
  size_t data_off;
  size_t page_end;

  hdr = lx->get_header ();

  for (oi = 0; oi < lx->get_object_count (); oi++)
    {
      ohdr = lx->get_object_header (oi);

      data.clear ();
      data.resize (ohdr->virtual_size);
      
      data_off = 0;
      page_end = min (ohdr->first_page_index + ohdr->page_count,
		      hdr->page_count);

      for (page_idx = ohdr->first_page_index; page_idx < page_end; page_idx++)
	{
	  if (page_idx + 1 < hdr->page_count)
	    size = min<size_t> (ohdr->virtual_size - data_off,
				hdr->page_size);
	  else
	    size = min<size_t> (ohdr->virtual_size - data_off,
				hdr->last_page_size);

          is->seekg (lx->get_page_file_offset (page_idx));
	  is->read ((char *) &data.front () + data_off, size);
	  if (!is->good ())
	    {
	      cerr << "Unexpected read error.\n";
	      return NULL;
	    }

	  data_off += size;
	}

      if (!apply_fixups (lx, oi, &data))
	{
	  cerr << "Failed to apply fixups.\n";
	  return NULL;
	}

      objects.push_back (Image::Object (oi, ohdr->base_address,
					(ohdr->flags & OH::EXECUTABLE) != 0,
					&data));
    }

  return new Image (&objects);
}
