/*
 * le_disasm - Linear Executable disassembler
 */
/** @file symbol_ld_map.cpp
 *     Load symbols from .MAP file.
 * @par Purpose:
 *     Implements compatibility layer between .MAP reader and the disassembler.
 * @author   Mefistotelis <mefistotelis@gmail.com>
 * @date     2025-07-27 - 2025-10-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#include <cstring>
#include <iostream>
#include <iomanip>
#include <map>

#include "error.hpp"
#include "MAPReader.hpp"
#include "symbol_map.hpp"
#include "symbol.hpp"

#ifdef WIN32
#  define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#  define _OBJC_NO_COM
#  define NOGDI
#  include <windef.h>
#  include <winbase.h>
#else
#  include  <errno.h>
#endif

#ifdef __EA64__
#  define BADADDR (unsigned long long)-1
  typedef uint64_t ea_t;
#else
#  define BADADDR (unsigned long)-1
  typedef uint32_t ea_t;
#endif

/// Maximum number of segments
#define SEG_MAX_NUM 255

const size_t g_minLineLen = 14; // For a "xxxx:xxxxxxxx " line

#ifdef __EA64__
void linearAddressToSymbolAddr(MapFile::MAPSymbol &sym, unsigned long long linear_addr)
#else
void linearAddressToSymbolAddr(MapFile::MAPSymbol &sym, unsigned long linear_addr)
#endif
{
    unsigned long sseg_start_ea = 0;
    sym.addr = linear_addr - sseg_start_ea;
}

void SymbolMap::load_file_map(const char *fileName)
{
    // Open the map file
    char * pMapStart = NULL;
    size_t mapSize = INVALID_MAPFILE_SIZE;
    MapFile::MAPResult eRet = MapFile::openMAP(fileName, pMapStart, mapSize);
    switch (eRet)
    {
        case MapFile::OS_ERROR:
            throw Error() << "Failed to open \"" << fileName << "\"; " <<
#ifdef WIN32
                "Win32 Error Code = 0x" << std::hex << GetLastError() << ".";
#else
                "OS Error Code = " << std::dec << errno << ".";
#endif
        case MapFile::FILE_EMPTY_ERROR:
            throw Error() << "File \"" << fileName << "\" is empty, read failed.";

        case MapFile::FILE_BINARY_ERROR:
            throw Error() << "File \"" << fileName << "\" seem to be a binary or Unicode, read failed.";

        case MapFile::OPEN_NO_ERROR:
        default:
            break;
    }

    MapFile::SectionType sectnHdr = MapFile::NO_SECTION;
    unsigned long sectnNumber = 0;
    unsigned long validSyms = 0;
    unsigned long invalidSyms = 0;

    // The mark pointer to the end of memory map file
    // all below code must not read or write at and over it
    const char * pMapEnd = pMapStart + mapSize;

    std::cerr << "Parsing symbols from the MAP file \"" << fileName << "\".\n";

    try
    {
        const char * pLine = pMapStart;
        const char * pEOL = pMapStart;
        unsigned long numOfSegs = SEG_MAX_NUM;
        MapFile::MAPSymbol sym;
        MapFile::MAPSymbol prvsym;
        sym.seg = SEG_MAX_NUM;
        sym.addr = BADADDR;
        sym.name[0] = '\0';

        while (pLine < pMapEnd)
        {
            // Skip the spaces, '\r', '\n' characters, blank lines, seek to the
            // non space character at the beginning of a non blank line
            pLine = MapFile::skipSpaces(pEOL, pMapEnd);

            // Find the EOL '\r' or '\n' characters
            pEOL = MapFile::findEOL(pLine, pMapEnd);

            size_t lineLen = (size_t) (pEOL - pLine);
            if (lineLen < g_minLineLen)
            {
                continue;
            }
            char fmt[80];
            fmt[0] = '\0';

            // Check if we're on section header or section end
            if (sectnHdr == MapFile::NO_SECTION)
            {
                sectnHdr = MapFile::recognizeSectionStart(pLine, lineLen);
                if (sectnHdr != MapFile::NO_SECTION)
                {
                    sectnNumber++;
                    std::cerr << "Section start line: \"" << pLine << "\".\n";
                    continue;
                }
            } else
            {
                sectnHdr = MapFile::recognizeSectionEnd(sectnHdr, pLine, lineLen);
                if (sectnHdr == MapFile::NO_SECTION)
                {
                    std::cerr << "Section end line: \"" << pLine << "\".\n";
                    continue;
                }
            }
            MapFile::ParseResult parsed;
            prvsym.seg = sym.seg;
            prvsym.addr = sym.addr;
            std::strncpy(prvsym.name, sym.name, sizeof(sym.name));
            sym.seg = SEG_MAX_NUM;
            sym.addr = BADADDR;
            sym.name[0] = '\0';
            parsed = MapFile::INVALID_LINE;

            switch (sectnHdr)
            {
            case MapFile::NO_SECTION:
                parsed = MapFile::SKIP_LINE;
                break;
            case MapFile::MSVC_MAP:
            case MapFile::BCCL_NAM_MAP:
            case MapFile::BCCL_VAL_MAP:
                parsed = parseMsSymbolLine(sym,pLine,lineLen,g_minLineLen,numOfSegs);
                break;
            case MapFile::WATCOM_MAP:
                parsed = parseWatcomSymbolLine(sym,pLine,lineLen,g_minLineLen,numOfSegs);
                break;
            case MapFile::GCC_MAP:
                parsed = parseGccSymbolLine(sym,pLine,lineLen,g_minLineLen,numOfSegs);
                break;
            }

            if (parsed == MapFile::SKIP_LINE)
            {
                std::cerr << "Skipping line: \"" << pLine << "\".\n";
                continue;
            }
            if (parsed == MapFile::FINISHING_LINE)
            {
                sectnHdr = MapFile::NO_SECTION;
                // we have parsed to end of value/name symbols table or reached EOF
                std::cerr << "Parsing finished at line: \"" << pLine << "\".\n";
                continue;
            }
            if (parsed == MapFile::INVALID_LINE)
            {
                invalidSyms++;
                std::cerr << "Invalid map line: \"" << pLine << "\".\n";
                continue;
            }
            if (parsed == MapFile::COMMENT_LINE)
            {
                std::cerr << "Comment line: \"" << pLine << "\".\n";
                if (BADADDR == sym.addr)
                    continue;
            }
            // Determine the DeDe map file
            char *pname = sym.name;
            if (('<' == pname[0]) && ('-' == pname[1]))
            {
                // Functions indicator symbol of DeDe map
                pname += 2;
            }
            else if ('*' == pname[0])
            {
                // VCL controls indicator symbol of DeDe map
                pname++;
            }
            else if (('-' == pname[0]) && ('>' == pname[1]))
            {
                // VCL methods indicator symbol of DeDe map
                pname += 2;
            }

            ea_t la = sym.addr;/* + getnseg((int) sym.seg)->start_ea; */

            bool didOk;
            // Apply symbols for name
            {
                didOk = 0;//TODO set_name(la, pname, SN_NOCHECK | SN_NOWARN);

                std::cerr << std::setfill('0') << std::setw(4) << std::hex << sym.seg
                     << std::setw(8) << la << " - name " << pname << " "
                     << (didOk ? "succeeded" : "failed") << "\n";
            }
            if (didOk)
                validSyms++;
            else
                invalidSyms++;
        }

    }
    catch (...)
    {
        std::cerr << "Exception while parsing a symbol in MAP file \"" << fileName << "\".\n";
        invalidSyms++;
    }
    MapFile::closeMAP(pMapStart);

    if (sectnNumber == 0)
    {
        throw Error() << "File \"" << fileName << "\" is not a valid MAP file; publics section header wasn't found.";
    }
    else
    {
        // Show the result
        std::cerr << "Result of parsing the MAP file \"" << fileName << "\"\n";
        std::cerr << "   Number of recognized Symbols: " << validSyms << "\n";
        std::cerr << "   Number of invalid Symbols: " << invalidSyms << "\n";
    }
}
