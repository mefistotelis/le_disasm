/*
 * le_disasm - Linear Executable disassembler
 */
/** @file error.hpp
 *     Declaration of Error, an exception class with stream operators support.
 * @par Purpose:
 *     Contains the full declaration and implementation of the Error class,
 *     with ability of constructing error message by stream operators.
 * @author   Mark Nelson <marknelson.us>
 * @date     2010-09-20 - 2024-01-10
 * @par  Copying and copyrights:
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 */
#ifndef LEDISASM_ERROR_H
#define LEDISASM_ERROR_H

#include <sstream>
#include <stdexcept>
#include <string>

// http://marknelson.us/2007/11/13/no-exceptions/
// throw Error() <<"Game over, "
//                     <<mHealth
//                     <<" health points!";
struct Error : public std::exception {
    Error() {
    }

    Error(const Error &that) {
        mWhat += that.mStream.str();
    }

    virtual ~Error() throw() {};

    virtual const char *what() const throw () {
        if (mStream.str().size()) {
            mWhat += mStream.str();
            mStream.str("");
        }
        return mWhat.c_str();
    }

    template<typename T>
    Error& operator<<(const T& t) {
        mStream << t;
        return *this;
    }
private:
    mutable std::stringstream mStream;
    mutable std::string mWhat;
};

#endif // LEDISASM_ERROR_H
