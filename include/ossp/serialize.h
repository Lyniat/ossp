/*
* MIT License
*
* Copyright (c) 2025 Laurin "lyniat" Muth
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
*         of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
*         to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*         copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
*         copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*         AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#pragma once

#include <bytebuffer/buffer.h>
#include "../mruby.h"

using namespace lyniat::memory::buffer;

namespace lyniat::ossp::serialize {
    static constexpr std::uint32_t LE_MAGIC_NUMBER = 0x4F535350; //OSSP
    static constexpr uint32_t BE_MAGIC_NUMBER = 0x5053534F; //OSSP
    static const char* END_OF_DATA = "EOD"; // EOD
    static const char* END_OF_FILE = "EOF"; // EOF
    static constexpr uint32_t EOD_POSITION = 0;
    static constexpr uint32_t EOF_POSITION = 0;
    static constexpr uint64_t FLAGS = 0;

    static constexpr unsigned char FLAG_SERVER =   0b00000001;
    static constexpr unsigned char FLAG_CLIENTS =  0b00000010;
    static constexpr unsigned char FLAG_SELF =     0b00000100;

    typedef unsigned short int st_counter_t;

    enum serialized_type : unsigned char {
        ST_FALSE = 0,
        ST_TRUE,
        ST_INT,
        ST_FLOAT,
        ST_SYMBOL,
        ST_HASH,
        ST_ARRAY,
        ST_STRING,
        ST_UNDEF,
        ST_NIL,
        ST_EOD = 69, // 69 = ASCII E / could also be EOF
        ST_ADV_BYTE_1 = 127,
        ST_ADV_BYTE_2,
        ST_ADV_BYTE_3,
        ST_ADV_BYTE_4,
        ST_ADV_BYTE_5,
        ST_ADV_BYTE_6,
        ST_ADV_BYTE_7,
        ST_ADV_BYTE_8,
        ST_INVALID = 255,
    };
}

namespace lyniat::ossp::serialize::bin {
    void start_serialize_data(ByteBuffer* binary_buffer, mrb_state* mrb, mrb_value data);

    mrb_value start_deserialize_data(ByteBuffer* binary_buffer, mrb_state* mrb);
}