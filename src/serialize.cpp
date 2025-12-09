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

#include <bytebuffer/buffer.h>
#include "../include/ossp/serialize.h"
#include "../include/ossp/help.h"
#include "../include/ossp/api.h"
#include "endian.inl"

using namespace lyniat::memory::buffer;

namespace lyniat::ossp::serialize::bin {

    void __serialize_data(ByteBuffer* binary_buffer, mrb_state* mrb, mrb_value data);
    mrb_value __deserialize_data(ByteBuffer* binary_buffer, mrb_state* mrb);
    serialized_type __get_st(mrb_value data);

    serialized_type get_min_bytes_for_signed(int64_t value) {
        // invert for negative numbers
        uint64_t bits = (value < 0) ? ~value : value;

        // find amount of needed bits
        int needed_bits = 0;
        if (bits == 0) {
            needed_bits = 1;
        } else {
            // find the highest bit
            uint64_t temp = bits;
            while (temp > 0) {
                needed_bits++;
                temp >>= 1;
            }
            // +1 for sign
            needed_bits++;
        }

        if (needed_bits <= 8) return ST_ADV_BYTE_1;
        if (needed_bits <= 16) return ST_ADV_BYTE_2;
        if (needed_bits <= 24) return ST_ADV_BYTE_3;
        if (needed_bits <= 32) return ST_ADV_BYTE_4;
        if (needed_bits <= 40) return ST_ADV_BYTE_5;
        if (needed_bits <= 48) return ST_ADV_BYTE_6;
        if (needed_bits <= 56) return ST_ADV_BYTE_7;
        if (needed_bits <= 64) return ST_ADV_BYTE_8;

        return ST_ADV_BYTE_8;
    }

    serialized_type split_int64_auto(int64_t value, ByteBuffer* buffer) {
        if (buffer == nullptr) {
            return ST_INVALID;
        }

        auto st = get_min_bytes_for_signed(value);

        buffer->Append(st);
        auto n_bytes = st - ST_ADV_BYTE_1 + 1;

        value = bx::toBigEndian(value);

        // Big Endian: MSB first
        for (int i = 0; i < n_bytes; i++) {
            int shift = (n_bytes - 1 - i) * 8;
            buffer->Append((uint8_t)((value >> shift) & 0xFF));
        }

        return st;
    }

    serialized_type __get_st(mrb_value data){
        if(mrb_nil_p(data)){
            return ST_NIL;
        }
        mrb_vtype type = mrb_type(data);
        switch (type) {
            case MRB_TT_FALSE:
                return ST_FALSE;
            case MRB_TT_TRUE:
                return ST_TRUE;
            case MRB_TT_STRING:
                return ST_STRING;
            case MRB_TT_INTEGER:
                return ST_INT;
            case MRB_TT_FLOAT:
                return ST_FLOAT;
            case MRB_TT_SYMBOL:
                return ST_SYMBOL;
            case MRB_TT_HASH:
                return ST_HASH;
            case MRB_TT_ARRAY:
                return ST_ARRAY;
            default:
                return ST_UNDEF;
        }
    }
    
    bool add_hash_key(ByteBuffer* binary_buffer, mrb_state* state, mrb_value key){
        auto key_type = __get_st(key);

        if(key_type == ST_STRING) {
            auto s_key = mrb_string_cstr(state, key);
            binary_buffer->Append(ST_STRING);
            st_counter_t str_len = strlen(s_key);// + 1; we SKIP this intentionally
            auto str_len_big_endian = bx::toBigEndian(str_len);
            binary_buffer->Append(str_len_big_endian);
            binary_buffer->Append((void*)s_key, str_len);
        }
        else if(key_type == ST_SYMBOL) {
            auto s_key = mrb_sym_name(state, mrb_obj_to_sym(state, key));
            binary_buffer->Append(ST_SYMBOL);
            st_counter_t str_len = strlen(s_key);// + 1; we SKIP this intentionally
            auto str_len_big_endian = bx::toBigEndian(str_len);
            binary_buffer->Append(str_len_big_endian);
            binary_buffer->Append((void*)s_key, str_len);
        }
        else if(key_type == ST_INT) {
            auto num_key = cext_to_int(state, key);

#ifdef ADV_SER
            split_int64_auto(num_key, binary_buffer);
#else
            num_key = bx::toBigEndian(num_key);
            binary_buffer->Append(ST_INT);
            binary_buffer->Append(num_key);
#endif

        }
        else if(key_type == ST_FLOAT) {
            auto num_key = cext_to_float(state, key);
            num_key = bx::toBigEndian(num_key);
            binary_buffer->Append(ST_FLOAT);
            binary_buffer->Append(num_key);
        }
        else {
            return false;
        }

        return true;
    }

    bool set_hash_key(ByteBuffer* binary_buffer, mrb_state* state, mrb_value hash){
        serialized_type key_type;
        if (!binary_buffer->Read(&key_type)) {
            return false;
        }
        mrb_value key;

        if(key_type == ST_STRING) {
            st_counter_t key_size;
            if (!binary_buffer->Read(&key_size)) {
                return false;
            }
            key_size = bx::toHostEndian(key_size, false);
            auto str_ptr = mrb_malloc(state, key_size);
            if (!binary_buffer->Read(str_ptr, key_size)) {
                return false;
            }
            key = mrb_str_new(state, (const char*)str_ptr, key_size);
            mrb_free(state, str_ptr);
        }
        else if(key_type == ST_SYMBOL) {
            st_counter_t key_size;
            if (!binary_buffer->Read(&key_size)) {
                return false;
            }
            key_size = bx::toHostEndian(key_size, false);
            auto str_ptr = mrb_malloc(state, key_size);
            if (!binary_buffer->Read(str_ptr, key_size)) {
                return false;
            }
            auto sym = mrb_intern_str(state, mrb_str_new(state, (const char*)str_ptr, key_size));
            key = mrb_symbol_value(sym);
            mrb_free(state, str_ptr);
        }
        else if(key_type == ST_INT) {
            mrb_int num_key;
            if (!binary_buffer->Read(&num_key)) {
                return false;
            }
            num_key = bx::toHostEndian(num_key, false);
            key = mrb_int_value(state, num_key);
        }
        else if(key_type == ST_FLOAT) {
            mrb_float num_key;
            if (!binary_buffer->Read(&num_key)) {
                return false;
            }
            num_key = bx::toHostEndian(num_key, false);
            key = mrb_float_value(state, num_key);
        }
        else if(key_type >= ST_ADV_BYTE_1 && key_type <= ST_ADV_BYTE_8) {
            auto num_bytes = key_type - ST_ADV_BYTE_1 + 1;
            int64_t value = 0;
            int8_t byte;
            // first byte is sign
            //int8_t first_byte = (int8_t)buffer[1];
            if (!binary_buffer->Read(&byte)) {
                return false;
            }

            // add sign for negative numbers
            if (byte < 0) {
                value = -1LL; // Alle Bits auf 1 setzen
            }

            // read bytes left to right (Big Endian)
            for (int i = 0; i < num_bytes; i++) {
                if (!binary_buffer->Read(&byte)) {
                    return false;
                }
                value = (value << 8) | byte;
            }

            //binary_buffer->Read(&num_key);
            auto num_key = bx::toHostEndian(value, false);
            key = mrb_int_value(state, num_key);
        }
        else {
            return false;
        }

        mrb_value data = __deserialize_data(binary_buffer, state);

        mrb_hash_set(state, hash, key, data);
        return true;
    }

    void start_serialize_data(ByteBuffer* binary_buffer, mrb_state* state, mrb_value data) {
        binary_buffer->Append(BE_MAGIC_NUMBER);
        binary_buffer->Append(EOD_POSITION);
        binary_buffer->Append(FLAGS);
        __serialize_data(binary_buffer, state, data);
        auto data_size = binary_buffer->Size();
        if (data_size > UINT32_MAX) {
            // TODO: handle this problem just in case it should ever happen
        }
        auto be_data_size = bx::toBigEndian((uint32_t)data_size);
        binary_buffer->Append(END_OF_DATA, strlen(END_OF_DATA));

        binary_buffer->SetAt(sizeof(BE_MAGIC_NUMBER), be_data_size);

        if (true) { // TODO: for testing, should be used if metadata is used
            const auto str = " PLACEHOLDER FOR METADATA";
            binary_buffer->Append(str, strlen(str) + 1);
        }
        binary_buffer->Append(END_OF_FILE, strlen(END_OF_FILE));
    }

    void __serialize_data(ByteBuffer* binary_buffer, mrb_state* state, mrb_value data) {
        auto stype = __get_st(data);
        auto type = (unsigned char)stype;
        if(stype == ST_FALSE || stype == ST_TRUE || stype == ST_NIL) {
            binary_buffer->Append(type);
        }

        else if(stype == ST_INT){
            mrb_int number = cext_to_int(state, data);
#ifdef ADV_SER
            split_int64_auto(number, binary_buffer);
#else
            number = bx::toBigEndian(number);
            binary_buffer->Append(ST_INT);
            binary_buffer->Append(number);
#endif
        }

        else if(stype == ST_FLOAT){
            mrb_float number = cext_to_float(state, data);
            number = bx::toBigEndian(number);
            binary_buffer->Append(ST_FLOAT);
            binary_buffer->Append(number);
        }

        else if(stype == ST_STRING){
            const char* string = cext_to_string(state, data);
            st_counter_t str_len = strlen(string);// + 1; we SKIP this intentionally
            auto str_len_big_endian = bx::toBigEndian(str_len);
            binary_buffer->Append(ST_STRING);
            binary_buffer->Append(str_len_big_endian);
            binary_buffer->Append((void*)string, str_len);
        }

        else if(stype == ST_SYMBOL){
            const char* string = mrb_sym_name(state, mrb_obj_to_sym(state, data));
            st_counter_t str_len = strlen(string);// + 1; we SKIP this intentionally
            auto str_len_big_endian = bx::toBigEndian(str_len);
            binary_buffer->Append(ST_SYMBOL);
            binary_buffer->Append(str_len_big_endian);
            binary_buffer->Append((void*)string, str_len);
        }

        else if(stype == ST_ARRAY){
            binary_buffer->Append(ST_ARRAY);
            auto current_pos = binary_buffer->CurrentPos();
            binary_buffer->Append((st_counter_t)0); // array_size
            st_counter_t array_size = 0;
            for (mrb_int i = 0; i < RARRAY_LEN(data); i++) {
                auto object = RARRAY_PTR(data)[i];
                __serialize_data(binary_buffer, state, object);
                array_size++;
            }
            array_size = bx::toBigEndian(array_size);
            binary_buffer->SetAt(current_pos, array_size);
        }

        else if (stype == ST_HASH) {
            binary_buffer->Append(ST_HASH);
            auto current_pos = binary_buffer->CurrentPos();
            binary_buffer->Append((st_counter_t)0); // hash_size
            st_counter_t hash_size = 0;
            auto hash = mrb_hash_ptr(data);

            typedef struct to_pass_t {ByteBuffer* buffer; st_counter_t* counter;} to_pass_t;
            to_pass_t to_pass = {binary_buffer, &hash_size};

            mrb_hash_foreach(state, hash, {[](mrb_state* intern_state, mrb_value key, mrb_value val, void* passed) -> int {
                auto to_pass = (to_pass_t*)passed;
                auto binary_buffer = to_pass->buffer;
                st_counter_t* hash_size = to_pass->counter;

                if(add_hash_key(binary_buffer, intern_state, key)){
                    __serialize_data(binary_buffer, intern_state, val);
                    *hash_size += 1;
                }
                return 0;
            }}, &to_pass);
            hash_size = bx::toBigEndian(hash_size);
            binary_buffer->SetAt(current_pos, hash_size);
        }
    }

    mrb_value start_deserialize_data(ByteBuffer* binary_buffer, mrb_state* state) {
        uint32_t magic_number;
        uint32_t eod_position;
        uint64_t flags;
        if (!binary_buffer->Read(&magic_number)) {
            return mrb_undef_value();
        }

        if (magic_number != BE_MAGIC_NUMBER) {
            return mrb_undef_value();
        }

        if (!binary_buffer->Read(&eod_position)) {
            return mrb_undef_value();
        }

        if (!binary_buffer->Read(&flags)) {
            return mrb_undef_value();
        }

        auto bb_size = binary_buffer->Size();
        auto eof_len = strlen(END_OF_FILE);
        if (bb_size < eof_len) {
            return mrb_undef_value();
        }
        auto eof_start = bb_size - eof_len;

        auto eof_content = std::string((const char*)binary_buffer->DataAt(eof_start), strlen(END_OF_FILE));
        if (eof_content != std::string(END_OF_DATA) && eof_content != std::string(END_OF_FILE)) {
            return mrb_undef_value();
        }

        auto host_eod_position = bx::toHostEndian(eod_position, false);
        auto eod_content = std::string((const char*)binary_buffer->DataAt(host_eod_position), strlen(END_OF_FILE));

        if (eod_content != END_OF_DATA) {
            return mrb_undef_value();
        }

        return __deserialize_data(binary_buffer, state);
    }

    mrb_value __deserialize_data(ByteBuffer* binary_buffer, mrb_state* state) {
        unsigned char bin_type;
        if (!binary_buffer->Read(&bin_type)) {
            return mrb_undef_value();
        }
        auto type = (serialized_type)bin_type;

        if (type == ST_FALSE) {
            return mrb_false_value();
        }

        if (type == ST_TRUE) {
            return mrb_true_value();
        }

        if (type == ST_NIL) {
            return mrb_nil_value();
        }

        if (type == ST_STRING) {
            st_counter_t data_size;
            if (!binary_buffer->Read(&data_size)) {
                return mrb_undef_value();
            }
            data_size = bx::toHostEndian(data_size, false);
            auto str_ptr = mrb_malloc(state, data_size);
            if (!binary_buffer->Read(str_ptr, data_size)) {
                return mrb_undef_value();
            }
            mrb_value data = mrb_str_new(state, (const char*)str_ptr, data_size);
            mrb_free(state, str_ptr);
            return data;
        }

        if (type == ST_SYMBOL) {
            st_counter_t data_size;
            if (!binary_buffer->Read(&data_size)) {
                return mrb_undef_value();
            }
            data_size = bx::toHostEndian(data_size, false);
            auto str_ptr = mrb_malloc(state, data_size);
            if (!binary_buffer->Read(str_ptr, data_size)) {
                return mrb_undef_value();
            }
            auto sym = mrb_intern_str(state, mrb_str_new(state, (const char*)str_ptr, data_size));
            auto data = mrb_symbol_value(sym);
            mrb_free(state, str_ptr);
            return data;
        }

        if (type == ST_INT) {
            mrb_int num;
            if (!binary_buffer->Read(&num)) {
                return mrb_undef_value();
            }
            num = bx::toHostEndian(num, false);
            return mrb_int_value(state, num);
        }

        if (type == ST_FLOAT) {
            mrb_float num;
            if (!binary_buffer->Read(&num)) {
                return mrb_undef_value();
            }
            num = bx::toHostEndian(num, false);
            return mrb_float_value(state, num);
        }

        if (type == ST_HASH) {
            st_counter_t hash_size;
            if (!binary_buffer->Read(&hash_size)) {
                return mrb_undef_value();
            }
            hash_size = bx::toHostEndian(hash_size, false);
            mrb_value hash = mrb_hash_new_capa(state, hash_size);

            for (st_counter_t i = 0; i < hash_size; ++i) {
                auto success = set_hash_key(binary_buffer, state, hash);
                if (!success) {
                    return mrb_undef_value();
                }
            }
            return hash;
        }

        if (type == ST_ARRAY) {
            st_counter_t array_size;
            if (!binary_buffer->Read(&array_size)) {
                return mrb_undef_value();
            }
            array_size = bx::toHostEndian(array_size, false);
            mrb_value array = mrb_ary_new_capa(state, array_size);

            for (st_counter_t i = 0; i < array_size; ++i) {
                mrb_value data = __deserialize_data(binary_buffer, state);
                mrb_ary_set(state, array, i, data);
            }
            return array;
        }

        if (type == ST_EOD) {
            return mrb_nil_value();
        }

        return mrb_undef_value();
    }
}
