#include "ossp/ossp.h"

#include "ossp/help.h"
#include "ossp/serialize.h"

namespace lyniat::ossp::serialize::bin {

void OSSP::Serialize(ByteBuffer* bb, mrb_state* mrb, mrb_value data, const std::string& meta_data) {
    bb->AppendWithEndian(LE_MAGIC_NUMBER, endian);
    bb->AppendWithEndian(EOD_POSITION, endian);
    bb->AppendWithEndian(FLAGS, endian);
    SerializeRecursive(bb, mrb, data);
    auto data_size = bb->Size();
    if (data_size > UINT32_MAX) {
        // TODO: handle this problem just in case it should ever happen
    }
    bb->SetAtWithEndian(sizeof(LE_MAGIC_NUMBER), (uint32_t)data_size, endian);

    if (!meta_data.empty()) {
        bb->Append(END_OF_DATA, strlen(END_OF_DATA));
        bb->AppendString(meta_data);
        bb->Append(END_OF_FILE, strlen(END_OF_FILE));
    } else {
        bb->Append(END_OF_FILE, strlen(END_OF_FILE));
    }
}

mrb_value OSSP::Deserialize(ReadBuffer* bb, mrb_state* mrb) {
    uint32_t magic_number;
    uint32_t eod_position;
    uint64_t flags;
    if (!bb->ReadWithEndian(&magic_number, endian)) {
        return mrb_undef_value();
    }

    if (magic_number != LE_MAGIC_NUMBER) {
        return mrb_undef_value();
    }

    if (!bb->ReadWithEndian(&eod_position, endian)) {
        return mrb_undef_value();
    }

    if (!bb->ReadWithEndian(&flags, endian)) {
        return mrb_undef_value();
    }

    auto bb_size = bb->Size();
    auto eof_len = strlen(END_OF_FILE);
    if (bb_size < eof_len) {
        return mrb_undef_value();
    }

    std::string first_end_content;
    bb->ReadStringAt(eod_position, &first_end_content, strlen(END_OF_DATA));
    bool has_meta_data = false;
    if (first_end_content == std::string(END_OF_DATA)) {
        has_meta_data = true;
    } else if (first_end_content != std::string(END_OF_FILE)) {
        return mrb_undef_value();
    }

    mrb_value ossp_meta_data = mrb_nil_value();
    if (has_meta_data) {
        //auto bb_end = std::string((const char*)bb->DataAt(bb_size - strlen(END_OF_FILE)), strlen(END_OF_FILE));
        std::string bb_end;
        bb->ReadStringAt((bb_size - strlen(END_OF_FILE)),&bb_end ,strlen(END_OF_FILE));
        if (bb_end != std::string(END_OF_FILE)) {
            return mrb_undef_value();
        }
        auto str_n = bb_size - eod_position - strlen(END_OF_DATA) - strlen(END_OF_FILE);
        //auto meta_str = std::string((const char*)bb->DataAt(eod_position + strlen(END_OF_DATA)), str_n);
        std::string meta_str;
        bb->ReadStringAt((eod_position + strlen(END_OF_DATA)), &meta_str, str_n);
        ossp_meta_data = mrb_str_new_cstr(mrb, meta_str.c_str());
    }

    auto deserialized = DeserializeRecursive(bb, mrb);

    mrb_value array = mrb_ary_new_capa(mrb, 2);
    mrb_ary_set(mrb, array, 0, deserialized);
    mrb_ary_set(mrb, array, 1, ossp_meta_data);
    return array;
}

void OSSP::SerializeRecursive(ByteBuffer* bb, mrb_state* mrb, mrb_value data) {
    auto stype = GetType(data);
    auto type = (uint8_t)stype;
    if (stype == ST_FALSE || stype == ST_TRUE || stype == ST_NIL) {
        bb->AppendWithEndian((uint8_t)type, endian);
    } else if (stype == ST_INT) {
        mrb_int number = cext_to_int(mrb, data);
        #ifdef ADV_SER
        split_int64_auto(number, bb);
        #else
        bb->AppendWithEndian((uint8_t)ST_INT, endian);
        bb->AppendWithEndian(number, endian);
        #endif
    } else if (stype == ST_FLOAT) {
        mrb_float number = cext_to_float(mrb, data);
        bb->AppendWithEndian((uint8_t)ST_FLOAT, endian);
        bb->AppendWithEndian(number, endian);
    } else if (stype == ST_STRING) {
        const char* string = cext_to_string(mrb, data);
        st_counter_t str_len = strlen(string); // + 1; we SKIP this intentionally
        bb->AppendWithEndian((uint8_t)ST_STRING, endian);
        bb->AppendWithEndian(str_len, endian);
        bb->Append((char*)string, str_len);
    } else if (stype == ST_SYMBOL) {
        const char* string = mrb_sym_name(mrb, mrb_obj_to_sym(mrb, data));
        st_counter_t str_len = strlen(string); // + 1; we SKIP this intentionally
        bb->AppendWithEndian((uint8_t)ST_SYMBOL, endian);
        bb->AppendWithEndian(str_len, endian);
        bb->Append((char*)string, str_len);
    } else if (stype == ST_ARRAY) {
        bb->AppendWithEndian((uint8_t)ST_ARRAY, endian);
        st_counter_t array_size = RARRAY_LEN(data);
        bb->AppendWithEndian(array_size, endian);
        for (mrb_int i = 0; i < array_size; i++) {
            auto object = RARRAY_PTR(data)[i];
            SerializeRecursive(bb, mrb, object);
        }
    } else if (stype == ST_HASH) {
        bb->AppendWithEndian((uint8_t)ST_HASH, endian);
        auto current_pos = bb->CurrentReadingPos();
        auto hash = mrb_hash_ptr(data);

        st_counter_t hash_size = mrb_hash_size(mrb, data);
        bb->AppendWithEndian(hash_size, endian);

        typedef struct to_pass_t {
            ByteBuffer* buffer;
        } to_pass_t;
        to_pass_t to_pass = {bb};

        mrb_hash_foreach(mrb, hash, {[](mrb_state* intern_state, mrb_value key, mrb_value val, void* passed) -> int {
            auto to_pass = (to_pass_t*)passed;
            auto bb = to_pass->buffer;

            if (AddHashKey(bb, intern_state, key)) {
                SerializeRecursive(bb, intern_state, val);
            }
            return 0;
        }}, &to_pass);
    }
}

mrb_value OSSP::DeserializeRecursive(ReadBuffer* rb, mrb_state* mrb) {
uint8_t bin_type;
    if (!rb->ReadWithEndian(&bin_type, endian)) {
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
        if (!rb->ReadWithEndian(&data_size, endian)) {
            return mrb_undef_value();
        }
        auto str_ptr = mrb_malloc(mrb, data_size);
        if (!rb->Read((char*)str_ptr, data_size)) {
            return mrb_undef_value();
        }
        mrb_value data = mrb_str_new(mrb, (const char*)str_ptr, data_size);
        mrb_free(mrb, str_ptr);
        return data;
    }

    if (type == ST_SYMBOL) {
        st_counter_t data_size;
        if (!rb->ReadWithEndian(&data_size, endian)) {
            return mrb_undef_value();
        }
        auto str_ptr = mrb_malloc(mrb, data_size);
        if (!rb->Read((char*)str_ptr, data_size)) {
            return mrb_undef_value();
        }
        auto sym = mrb_intern_str(mrb, mrb_str_new(mrb, (const char*)str_ptr, data_size));
        auto data = mrb_symbol_value(sym);
        mrb_free(mrb, str_ptr);
        return data;
    }

    if (type == ST_INT) {
        mrb_int num;
        if (!rb->ReadWithEndian(&num, endian)) {
            return mrb_undef_value();
        }
        return mrb_int_value(mrb, num);
    }

    if (type == ST_FLOAT) {
        mrb_float num;
        if (!rb->ReadWithEndian(&num, endian)) {
            return mrb_undef_value();
        }
        return mrb_float_value(mrb, num);
    }

    if (type == ST_HASH) {
        st_counter_t hash_size;
        if (!rb->ReadWithEndian(&hash_size, endian)) {
            return mrb_undef_value();
        }
        mrb_value hash = mrb_hash_new_capa(mrb, hash_size);

        for (st_counter_t i = 0; i < hash_size; ++i) {
            auto success = SetHashKey(rb, mrb, hash);
            if (!success) {
                return mrb_undef_value();
            }
        }
        return hash;
    }

    if (type == ST_ARRAY) {
        st_counter_t array_size;
        if (!rb->ReadWithEndian(&array_size, endian)) {
            return mrb_undef_value();
        }
        mrb_value array = mrb_ary_new_capa(mrb, array_size);

        for (st_counter_t i = 0; i < array_size; ++i) {
            mrb_value data = DeserializeRecursive(rb, mrb);
            mrb_ary_set(mrb, array, i, data);
        }
        return array;
    }

    if (type == ST_EOD) {
        return mrb_nil_value();
    }

    return mrb_undef_value();
}

bool OSSP::SetHashKey(ReadBuffer* rb, mrb_state* state, mrb_value hash) {
    serialized_type key_type;
    if (!rb->ReadWithEndian((u_int8_t*)&key_type, endian)) {
        return false;
    }
    mrb_value key;

    if (key_type == ST_STRING) {
        st_counter_t key_size;
        if (!rb->ReadWithEndian(&key_size, endian)) {
            return false;
        }
        auto str_ptr = mrb_malloc(state, key_size);
        if (!rb->Read((char*)str_ptr, key_size)) {
            return false;
        }
        key = mrb_str_new(state, (const char*)str_ptr, key_size);
        mrb_free(state, str_ptr);
    } else if (key_type == ST_SYMBOL) {
        st_counter_t key_size;
        if (!rb->ReadWithEndian(&key_size, endian)) {
            return false;
        }
        auto str_ptr = mrb_malloc(state, key_size);
        if (!rb->Read((char*)str_ptr, key_size)) {
            return false;
        }
        auto sym = mrb_intern_str(state, mrb_str_new(state, (const char*)str_ptr, key_size));
        key = mrb_symbol_value(sym);
        mrb_free(state, str_ptr);
    } else if (key_type == ST_INT) {
        mrb_int num_key;
        if (!rb->ReadWithEndian(&num_key, endian)) {
            return false;
        }
        key = mrb_int_value(state, num_key);
    } else if (key_type == ST_FLOAT) {
        mrb_float num_key;
        if (!rb->ReadWithEndian(&num_key, endian)) {
            return false;
        }
        key = mrb_float_value(state, num_key);
    } else if (key_type >= ST_ADV_BYTE_1 && key_type <= ST_ADV_BYTE_8) {
        auto num_bytes = key_type - ST_ADV_BYTE_1 + 1;
        int64_t value = 0;
        uint8_t byte;
        // first byte is sign
        //int8_t first_byte = (int8_t)buffer[1];
        if (!rb->ReadWithEndian(&byte, endian)) {
            return false;
        }

        // add sign for negative numbers
        if (byte < 0) {
            value = -1LL; // Set all bits to 1
        }

        // read bytes left to right (Big Endian)
        for (size_t i = 0; i < num_bytes; i++) {
            if (!rb->ReadWithEndian(&byte, endian)) {
                return false;
            }
            value = (value << 8) | byte;
        }

        //bb->ReadWithEndian(&num_key, endian);
        //key = mrb_int_value(state, num_key);
    } else {
        return false;
    }

    mrb_value data = DeserializeRecursive(rb, state);

    mrb_hash_set(state, hash, key, data);
    return true;
}

bool OSSP::AddHashKey(ByteBuffer* bb, mrb_state* state, mrb_value key) {
    auto key_type = GetType(key);

    if (key_type == ST_STRING) {
        auto s_key = mrb_string_cstr(state, key);
        bb->AppendWithEndian((uint8_t)ST_STRING, endian);
        st_counter_t str_len = strlen(s_key); // + 1; we SKIP this intentionally
        bb->AppendWithEndian(str_len, endian);
        bb->Append((char*)s_key, str_len);
    } else if (key_type == ST_SYMBOL) {
        auto s_key = mrb_sym_name(state, mrb_obj_to_sym(state, key));
        bb->AppendWithEndian((uint8_t)ST_SYMBOL, endian);
        st_counter_t str_len = strlen(s_key); // + 1; we SKIP this intentionally
        bb->AppendWithEndian(str_len, endian);
        bb->Append((char*)s_key, str_len);
    } else if (key_type == ST_INT) {
        auto num_key = cext_to_int(state, key);

        #ifdef ADV_SER
        split_int64_auto(num_key, bb);
        #else
        bb->AppendWithEndian((uint8_t)ST_INT, endian);
        bb->AppendWithEndian(num_key, endian);
        #endif

    } else if (key_type == ST_FLOAT) {
        auto num_key = cext_to_float(state, key);
        bb->AppendWithEndian((uint8_t)ST_FLOAT, endian);
        bb->AppendWithEndian(num_key, endian);
    } else {
        return false;
    }

    return true;
}

serialized_type OSSP::GetType(mrb_value data) {
    if (mrb_nil_p(data)) {
        return ST_NIL;
    }
    mrb_vtype type = mrb_type(data);
    switch (type) {
        case MRB_TT_FALSE: return ST_FALSE;
        case MRB_TT_TRUE: return ST_TRUE;
        case MRB_TT_STRING: return ST_STRING;
        case MRB_TT_INTEGER: return ST_INT;
        case MRB_TT_FLOAT: return ST_FLOAT;
        case MRB_TT_SYMBOL: return ST_SYMBOL;
        case MRB_TT_HASH: return ST_HASH;
        case MRB_TT_ARRAY: return ST_ARRAY;
        default: return ST_UNDEF;
    }
}

serialized_type OSSP::SplitInt64(int64_t value, ByteBuffer* bb) {
    if (bb == nullptr) {
        return ST_INVALID;
    }

    auto st = GetMinBytes(value);

    bb->AppendWithEndian((uint8_t)st, endian);
    auto n_bytes = st - ST_ADV_BYTE_1 + 1;

    // Big Endian: MSB first
    for (size_t i = 0; i < n_bytes; i++) {
        size_t shift = (n_bytes - 1 - i) * 8;
        bb->Append((uint8_t)((value >> shift) & 0xFF));
    }

    return st;
}

serialized_type OSSP::GetMinBytes(int64_t value) {
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

    if (needed_bits <= 8) {
        return ST_ADV_BYTE_1;
    }
    if (needed_bits <= 16) {
        return ST_ADV_BYTE_2;
    }
    if (needed_bits <= 24) {
        return ST_ADV_BYTE_3;
    }
    if (needed_bits <= 32) {
        return ST_ADV_BYTE_4;
    }
    if (needed_bits <= 40) {
        return ST_ADV_BYTE_5;
    }
    if (needed_bits <= 48) {
        return ST_ADV_BYTE_6;
    }
    if (needed_bits <= 56) {
        return ST_ADV_BYTE_7;
    }
    if (needed_bits <= 64) {
        return ST_ADV_BYTE_8;
    }

    return ST_ADV_BYTE_8;
}

}