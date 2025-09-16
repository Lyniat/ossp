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

#include "../include/ossp/api.h"
#include "../include/ossp/help.h"

mrb_int cext_to_int(mrb_state* state, mrb_value value){
    return mrb_integer_func(mrb_to_int(state, value));
}

mrb_float cext_to_float(mrb_state* state, mrb_value value){
    return mrb_to_flo(state, value);
}

const char* cext_to_string(mrb_state* state, mrb_value value){
    return mrb_string_cstr(state, value);
}

mrb_sym cext_sym(mrb_state* state, const char* str){
    return mrb_intern_check_cstr(state, str);
}

mrb_value cext_key(mrb_state* state, const char* str){
    return mrb_str_new_cstr(state, str);
}

mrb_value cext_key_sym(mrb_state* state, const char* str){
    return mrb_symbol_value(cext_sym(state, str));
}

mrb_value cext_hash_get(mrb_state* state, mrb_value hash, const char* key){
    auto result_with_str = mrb_hash_get(state, hash, cext_key(state, key));
    if(result_with_str.w == 0){
        return mrb_hash_get(state, hash, cext_key_sym(state, key));
    }
    return result_with_str;
}

mrb_int cext_hash_get_int(mrb_state* state, mrb_value hash, const char* key){
    return cext_to_int(state, mrb_hash_get(state, hash, cext_key(state, key)));
}

const char* cext_hash_get_string(mrb_state* state, mrb_value hash, const char* key){
    return cext_to_string(state, mrb_hash_get(state, hash, cext_key(state, key)));
}

mrb_sym cext_hash_get_sym(mrb_state* state, mrb_value hash, const char* key){
    return mrb_obj_to_sym(state, cext_hash_get(state, hash, key));
}

mrb_value cext_hash_get_save_hash(mrb_state* state, mrb_value hash, const char* key){
    auto h = cext_hash_get(state, hash, key);
    if((cext_is_hash(state, h))){
        return h;
    }
    return mrb_hash_new(state);
}

void cext_hash_set_kstr(mrb_state* state, mrb_value hash, const char* key, mrb_value val){
    mrb_hash_set(state, hash, mrb_str_new_cstr(state, key), val);
}

void cext_hash_set_ksym(mrb_state* state, mrb_value hash, const char* key, mrb_value val){
    mrb_hash_set(state, hash, cext_key_sym(state, key), val);
}

mrb_sym pext_sym(mrb_state* state, const char* str) {
    return mrb_intern_cstr(state, str);
}

mrb_sym pext_sym(mrb_state* state, const std::string &val) {
    return pext_sym(state, val.c_str());
}

mrb_value pext_sym_val(mrb_state* state, const char* str) {
    return mrb_symbol_value(pext_sym(state, str));
}

mrb_value pext_sym_val(mrb_state* state, const std::string &val) {
    return mrb_symbol_value(pext_sym(state, val.c_str()));
}

mrb_value pext_str(mrb_state* state, const char* str) {
    return mrb_str_new_cstr(state, str);
}

mrb_value pext_str(mrb_state* state, const std::string &str) {
    return mrb_str_new_cstr(state, str.c_str());
}

bool cext_is_string(mrb_state* state, mrb_value value){
    return mrb_type(value) == MRB_TT_STRING;
}

bool cext_is_symbol(mrb_state* state, mrb_value value){
    return mrb_type(value) == MRB_TT_SYMBOL;
}

bool cext_is_int(mrb_state* state, mrb_value value){
    return mrb_type(value) == MRB_TT_INTEGER;
}

bool cext_is_hash(mrb_state* state, mrb_value value){
    return mrb_type(value) == MRB_TT_HASH;
}

bool cext_is_array(mrb_state* state, mrb_value value){
    return mrb_type(value) == MRB_TT_ARRAY;
}

bool cext_is_undef(mrb_state* state, mrb_value value){
    return mrb_type(value) == MRB_TT_UNDEF;
}

mrb_int cext_hash_get_int_default(mrb_state* state, mrb_value hash, const char* key, mrb_int def){
    auto value = cext_hash_get(state, hash, key);
    if(cext_is_int(state, value)){
        return cext_to_int(state, value);
    }
    return def;
}

const char* cext_hash_get_string_default(mrb_state* state, mrb_value hash, const char* key, const char* def){
    auto value = cext_hash_get(state, hash, key);
    if(cext_is_string(state, value)){
        return cext_to_string(state, value);
    }
    return def;
}

mrb_sym cext_hash_get_sym_default(mrb_state* state, mrb_value hash, const char* key, mrb_sym def){
    auto value = cext_hash_get(state, hash, key);
    if(cext_is_symbol(state, value)){
        return mrb_obj_to_sym(state, value);
    }
    return def;
}