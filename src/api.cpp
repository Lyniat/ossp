/*
* MIT License
*
* Copyright (c) 2023 Laurin Muth
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

#ifdef USE_DRGTK
drb_api_t* drb_api;
#endif

std::vector<mrb_value> value_list;
std::vector<mrb_value> own_data_list;

#define __temp_state update_state
void push_to_updates(const std::string &event_type, mrb_value value) {
    auto hash = mrb_hash_new_capa(update_state, 2);
    PEXT_H(hash, "type", event_type);
    PEXT_H(hash, "data", value);
    value_list.push_back(hash);
}

void push_to_updates(mrb_sym event_type, mrb_value value) {
    auto hash = mrb_hash_new_capa(update_state, 2);
    PEXT_H(hash, "type", event_type);
    PEXT_H(hash, "data", value);
    value_list.push_back(hash);
}

void push_error(const std::string &event_type, int id) {
    auto hash = mrb_hash_new_capa(update_state, 3);
    PEXT_H(hash, "type", "error");
    PEXT_H(hash, "data", event_type);
    PEXT_H(hash, "id", id);
    value_list.push_back(hash);
}
#undef __temp_state