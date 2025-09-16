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

#include <cstdint>

namespace lyniat::ossp::buffer {
    class BinaryBuffer{
    public:
        BinaryBuffer();

        explicit BinaryBuffer(unsigned int size);

        BinaryBuffer(void* new_ptr, unsigned int size, bool copy = false);

        // Rule of Five Implementation
        BinaryBuffer(const BinaryBuffer& other);
        BinaryBuffer& operator=(const BinaryBuffer& other);
        BinaryBuffer(BinaryBuffer&& other) noexcept;
        BinaryBuffer& operator=(BinaryBuffer&& other) noexcept;


        ~BinaryBuffer();

        template<typename T>
        bool Append(T data){
            return AppendData(&data, sizeof(T));
        }

        template<typename T>
        bool Append(T* data, unsigned int size){
            return AppendData(data, size);
        }

        template<typename T>
        bool Append(const T* data, unsigned int size){
            return AppendData(data, size);
        }

        template<typename T>
        bool SetAt(unsigned int pos, T data){
            return SetDataAt(pos, &data, sizeof(T));
        }

        template<typename T>
        bool SetAt(unsigned int pos, T* data, unsigned int size){
            return SetDataAt(pos, data, size);
        }

        template<typename T>
        bool Read(T* data){
            return ReadData(data, sizeof(T));
        }

        template<typename T>
        bool Read(T* data, unsigned int size){
            return ReadData(data, size);
        }

        const void* Data() const;

        void* MutableData();

        const void* DataAt(unsigned int position) const;

        unsigned int Size();

        bool ReadOnly();

        unsigned int CurrentPos();

        bool Compress();

        bool Uncompress();

        uint64_t Hash();

        //void Append(void* data, int size);

    private:
        void* ptr;
        unsigned int b_size;
        unsigned int b_length;
        bool AppendData(const void* data, unsigned int size);
        bool SetDataAt(unsigned int pos, void* data, unsigned int size);
        bool ReadData(void* data, unsigned int size);
        unsigned int current_pos;
        bool free_memory;
        bool read_only;

        // read feature
        unsigned int current_read_pos;
    };

}