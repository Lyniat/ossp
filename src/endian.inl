/*
* Copyright 2010-2025 Branimir Karadzic. All rights reserved.
 * License: https://github.com/bkaradzic/bx/blob/master/LICENSE
 */

//#ifndef BX_ENDIAN_H_HEADER_GUARD
//#	error "Must be included from bx/endian.h!"
//#endif // BX_ENDIAN_H_HEADER_GUARD

// Endianness
#define BX_CPU_ENDIAN_BIG    0
#define BX_CPU_ENDIAN_LITTLE 0

// CPU
#define BX_CPU_ARM   0
#define BX_CPU_X86   0

// http://sourceforge.net/apps/mediawiki/predef/index.php?title=Architectures
#if defined(__arm__)     \
|| defined(__aarch64__) \
|| defined(_M_ARM)
#	undef  BX_CPU_ARM
#	define BX_CPU_ARM 1
#	undef  BX_CPU_ENDIAN_LITTLE
#	define BX_CPU_ENDIAN_LITTLE 1
#else
#	undef  BX_CPU_X86
#	define BX_CPU_X86 1
#	undef  BX_CPU_ENDIAN_LITTLE
#	define BX_CPU_ENDIAN_LITTLE 1
#endif

namespace bx
{
    inline int16_t endianSwap(int16_t _in)
    {
        return (int16_t)endianSwap( (uint16_t)_in);
    }

    inline uint16_t endianSwap(uint16_t _in)
    {
        return (_in>>8) | (_in<<8);
    }

    inline uint32_t endianSwap(uint32_t _in)
    {
        return (  _in            >>24) | (  _in            <<24)
             | ( (_in&0x00ff0000)>> 8) | ( (_in&0x0000ff00)<< 8)
             ;
    }

    inline int32_t endianSwap(int32_t _in)
    {
        return (int32_t)endianSwap( (uint32_t)_in);
    }

    inline uint64_t endianSwap(uint64_t _in)
    {
        return   (_in                               >>56) | (  _in                               <<56)
             | ( (_in&UINT64_C(0x00ff000000000000) )>>40) | ( (_in&UINT64_C(0x000000000000ff00) )<<40)
             | ( (_in&UINT64_C(0x0000ff0000000000) )>>24) | ( (_in&UINT64_C(0x0000000000ff0000) )<<24)
             | ( (_in&UINT64_C(0x000000ff00000000) )>> 8) | ( (_in&UINT64_C(0x00000000ff000000) )<< 8)
             ;
    }

    inline int64_t endianSwap(int64_t _in)
    {
        return (int64_t)endianSwap( (uint64_t)_in);
    }

    inline double endianSwap(double _in)
    {
        double retVal;
        char *floatToConvert = ( char* ) & _in;
        char *returnFloat = ( char* ) & retVal;

        // swap the bytes into a temporary buffer
        returnFloat[0] = floatToConvert[7];
        returnFloat[1] = floatToConvert[6];
        returnFloat[2] = floatToConvert[5];
        returnFloat[3] = floatToConvert[4];
        returnFloat[4] = floatToConvert[3];
        returnFloat[5] = floatToConvert[2];
        returnFloat[6] = floatToConvert[1];
        returnFloat[7] = floatToConvert[0];

        return retVal;
    }

    template <typename Ty>
    inline Ty toLittleEndian(Ty _in)
    {
#if BX_CPU_ENDIAN_BIG
        return endianSwap(_in);
#else
        return _in;
#endif // BX_CPU_ENDIAN_BIG
    }

    template <typename Ty>
    inline Ty toBigEndian(Ty _in)
    {
#if BX_CPU_ENDIAN_LITTLE
        return endianSwap(_in);
#else
        return _in;
#endif // BX_CPU_ENDIAN_LITTLE
    }

    template <typename Ty>
    inline Ty toHostEndian(Ty _in, bool _fromLittleEndian)
    {
#if BX_CPU_ENDIAN_LITTLE
        return _fromLittleEndian ? _in : endianSwap(_in);
#else
        return _fromLittleEndian ? endianSwap(_in) : _in;
#endif // BX_CPU_ENDIAN_LITTLE
    }

} // namespace bx