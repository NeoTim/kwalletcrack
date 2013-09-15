#if defined __GNUC__ && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4)) 
#       define JOHNSWAP(x)      __builtin_bswap32((x))
#       define JOHNSWAP64(x)    __builtin_bswap64((x))
#elif defined (__linux__)
#       include <byteswap.h>
#       define JOHNSWAP(x)              bswap_32((x))
#       define JOHNSWAP64(x)    bswap_64((x))
#elif (_MSC_VER > 1300) && (_M_IX86 >= 400 || defined(CPU_IA32) ||  defined(CPU_X64)) /* MS VC */
#       define JOHNSWAP(x)              _byteswap_ulong((x))
#       define JOHNSWAP64(x)    _byteswap_uint64 (((unsigned __int64)x))
#endif

typedef unsigned int ARCH_WORD_32;

void alter_endianity(void * _x, unsigned int size)
{
        // size is in BYTES
        // since we are only using this in MMX code, we KNOW that we are using x86 CPU's which do not have problems
        // with non aligned 4 byte word access.  Thus, we use a faster swapping function.
        ARCH_WORD_32 *x = (ARCH_WORD_32*)_x;
        int i = -1;
        size>>=2;
        while (++i < size) {
                x[i] = JOHNSWAP(x[i]);
        }
}
