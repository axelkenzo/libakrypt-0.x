/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hash-sha3.c                                                                             */
/*  - содержит реализацию алгоритма бесключевого хэширования SHA3                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
#include <stdlib.h>
#else
#error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
#include <string.h>
#else
#error Library cannot be compiled without string.h header
#endif

#include <ak_parameters.h>
#include <ak_hash.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования SHA3             */

    /*текущий хеш*/
    union sha3_struct
    {
        ak_uint8 b[200];
        ak_uint64 q[25];
    };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, реализующая циклическое смещение                                               */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint64 ROT64(ak_uint64 x, ak_uint64 y)
{
#ifdef LIBAKRYPT_LITTLE_ENDIAN
    return (((x) << y) | ((x) >> (64 - y)));
#else
    return bswap_64((bswap_64(x) << y) | (bswap_64(x) >> (64 - y)));
#endif
}

//static void printIntInMem(ak_uint64 x)
//{
//    unsigned char* p_uch = (unsigned char*)((void*)&x);
//    for(int i = 0; i < 8; i++)
//    {
//        printf("%02X", p_uch[i] & 0xFF);
//    }
//    printf(" ");
//}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция раундовых перестановок (θ,ρ,π,χ,ι)                                           */
/* ----------------------------------------------------------------------------------------------- */
static inline void keccak_permut(ak_uint64 state[25])
{
    int i, j, r;
    ak_uint64 t, bc[5];
    for (r = 0; r < 24; r++)
    {
        /* θ */
        //printIntInMem(state[r]);
        for (i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            //printIntInMem(bc[i]);
        }
        for (i = 0; i < 5; i++)
        {
            t = bc[(i + 4) % 5] ^ ROT64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }
        /* ρ и π*/
        t = state[1];
        for (i = 0; i < 24; i++)
        {
            j = keccak_pi[i];
            bc[0] = state[j];
            state[j] = ROT64(t, keccak_ro[i]);
            t = bc[0];
        }
        /* χ */
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5; i++)
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        /* ι */
    #ifdef LIBAKRYPT_LITTLE_ENDIAN
        state[0] ^= keccakf_rc[r];
    #else
        state[0] ^= keccakf_rc_be[r];
    #endif
    }
}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */

static int ak_hash_sha3_clean( ak_pointer ctx )
{

    union  sha3_struct *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );
    sx = ( union  sha3_struct * ) ((( ak_hash ) ctx ))->data;
    memset( sx->q, 0, sizeof(sx->q));
    return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция "впитывания" для ровного количества блоков
    @param ctx указатель на контекст структуры struct hash
    @param in блок обрабатываемых данных
    @param size длина блока обрабатываемых данных в байтах; данное значение должно быть кратно
    длине блока обрабатываемых данных   */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha3_update(ak_pointer ctx, const ak_pointer in, const size_t size)
{

    ak_uint64 quot = 0;
    union  sha3_struct *sx = NULL;
    ak_uint32 bsize;

    if( ctx == NULL ) return  ak_error_message( ak_error_null_pointer,
                                                __func__ , "using null pointer to a context" );
    if( !size ) return ak_error_message( ak_error_zero_length,
                                         __func__ , "using zero length for hash data" );
    quot = size/(( ak_hash ) ctx )->bsize;
    if( size - quot*(( ak_hash ) ctx )->bsize ) /* длина данных должна быть кратна ctx->bsize */
        return ak_error_message( ak_error_wrong_length, __func__ , "using data with wrong length" );

    sx = ( union  sha3_struct * ) (( ak_hash ) ctx )->data;
    bsize =(ak_uint32 )((ak_hash)ctx)->bsize;
    size_t i,k;
    ak_int32 j=0;
    for (i=0; i<quot;i++)
    {
        for (k=0; k<bsize;k++)
            sx->b[k] ^= ((const ak_uint8 *) in)[j++];
        keccak_permut(sx->q);
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет завершающее преобразование алгоритма SHA3 и "отжатие"
    @param ctx указатель на контекст структуры struct hash
    @param in блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных
    @param size длина блока обрабатываемых данных
    @param out указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возвращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
static ak_buffer ak_hash_sha3_finalize(ak_pointer ctx, const ak_pointer in, const size_t size, ak_pointer out )
{

    ak_pointer pout = NULL;
    ak_buffer result = NULL;
    ak_int32 bsize;
    size_t p;
    int i;
    union  sha3_struct *sx;

    if( ctx == NULL )
    {
        ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
        return NULL;
    }


    sx = ( union  sha3_struct * ) (( ak_hash ) ctx )->data;
    bsize =(ak_uint32 )((ak_hash)ctx)->bsize;

    if( size >= bsize )
    {
        ak_error_message( ak_error_zero_length, __func__ ,
                          "using wrong length for finalized hash data" );
        return NULL;
    }

    p = 0;

    for(i=0;i<size;i++)
    {
        sx->b[i] ^= ((const ak_uint8 *)in)[p];
        p++;
    }

    /*pad 10*1*/
    if ((((ak_hash)ctx)->oid==ak_oid_context_find_by_name("shake128"))||(((ak_hash)ctx)->oid==ak_oid_context_find_by_name("shake256")))
        sx->b[p] ^= 0x1F;
    else
        sx->b[p] ^= 0x06;
    sx->b[bsize - 1] ^= 0x80;

    keccak_permut(sx->q);

    /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
    if( out != NULL )
        pout = out;
    else
        {
        if(( result = ak_buffer_new_size((( ak_hash )ctx)->hsize )) != NULL )
            pout = result->data;
        else ak_error_message( ak_error_get_value( ), __func__ ,
                               "wrong creation of result buffer" );
        }

    /* копируем нужную часть результирующего массива или выдаем сообщение об ошибке */
    if( pout != NULL )
    {
        memcpy( pout, sx->b, ((ak_hash)ctx)->hsize );
    }
    else ak_error_message( ak_error_out_of_memory, __func__ ,
                             "incorrect memory allocation for result buffer" );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    SHA3, с длиной хэшкода, равной 224 бит.

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha3_224(ak_hash ctx)
{

    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_context_create( ctx, sizeof( union  sha3_struct ), 144 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha3 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 28; /* длина хешкода составляет 224 бит */
    if(( ctx->oid = ak_oid_context_find_by_name( "sha3_224" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */

    ctx->clean =     ak_hash_sha3_clean;
    ctx->update =    ak_hash_sha3_update;
    ctx->finalize =  ak_hash_sha3_finalize;

    /* инициализируем память */
    ak_hash_sha3_clean( ctx );
    return error;

}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    SHA3, с длиной хэшкода, равной 256 бит.

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha3_256(ak_hash ctx)
{

    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_context_create( ctx, sizeof( union  sha3_struct ), 136 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha3 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 32; /* длина хешкода составляет 256 бит */
    if(( ctx->oid = ak_oid_context_find_by_name( "sha3_256" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean =     ak_hash_sha3_clean;
    ctx->update =    ak_hash_sha3_update;
    ctx->finalize =  ak_hash_sha3_finalize;

    /* инициализируем память */
    ak_hash_sha3_clean( ctx );
    return error;

}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    SHA3, с длиной хэшкода, равной 384 бит.

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha3_384(ak_hash ctx)
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_context_create( ctx, sizeof( union  sha3_struct ), 104 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha3 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 48; /* длина хешкода составляет 384 бит */
    if(( ctx->oid = ak_oid_context_find_by_name( "sha3_384" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean =     ak_hash_sha3_clean;
    ctx->update =    ak_hash_sha3_update;
    ctx->finalize =  ak_hash_sha3_finalize;

    /* инициализируем память */
    ak_hash_sha3_clean( ctx );
    return error;

}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    SHA3, с длиной хэшкода, равной 512 бит.

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha3_512(ak_hash ctx)
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_context_create( ctx, sizeof( union  sha3_struct ), 72 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha3 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 64; /* длина хешкода составляет 512 бит */
    if(( ctx->oid = ak_oid_context_find_by_name( "sha3_512" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean =     ak_hash_sha3_clean;
    ctx->update =    ak_hash_sha3_update;
    ctx->finalize =  ak_hash_sha3_finalize;

    /* инициализируем память */
    ak_hash_sha3_clean( ctx );
    return error;

}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    SHAKE. В общем случае, длина хэшкода может быть любой, но в данном случае она будет равна 256 бит.

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_shake128(ak_hash ctx)
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_context_create( ctx, sizeof( union  sha3_struct ), 168 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha3 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 32; /* длина хешкода составляет 128 бит */
    if(( ctx->oid = ak_oid_context_find_by_name( "shake128" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean =     ak_hash_sha3_clean;
    ctx->update =    ak_hash_sha3_update;
    ctx->finalize =  ak_hash_sha3_finalize;

    /* инициализируем память */
    ak_hash_sha3_clean( ctx );
    return error;

}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    SHAKE. В общем случае, длина хэшкода может быть любой, но в данном случае она будет равна 512 бит.

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_shake256(ak_hash ctx)
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_context_create( ctx, sizeof( union  sha3_struct ), 136 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha3 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 64; /* длина хешкода составляет 256 бит */
    if(( ctx->oid = ak_oid_context_find_by_name( "shake256" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean =     ak_hash_sha3_clean;
    ctx->update =    ak_hash_sha3_update;
    ctx->finalize =  ak_hash_sha3_finalize;

    /* инициализируем память */
    ak_hash_sha3_clean( ctx );
    return error;

}


static ak_uint8 sha3_testM2[4]= "abc";

/*! результат хеширования пустого собщения алгоритмом SHA3 в длиной хеш-кода 224 бит */
static ak_uint8 sha3_224_test[28]=
        {
                0x6b,0x4e,0x03,0x42,0x36,0x67,0xdb,0xb7,0x3b,0x6e,0x15,0x45,0x4f,0x0e,0xb1,0xab,0xd4,0x59,0x7f,
                0x9a,0x1b,0x07,0x8e,0x3f,0x5b,0x5a,0x6b,0xc7
        };


static ak_uint8 sha3_224_test2[28]=
        {
                0xe6,0x42,0x82,0x4c,0x3f,0x8c,0xf2,0x4a,0xd0,0x92,0x34,0xee,0x7d,0x3c,0x76,0x6f,0xc9,0xa3,
                0xa5,0x16,0x8d,0x0c,0x94,0xad,0x73,0xb4,0x6f,0xdf
        };
/*! результат хеширования пустого собщения алгоритмом SHA3 в длиной хеш-кода 256 бит */
static ak_uint8 sha3_256_test[32]=
        {
                0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,0xf5,0x80,0xff,0x4d,
                0xe4,0x3b,0x49, 0xfa,0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a
        };

static ak_uint8 sha3_256_test2[32]=
        {
                0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,0x85,0x5f,0x08,0x6e,
                0x3e,0x9d,0x52,0x5b,0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
        };
/*! результат хеширования пустого собщения алгоритмом SHA3 в длиной хеш-кода 384 бит */
static ak_uint8 sha3_384_test[48]=
        {
                0x0c,0x63,0xa7,0x5b,0x84,0x5e,0x4f,0x7d,0x01,0x10,0x7d,0x85,0x2e,0x4c,0x24,0x85,0xc5,0x1a,0x50,
                0xaa,0xaa,0x94,0xfc,0x61,0x99,0x5e,0x71,0xbb,0xee,0x98,0x3a, 0x2a,0xc3,0x71,0x38,0x31,0x26,0x4a,
                0xdb,0x47,0xfb,0x6b,0xd1,0xe0,0x58,0xd5,0xf0,0x04
        };
static ak_uint8 sha3_384_test2[48]=
        {
                0xec,0x01,0x49,0x82,0x88,0x51,0x6f,0xc9,0x26,0x45,0x9f,0x58,0xe2,0xc6,0xad,0x8d,0xf9,0xb4,0x73,
                0xcb,0x0f,0xc0,0x8c,0x25,0x96,0xda,0x7c,0xf0,0xe4,0x9b,0xe4,0xb2,0x98,0xd8,0x8c,0xea,0x92,0x7a,
                0xc7,0xf5,0x39,0xf1,0xed,0xf2,0x28,0x37,0x6d,0x25
        };
/*! результат хеширования пустого собщения алгоритмом SHA3 в длиной хеш-кода 512 бит */
static ak_uint8 sha3_512_test[64]=
        {
                0xa6,0x9f,0x73,0xcc,0xa2,0x3a,0x9a,0xc5,0xc8,0xb5,0x67,0xdc,0x18,0x5a,0x75,0x6e,0x97,0xc9,0x82,0x16,0x4f,
                0xe2,0x58,0x59,0xe0,0xd1,0xdc,0xc1,0x47,0x5c,0x80,0xa6,0x15,0xb2,0x12,0x3a,0xf1,0xf5,0xf9,0x4c,0x11,0xe3,
                0xe9, 0x40,0x2c,0x3a,0xc5,0x58,0xf5,0x00,0x19,0x9d,0x95,0xb6,0xd3,0xe3,0x01,0x75,0x85,0x86,0x28,
                0x1d,0xcd,0x26
        };
static ak_uint8 sha3_512_test2[64]=
        {
                0xb7,0x51,0x85,0x0b,0x1a,0x57,0x16,0x8a,0x56,0x93,0xcd,0x92,0x4b,0x6b,0x09,0x6e,0x08,0xf6,0x21,0x82,0x74,
                0x44,0xf7,0x0d,0x88,0x4f,0x5d,0x02,0x40,0xd2,0x71,0x2e,0x10,0xe1,0x16,0xe9,0x19,0x2a,0xf3,0xc9,0x1a,0x7e,
                0xc5,0x76,0x47,0xe3,0x93,0x40,0x57,0x34,0x0b,0x4c,0xf4,0x08,0xd5,0xa5,0x65,0x92,0xf8,0x27,0x4e,0xec,0x53,
                0xf0
        };
/*! результат хеширования пустого собщения алгоритмом SHAKE в длиной хеш-кода 256бит */
static ak_uint8 shake128_test[32]=
        {
                0x7f,0x9c,0x2b,0xa4,0xe8,0x8f,0x82,0x7d,0x61,0x60,0x45,0x50,0x76,0x05,0x85,0x3e,0xd7,0x3b,0x80,0x93,0xf6,
                0xef,0xbc,0x88,0xeb,0x1a,0x6e,0xac,0xfa,0x66,0xef,0x26
        };
/*! результат хеширования пустого собщения алгоритмом SHAKE в длиной хеш-кода 512бит */
static ak_uint8 shake256_test[64]=
        {
                0x46,0xb9,0xdd,0x2b,0x0b,0xa8,0x8d,0x13,0x23,0x3b,0x3f,0xeb,0x74,0x3e,0xeb,0x24,0x3f,0xcd,0x52,0xea,
                0x62,0xb8,0x1b,0x82,0xb5,0x0c,0x27,0x64,0x6e,0xd5,0x76,0x2f,0xd7,0x5d,0xc4,0xdd,0xd8,0xc0,0xf2,0x00,
                0xcb,0x05,0x01,0x9d,0x67,0xb5,0x92,0xf6,0xfc,0x82,0x1c,0x49,0x47,0x9a,0xb4,0x86,0x40,0x29,0x2e,0xac,
                0xb3,0xb7,0xc4,0xbe
        };

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_hash_test_sha3_224( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[28]; /* буффер длиной 28 байта (224 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();
    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha3_224( &ctx )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3_224 context" );
        return ak_false;
    }

    /* хеширование пустого вектора */
    ak_hash_context_ptr( &ctx, "", 0, out );
    if(( error = ak_error_get_value()) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "invalid calculation of sha3_224 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_224_test, out, 28 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
    } else
    {
        ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 28, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_224_test, 28, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }


    /* хеширование "abc" */
    ak_hash_context_ptr( &ctx, sha3_testM2, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_224 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_224_test2, out, 28 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 2st test for sha3_224 is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 28, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_224_test2, 28, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_context_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_hash_test_sha3_256( void )
{

    struct hash ctx;/* контекст функции хеширования */
    ak_uint8 out[32]; /* буффер длиной 32 байта (256 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();
    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha3_256( &ctx )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3_256 context" );
        return ak_false;
    }

    /* хеширование пустого вектора */
    ak_hash_context_ptr( &ctx, "", 0, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_256_test, out, 32 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
    } else
    {
        ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_256_test, 32, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }


    /* хеширование "abc" */
    ak_hash_context_ptr( &ctx, sha3_testM2, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_256_test2, out, 32 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 2сst test for sha3_256 is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_256_test2, 32, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }
    /* уничтожаем контекст */
    lab_exit: ak_hash_context_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_hash_test_sha3_384( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[48]; /* буффер длиной 48 байта (384 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();
    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha3_384( &ctx )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3_384 context" );
        return ak_false;
    }

    /* хеширование пустого вектора */
    ak_hash_context_ptr( &ctx, "", 0, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_384_test, out, 48 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
    } else
    {
        ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 48, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_384_test, 48, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* хеширование "abc" */
    ak_hash_context_ptr( &ctx, sha3_testM2, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_384_test2, out, 48 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 2st test for sha3_384 is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 48, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_224_test2, 48, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_context_destroy( &ctx );
    return result;
}

bool_t ak_hash_test_sha3_512(void)
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[64]; /* буффер длиной 64 байта (512 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();
    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha3_512( &ctx )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of sha3_512 context" );
        return ak_false;
    }

    /* хеширование пустого вектора */
    ak_hash_context_ptr( &ctx, "", 0, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_512 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_512_test, out, 64 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
    } else
    {
        ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_512_test, 64, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* хеширование "abc" */
    ak_hash_context_ptr( &ctx, sha3_testM2, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha3_512 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha3_512_test2, out, 64 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 2st test for sha3_512 is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha3_512_test2, 64, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }
    /* уничтожаем контекст */
    lab_exit: ak_hash_context_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_hash_test_shake128( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[32]; /* буффер длиной 64 байта (512 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();
    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_shake128( &ctx )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of shake128 context" );
        return ak_false;
    }

    /* хеширование пустого вектора */
    ak_hash_context_ptr( &ctx, "", 0, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of shake128 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( shake128_test, out, 32 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
    } else
    {
        ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( shake128_test, 32, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_context_destroy( &ctx );
    return result;
}
/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_hash_test_shake256( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[64]; /* буффер длиной 64 байта (512 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();
    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_shake256( &ctx )) != ak_error_ok )
    {
        ak_error_message( error, __func__ , "wrong initialization of shake256 context" );
        return ak_false;
    }

    /* хеширование пустого вектора */
    ak_hash_context_ptr( &ctx, "", 0, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of shake256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( shake256_test, out, 64 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
    } else
    {
        ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( shake256_test, 64, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_context_destroy( &ctx );
    return result;
}




