/* ----------------------------------------------------------------------------------------------- */
/*   Created by Андрей Зорькин on 22.05.18.                                                        */
/*                                                                                                 */
/*   Здесь, возможно, должен быть какой-то текст, но пока его нет.                                 */
/*                                                                                                 */
/*                  _            _       _    _                 _                                  */
/*                 / /\         / /\    / /\ / /\             /\ \                                 */
/*                / /  \       / / /   / / // /  \           /  \ \                                */
/*               / / /\ \__   / /_/   / / // / /\ \         / /\ \ \                               */
/*              / / /\ \___\ / /\ \__/ / // / /\ \ \    ____\/_/\ \ \                              */
/*              \ \ \ \/___// /\ \___\/ // / /  \ \ \ /\____/\  / / /                              */
/*               \ \ \     / / /\/___/ // / /___/ /\ \\/____\/ / / /                               */
/*           _    \ \ \   / / /   / / // / /_____/ /\ \       / / /  _                             */
/*          /_/\__/ / /  / / /   / / // /_________/\ \ \     / / /_/\_\                            */
/*          \ \/___/ /  / / /   / / // / /_       __\ \_\   / /_____/ /                            */
/*           \_____\/   \/_/    \/_/ \_\___\     /____/_/   \________/                             */
/*                                                                                                 */
/*                                                                                                 */
/*   ak_sha512.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */

#include <ak_parameters.h>
#include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования SHA-512          */
struct sha512 {
    ak_uint8 *current_block; // указатель на текущий блок
    ak_uint64 words[80]; // 16 + 48
    ak_uint64 A[8]; // для раунда
    ak_uint64 H[8]; // текущий хэш
    ak_uint64 length;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, реализующая циклическое смещение                                               */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint64 rotr(ak_uint64 qword, ak_uint64 n) {
    return (qword >> n) | (qword << (64 - n));
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha512_prepare( struct sha512 *ctx)
{
    ak_uint64 *words = ctx->words;
    for (int z = 0; z < 16; ++z) {
        ((ak_uint8 *) words)[z * 8 + 0] = ctx->current_block[z * 8 + 7];
        ((ak_uint8 *) words)[z * 8 + 1] = ctx->current_block[z * 8 + 6];
        ((ak_uint8 *) words)[z * 8 + 2] = ctx->current_block[z * 8 + 5];
        ((ak_uint8 *) words)[z * 8 + 3] = ctx->current_block[z * 8 + 4];
        ((ak_uint8 *) words)[z * 8 + 4] = ctx->current_block[z * 8 + 3];
        ((ak_uint8 *) words)[z * 8 + 5] = ctx->current_block[z * 8 + 2];
        ((ak_uint8 *) words)[z * 8 + 6] = ctx->current_block[z * 8 + 1];
        ((ak_uint8 *) words)[z * 8 + 7] = ctx->current_block[z * 8 + 0];
    }

    for (int i = 16; i < 80; ++i) {
        ak_uint64 s0 = rotr(words[i-15], 1) ^ rotr(words[i-15], 8) ^ (words[i-15] >> 7);
        ak_uint64 s1 = rotr(words[i-2], 19) ^ rotr(words[i-2], 61) ^ (words[i-2] >> 6);
        words[i] = words[i-16] + s0 + words[i-7] + s1;
    }
    for (int i = 0; i < 8; ++i) {
        ctx->A[i] = ctx->H[i];
    }
}

ak_uint64 sha512_sigma0(ak_uint64 a){
    return rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
}
ak_uint64 sha512_sigma1(ak_uint64 e){
    return rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
}
ak_uint64 sha512_ch(ak_uint64 e, ak_uint64 f, ak_uint64 g){
    return (e & f) ^ ((~ e) & g);
}
ak_uint64 sha512_ma(ak_uint64 a, ak_uint64 b, ak_uint64 c){
    return (a & b) ^ (a & c) ^ (b & c);
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha512_block( struct sha512 *ctx )
{

    for (int i = 0; i < 80; ++i) {
        ak_uint64 t1 = ctx->A[7]+ sha512_sigma1(ctx->A[4])
                + sha512_ch(ctx->A[4], ctx->A[5], ctx->A[6]) + sha512_c[i] + ctx->words[i];
        ak_uint64 t2 = sha512_sigma0(ctx->A[0]) + sha512_ma(ctx->A[0], ctx->A[1], ctx->A[2]);

        ctx->A[7] = ctx->A[6];
        ctx->A[6] = ctx->A[5];
        ctx->A[5] = ctx->A[4];
        ctx->A[4] = ctx->A[3] + t1;
        ctx->A[3] = ctx->A[2];
        ctx->A[2] = ctx->A[1];
        ctx->A[1] = ctx->A[0];
        ctx->A[0] = t1 + t2;
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha512_finish_block( struct sha512 *ctx)
{
    for (int i = 0; i < 8; ++ i) {
        ctx->H[i] += ctx->A[i];
    }
    ctx->current_block += 64;
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha512_endian_change( struct sha512 *ctx)
{
    for (int i = 0; i < 8; ++ i) {
        ak_uint64 h = ctx->H[i];
        ((ak_uint8 *) &ctx->H[i])[0] = ((ak_uint8 *) &h)[7];
        ((ak_uint8 *) &ctx->H[i])[1] = ((ak_uint8 *) &h)[6];
        ((ak_uint8 *) &ctx->H[i])[2] = ((ak_uint8 *) &h)[5];
        ((ak_uint8 *) &ctx->H[i])[3] = ((ak_uint8 *) &h)[4];
        ((ak_uint8 *) &ctx->H[i])[4] = ((ak_uint8 *) &h)[3];
        ((ak_uint8 *) &ctx->H[i])[5] = ((ak_uint8 *) &h)[2];
        ((ak_uint8 *) &ctx->H[i])[6] = ((ak_uint8 *) &h)[1];
        ((ak_uint8 *) &ctx->H[i])[7] = ((ak_uint8 *) &h)[0];
    }
    ctx->current_block += 128;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha512_clean( ak_pointer ctx )
{
    struct sha512 *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );

    sx = ( struct sha512 * ) (( ak_hash ) ctx )->data;
    sx->current_block = NULL;
    memset( sx->A, 0, 64 );
    memcpy( sx->H, sha512_hash, 64 );
    memset( sx->words, 0, 640 );
    sx->length = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha384_clean( ak_pointer ctx )
{
    struct sha512 *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );

    sx = ( struct sha512 * ) (( ak_hash ) ctx )->data;
    sx->current_block = NULL;
    memset( sx->A, 0, 64 );
    memcpy( sx->H, sha384_hash, 64 );
    memset( sx->words, 0, 640 );
    sx->length = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha512_256_clean( ak_pointer ctx )
{
    struct sha512 *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );

    sx = ( struct sha512 * ) (( ak_hash ) ctx )->data;
    sx->current_block = NULL;
    memset( sx->A, 0, 64 );
    memcpy( sx->H, sha512_256_hash, 64 );
    memset( sx->words, 0, 640 );
    sx->length = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha512_224_clean( ak_pointer ctx )
{
    struct sha512 *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );

    sx = ( struct sha512 * ) (( ak_hash ) ctx )->data;
    sx->current_block = NULL;
    memset( sx->A, 0, 64 );
    memcpy( sx->H, sha512_224_hash, 64 );
    memset( sx->words, 0, 640 );
    sx->length = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Основное циклическое преобразование (Этап 2)                                                   */
static int ak_hash_sha512_update( ak_pointer ctx, const ak_pointer in, const size_t size )
{
    ak_uint64 quot = 0;
    struct sha512 *sx = NULL;

    if( ctx == NULL ) return  ak_error_message( ak_error_null_pointer,
                                                __func__ , "using null pointer to a context" );
    if( !size ) return ak_error_message( ak_error_zero_length,
                                         __func__ , "using zero length for hash data" );
    quot = size/(( ak_hash ) ctx )->bsize;
    if( size - quot*(( ak_hash ) ctx )->bsize ) /* длина данных должна быть кратна ctx->bsize */
        return ak_error_message( ak_error_wrong_length, __func__ , "using data with wrong length" );

    sx = ( struct sha512 * ) (( ak_hash ) ctx )->data;
    sx->current_block = in;
    do{
        sha512_prepare(sx);
        sha512_block(sx);
        sha512_finish_block(sx);
        quot--;
    } while( quot > 0 );
    ++(sx->length);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
static ak_buffer ak_hash_sha512_finalize( ak_pointer ctx, const ak_pointer in,
                                          const size_t size, ak_pointer out )
{
    ak_uint64 m[16];
    ak_buffer result = NULL;
    ak_uint8 *block1 = ( ak_uint8 * )m;
    ak_uint8 *block2 = block1;
    struct sha512 *sx = NULL;

    if( ctx == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
        return NULL;
    }
    if( size >= 128 ) {
        ak_error_message( ak_error_zero_length, __func__ ,
                          "using wrong length for finalized hash data" );
        return NULL;
    }
    sx = ( struct sha512 * ) (( ak_hash ) ctx )->data;

    memset(block1, 0, 128);
    if (in != NULL)
        memcpy(block1, in, (ak_uint64) size); // здесь приведение типов корректно, поскольку 0 <= size < 128
    block1[(ak_uint64) size] = 128; /* дополнение */

    if (size <= 119) {

    } else /*if (size <= 128) */ {
        block2 = malloc(128);
        memset(block2, 0, 128);
    }

    ak_uint64 length = 8 * (sx->length * 128 + (ak_uint64) size);
    block2[127] = ((ak_uint8 *) &length)[0];
    block2[126] = ((ak_uint8 *) &length)[1];
    block2[125] = ((ak_uint8 *) &length)[2];
    block2[124] = ((ak_uint8 *) &length)[3];
    block2[123] = ((ak_uint8 *) &length)[4];
    block2[122] = ((ak_uint8 *) &length)[5];
    block2[121] = ((ak_uint8 *) &length)[6];
    block2[120] = ((ak_uint8 *) &length)[7];

//    printf("current stroka\n");
//    for (int i = 0; i < 64; ++i) {
//        printf("%08x ", block1[i]);
//    }
//    printf("\n");

    sx->current_block = block1;
    sha512_prepare(sx);
    sha512_block(sx);
    sha512_finish_block(sx);
    if (size <= 119){

    } else {
        sx->current_block = block2;
        sha512_prepare(sx);
        sha512_block(sx);
        sha512_finish_block(sx);
        free(block2);
    }

    sha512_endian_change(sx);
    if( out != NULL ) {
        memcpy(out, sx->H, ((ak_hash) ctx)->hsize);
        return NULL;
    } else {
        if ((result = ak_buffer_new_size(((ak_hash) ctx)->hsize)) != NULL) {
            memcpy( result->data, sx->H, ((ak_hash) ctx)->hsize );
            return  result;
        }else ak_error_message( ak_error_get_value( ), __func__ ,
                                "wrong creation of result buffer" );
    }

    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования с длиной хэшкода,
    равной 512 бит (функция SHA-512).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha512( ak_hash ctx )
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_create( ctx, sizeof( struct sha512 ), 128 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha512 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 64; /* длина хешкода составляет 512 бит */
    if(( ctx->oid = ak_oid_find_by_name( "sha512" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean = ak_hash_sha512_clean;
    ctx->update = ak_hash_sha512_update;
    ctx->finalize = ak_hash_sha512_finalize;

    /* инициализируем память */
    ak_hash_sha512_clean( ctx );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования с длиной хэшкода,
    равной 384 бит (функция SHA-384).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha384( ak_hash ctx )
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_create( ctx, sizeof( struct sha512 ), 128 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha512 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 48; /* длина хешкода составляет 384 бит */
    if(( ctx->oid = ak_oid_find_by_name( "sha384" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean = ak_hash_sha384_clean;
    ctx->update = ak_hash_sha512_update;
    ctx->finalize = ak_hash_sha512_finalize;

    /* инициализируем память */
    ak_hash_sha384_clean( ctx );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования с длиной хэшкода,
    равной 256 бит (функция SHA-512/256).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha512_256( ak_hash ctx )
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_create( ctx, sizeof( struct sha512 ), 128 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha512 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 32; /* длина хешкода составляет 256 бит */
    if(( ctx->oid = ak_oid_find_by_name( "sha512_256" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean = ak_hash_sha512_256_clean;
    ctx->update = ak_hash_sha512_update;
    ctx->finalize = ak_hash_sha512_finalize;

    /* инициализируем память */
    ak_hash_sha512_256_clean( ctx );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования с длиной хэшкода,
    равной 224 бит (функция SHA-512/224).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha512_224( ak_hash ctx )
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_create( ctx, sizeof( struct sha512 ), 128 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha512 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 28; /* длина хешкода составляет 224 бит */
    if(( ctx->oid = ak_oid_find_by_name( "sha512" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean = ak_hash_sha512_224_clean;
    ctx->update = ak_hash_sha512_update;
    ctx->finalize = ak_hash_sha512_finalize;

    /* инициализируем память */
    ak_hash_sha512_224_clean( ctx );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! первое тестовое сообщение */
static ak_uint8 sha_M1_message[] = "abc";

/*! второе тестовое сообщение */
static ak_uint8 sha_M2_message[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

static ak_uint8 sha384_testM1[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
};

static ak_uint8 sha512_testM1[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};
static ak_uint8 sha512_256_testM1[32] = {
        0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab,
        0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46, 0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23
};

static ak_uint8 sha512_224_testM1[28] = {
        0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54, 0xda, 0xae, 0x75, 0x30, 0x46, 0x08, 0x42, 0xe2,
        0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4, 0x3e, 0x89, 0x24, 0xaa
};
static ak_uint8 sha384_testM2[48] = {
        0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39, 0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39,
        0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab, 0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6,
        0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f, 0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b,
};

static ak_uint8 sha512_testM2[64] = {
        0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
        0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
        0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
        0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45
};
static ak_uint8 sha512_256_testM2[32] = {
        0xbd, 0xe8, 0xe1, 0xf9, 0xf1, 0x9b, 0xb9, 0xfd, 0x34, 0x06, 0xc9, 0x0e, 0xc6, 0xbc, 0x47, 0xbd,
        0x36, 0xd8, 0xad, 0xa9, 0xf1, 0x18, 0x80, 0xdb, 0xc8, 0xa2, 0x2a, 0x70, 0x78, 0xb6, 0xa4, 0x61
};

static ak_uint8 sha512_224_testM2[28] = {
        0xe5, 0x30, 0x2d, 0x6d, 0x54, 0xbb, 0x24, 0x22, 0x75, 0xd1, 0xe7, 0x62, 0x2d, 0x68, 0xdf, 0x6e,
        0xb0, 0x2d, 0xed, 0xd1, 0x3f, 0x56, 0x4c, 0x13, 0xdb, 0xda, 0x21, 0x74
};
/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_hash_test_sha384( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[48]; /* буффер длиной 48 байта (384 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    ak_bool result = ak_true;
    int audit = ak_log_get_level();

    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha384( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong initialization of sha384 context" );
        return ak_false;
    }

    /* первый пример */
    ak_hash_context_ptr( &ctx, sha_M1_message, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha384_testM1, out, 48 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 1st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 1st test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 48, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha384_testM1, 48, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* второй пример */
    ak_hash_context_ptr( &ctx, sha_M2_message, 56, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha384_testM2, out, 48 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2nd test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ , "the 2nd test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 48, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha384_testM2, 48, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_hash_test_sha512( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[64]; /* буффер длиной 64 байта (512 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    ak_bool result = ak_true;
    int audit = ak_log_get_level();

    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha512( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong initialization of sha512 context" );
        return ak_false;
    }

    /* первый пример */
    ak_hash_context_ptr( &ctx, sha_M1_message, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha512 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha512_testM1, out, 64 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 1st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 1st test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha384_testM1, 64, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* второй пример */
    ak_hash_context_ptr( &ctx, sha_M2_message, 56, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha512_testM2, out, 48 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2nd test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ , "the 2nd test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 48, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha384_testM2, 48, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_hash_test_sha512_256( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[32]; /* буффер длиной 32 байта (256 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    ak_bool result = ak_true;
    int audit = ak_log_get_level();

    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha512_256( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong initialization of sha512_256 context" );
        return ak_false;
    }

    /* первый пример */
    ak_hash_context_ptr( &ctx, sha_M1_message, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha512_256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha512_256_testM1, out, 32 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 1st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 1st test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha512_256_testM1, 32, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* второй пример */
    ak_hash_context_ptr( &ctx, sha_M2_message, 56, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha512_256_testM2, out,  32)) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2nd test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ , "the 2nd test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha512_256_testM2, 32, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_hash_test_sha512_224( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[28]; /* буффер длиной 28 байта (224 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    ak_bool result = ak_true;
    int audit = ak_log_get_level();

    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha512_224( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong initialization of sha512_224 context" );
        return ak_false;
    }

    /* первый пример */
    ak_hash_context_ptr( &ctx, sha_M1_message, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha512_224 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha512_224_testM1, out, 28 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 1st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 1st test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 28, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha512_224_testM1, 28, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* второй пример */
    ak_hash_context_ptr( &ctx, sha_M2_message, 56, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha384 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha512_224_testM2, out, 28 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2nd test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ , "the 2nd test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 28, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha384_testM2, 28, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
