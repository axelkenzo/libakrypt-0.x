/* ----------------------------------------------------------------------------------------------- */
/*   Created by Андрей Зорькин on 20.05.18.                                                        */
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
/*   ak_sha256.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */

#include <ak_parameters.h>
#include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования SHA-256          */
/* ----------------------------------------------------------------------------------------------- */
struct sha256 {
   ak_uint8 *current_block; // указатель на текущий блок
   ak_uint32 words[64]; // 16 + 48
   ak_uint32 A[8]; // для раунда
   ak_uint32 H[8]; // текущий хэш
    ak_uint32 length;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, реализующая циклическое смещение                                               */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint32 rotr(ak_uint32 word, ak_uint32 n) {
    return (word >> n) | (word << (32 - n));
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha256_prepare( struct sha256 *ctx)
{
   ak_uint32 *words = ctx->words;
       for (int z = 0; z < 16; ++z) {
           ((ak_uint8 *) words)[z * 4 + 0] = ctx->current_block[z * 4 + 3];
           ((ak_uint8 *) words)[z * 4 + 1] = ctx->current_block[z * 4 + 2];
           ((ak_uint8 *) words)[z * 4 + 2] = ctx->current_block[z * 4 + 1];
           ((ak_uint8 *) words)[z * 4 + 3] = ctx->current_block[z * 4 + 0];
       }

    for (int i = 16; i < 64; ++i) {
        unsigned int s0 = rotr(words[i-15], 7) ^ rotr(words[i-15], 18) ^ (words[i-15] >> 3);
        unsigned int s1 = rotr(words[i-2], 17) ^ rotr(words[i-2], 19) ^ (words[i-2] >> 10);
        words[i] = words[i-16] + s0 + words[i-7] + s1;
    }
    for (int i = 0; i < 8; ++i) {
       ctx->A[i] = ctx->H[i];
   }
}

ak_uint32 sha256_sigma1(ak_uint32 e){
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
}
ak_uint32  sha256_ch(ak_uint32 e, ak_uint32 f, ak_uint32 g){
    return (e & f) ^ ((~ e) & g);
}
ak_uint32 sha256_sigma0(ak_uint32 a){
    return rotr(a,2) ^ rotr(a, 13) ^ rotr(a, 22);
}
ak_uint32 sha256_ma(ak_uint32 a, ak_uint32 b, ak_uint32 c){
    return (a & b) ^ (a & c) ^ (b & c);
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha256_block( struct sha256 *ctx )
{

    for (int i = 0; i < 64; ++i) {
        ak_uint32 t1 = ctx->A[7] + sha256_sigma1(ctx->A[4]) + sha256_ch(ctx->A[4], ctx->A[5], ctx->A[6]) + sha256_c[i] + ctx->words[i];
        ak_uint32 t2 = sha256_sigma0(ctx->A[0]) + sha256_ma(ctx->A[0], ctx->A[1], ctx->A[2]);

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
static inline void sha256_finish_block( struct sha256 *ctx)
{
    for (int i = 0; i < 8; ++ i) {
        ctx->H[i] += ctx->A[i];
    }
    ctx->current_block += 64;
}

/* ----------------------------------------------------------------------------------------------- */
/*!                                                                                                */
/* ----------------------------------------------------------------------------------------------- */
static inline void sha256_endian_change( struct sha256 *ctx)
{
    for (int i = 0; i < 8; ++ i) {
        ak_uint32 h = ctx->H[i];
        ((ak_uint8 *) &ctx->H[i])[0] = ((ak_uint8 *) &h)[3];
        ((ak_uint8 *) &ctx->H[i])[1] = ((ak_uint8 *) &h)[2];
        ((ak_uint8 *) &ctx->H[i])[2] = ((ak_uint8 *) &h)[1];
        ((ak_uint8 *) &ctx->H[i])[3] = ((ak_uint8 *) &h)[0];
    }
    ctx->current_block += 64;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha224_clean( ak_pointer ctx )
{
    struct sha256 *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );

    sx = ( struct sha256 * ) (( ak_hash ) ctx )->data;
    sx->current_block = NULL;
    memset( sx->A, 0, 32 );
    memcpy( sx->H, sha224_hash, 32 );
    memset( sx->words, 0, 256 );
    sx->length = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
static int ak_hash_sha256_clean( ak_pointer ctx )
{
    struct sha256 *sx = NULL;
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using null pointer to a context" );

    sx = ( struct sha256 * ) (( ak_hash ) ctx )->data;
    sx->current_block = NULL;
    memset( sx->A, 0, 32 );
    memcpy( sx->H, sha256_hash, 32 );
    memset( sx->words, 0, 256 );
    sx->length = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Основное циклическое преобразование (Этап 2)                                                   */
static int ak_hash_sha256_update( ak_pointer ctx, const ak_pointer in, const size_t size )
{
    ak_uint64 quot = 0;
    struct sha256 *sx = NULL;

    if( ctx == NULL ) return  ak_error_message( ak_error_null_pointer,
                                                __func__ , "using null pointer to a context" );
    if( !size ) return ak_error_message( ak_error_zero_length,
                                         __func__ , "using zero length for hash data" );
    quot = size/(( ak_hash ) ctx )->bsize;
    if( size - quot*(( ak_hash ) ctx )->bsize ) /* длина данных должна быть кратна ctx->bsize */
        return ak_error_message( ak_error_wrong_length, __func__ , "using data with wrong length" );

    sx = ( struct sha256 * ) (( ak_hash ) ctx )->data;
    sx->current_block = in;
    do{
        sha256_prepare(sx);
        sha256_block(sx);
        sha256_finish_block(sx);
        quot--;
    } while( quot > 0 );
    ++(sx->length);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
static ak_buffer ak_hash_sha256_finalize( ak_pointer ctx, const ak_pointer in,
                                            const size_t size, ak_pointer out )
{
    ak_uint64 m[8];
    ak_buffer result = NULL;
    ak_uint8 *block1 = ( ak_uint8 * )m;
    ak_uint8 *block2 = block1;
    struct sha256 *sx = NULL;

    if( ctx == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
        return NULL;
    }
    if( size >= 64 ) {
        ak_error_message( ak_error_zero_length, __func__ ,
                          "using wrong length for finalized hash data" );
        return NULL;
    }
    sx = ( struct sha256 * ) (( ak_hash ) ctx )->data;

    memset(block1, 0, 64);
    if (in != NULL)
        memcpy(block1, in, (ak_uint32) size); // здесь приведение типов корректно, поскольку 0 <= size < 64
    block1[(ak_uint32) size] = 128; /* дополнение */

    if (size <= 55) {

    } else /*if (size <= 63) */ {
        block2 = malloc(64);
        memset(block2, 0, 64);
    }

    ak_uint64 length = 8 * (sx->length * 64 + (ak_uint64) size);
    block2[63] = ((ak_uint8 *) &length)[0];
    block2[62] = ((ak_uint8 *) &length)[1];
    block2[61] = ((ak_uint8 *) &length)[2];
    block2[60] = ((ak_uint8 *) &length)[3];
    block2[59] = ((ak_uint8 *) &length)[4];
    block2[58] = ((ak_uint8 *) &length)[5];
    block2[57] = ((ak_uint8 *) &length)[6];
    block2[56] = ((ak_uint8 *) &length)[7];

//    printf("current stroka\n");
//    for (int i = 0; i < 64; ++i) {
//        printf("%08x ", block1[i]);
//    }
//    printf("\n");

    sx->current_block = block1;
    sha256_prepare(sx);
    sha256_block(sx);
    sha256_finish_block(sx);
    if (size <= 55){

    } else {
        sx->current_block = block2;
        sha256_prepare(sx);
        sha256_block(sx);
        sha256_finish_block(sx);
        free(block2);
    }

    sha256_endian_change(sx);
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
    равной 256 бит (функция SHA-256).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha256( ak_hash ctx )
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_create( ctx, sizeof( struct sha256 ), 64 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha256 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 32; /* длина хешкода составляет 256 бит */
    if(( ctx->oid = ak_oid_find_by_name( "sha256" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean = ak_hash_sha256_clean;
    ctx->update = ak_hash_sha256_update;
    ctx->finalize = ak_hash_sha256_finalize;

    /* инициализируем память */
    ak_hash_sha256_clean( ctx );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования с длиной хэшкода,
    равной 224 бит (функция SHA-224).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_hash_create_sha224( ak_hash ctx )
{
    int error = ak_error_ok;

    /* выполняем проверку */
    if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to hash context" );
    /* инициализируем контекст */
    if(( error = ak_hash_create( ctx, sizeof( struct sha256 ), 64 )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect sha256 context creation" );

    /* устанавливаем размер хешхода и OID алгоритма хеширования */
    ctx->hsize = 28; /* длина хешкода составляет 256 бит */
    if(( ctx->oid = ak_oid_find_by_name( "sha256" )) == NULL )
        return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

    /* устанавливаем функции - обработчики событий */
    ctx->clean = ak_hash_sha224_clean;
    ctx->update = ak_hash_sha256_update;
    ctx->finalize = ak_hash_sha256_finalize;

    /* инициализируем память */
    ak_hash_sha224_clean( ctx );
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! первое тестовое сообщение */
static ak_uint8 sha_M1_message[] = "abc";

/*! второе тестовое сообщение */
static ak_uint8 sha_M2_message[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

static ak_uint8 sha256_testM1[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static ak_uint8 sha256_testM2[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

static ak_uint8 sha224_testM1[28] = {
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
        0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7
};

static ak_uint8 sha224_testM2[28] = {
        0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01, 0x50,
        0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25
};
/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_hash_test_sha256( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[32]; /* буффер длиной 32 байта (256 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    ak_bool result = ak_true;
    int audit = ak_log_get_level();

    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha256( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong initialization of sha256 context" );
        return ak_false;
    }

    /* первый пример */
    ak_hash_context_ptr( &ctx, sha_M1_message, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha256_testM1, out, 32 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 1st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 1st test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha256_testM1, 32, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* второй пример */
    ak_hash_context_ptr( &ctx, sha_M2_message, 56, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha256_testM2, out, 32 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2nd test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ , "the 2nd test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha256_testM2, 32, ak_false ))); free( str );
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
ak_bool ak_hash_test_sha224( void )
{
    struct hash ctx; /* контекст функции хеширования */
    ak_uint8 out[28]; /* буффер длиной 28 байта (224 бит) для получения результата */
    char *str = NULL;
    int error = ak_error_ok;
    ak_bool result = ak_true;
    int audit = ak_log_get_level();

    /* инициализируем контекст функции хешиирования */
    if(( error = ak_hash_create_sha224( &ctx )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "wrong initialization of sha256 context" );
        return ak_false;
    }

    /* первый пример */
    ak_hash_context_ptr( &ctx, sha_M1_message, 3, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha224_testM1, out, 28 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 1st test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ ,
                          "the 1st test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 28, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha256_testM1, 28, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* второй пример */
    ak_hash_context_ptr( &ctx, sha_M2_message, 56, out );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of sha256 code" );
        result = ak_false;
        goto lab_exit;
    }

    if( ak_ptr_is_equal( sha224_testM2, out, 28 )) {
        if( audit >= ak_log_maximum )
            ak_error_message( ak_error_ok, __func__ , "the 2nd test is Ok" );
    } else {
        ak_error_message( ak_error_not_equal_data, __func__ , "the 2nd test is wrong" );
        ak_log_set_message(( str = ak_ptr_to_hexstr( out, 28, ak_false ))); free( str );
        ak_log_set_message(( str = ak_ptr_to_hexstr( sha224_testM2, 28, ak_false ))); free( str );
        result = ak_false;
        goto lab_exit;
    }

    /* уничтожаем контекст */
    lab_exit: ak_hash_destroy( &ctx );
    return result;
}

/* ----------------------------------------------------------------------------------------------- */
