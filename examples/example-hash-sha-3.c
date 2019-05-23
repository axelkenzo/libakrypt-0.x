#include <stdlib.h>
#include <stdio.h>
#include <libakrypt.h>


int main( void )
{
    /* вывод порядка байт */
    unsigned int test_char = 1;
    char *c = (char*)&test_char;
    if (*c)
        printf("You work under litte endian\n");
    else
        printf("You work under big endian\n");
    char *str = NULL;
    /* определяем дескриптор и инициализируем его */
    ak_handle handle = ak_error_wrong_handle;

    /* определяем данные для хэширования */
    ak_uint8 data[113] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    /* буффер для хранения результата */
    ak_buffer buffer = NULL;
    /* значение, которое должно быть вычислено */
    ak_uint8 test[28] =
            {
                    0x54,0x3e,0x68,0x68,0xe1,0x66,0x6c,0x1a,0x64,0x36,0x30,0xdf,0x77,0x36,0x7a,
                    0xe5,0xa6,0x2a,0x85,0x07,0x0a,0x51,0xc1,0x4c,0xbf,0x66,0x5c,0xbc
            };
    ak_uint8 test256[32] =
            {
                    0x91,0x6f,0x60,0x61,0xfe,0x87,0x97,0x41,0xca,0x64,0x69,0xb4,0x39,0x71,0xdf,0xdb,0x28,0xb1,0xa3,0x2d,
                    0xc3, 0x6c,0xb3,0x25,0x4e,0x81,0x2b,0xe2,0x7a,0xad,0x1d,0x18
            };

    ak_uint8 test384[48] =
            {
                    0x79,0x40,0x7d,0x3b,0x59,0x16,0xb5,0x9c,0x3e,0x30,0xb0,0x98,0x22,0x97,0x47,0x91,0xc3,0x13,0xfb,0x9e,
                    0xcc,0x84,0x9e,0x40,0x6f,0x23,0x59,0x2d,0x04,0xf6,0x25,0xdc,0x8c,0x70,0x9b,0x98,0xb4,0x3b,0x38,0x52,
                    0xb3,0x37,0x21,0x61,0x79,0xaa,0x7f,0xc7
            };
    ak_uint8 test512[64]=
    {
                    0xaf,0xeb,0xb2,0xef,0x54,0x2e,0x65,0x79,0xc5,0x0c,0xad,0x06,0xd2,0xe5,0x78,0xf9,0xf8,0xdd,0x68,
                    0x81,0xd7,0xdc,0x82,0x4d,0x26,0x36,0x0f,0xee,0xbf,0x18,0xa4,0xfa,0x73,0xe3,0x26,0x11,0x22,0x94,0x8e,
                    0xfc,0xfd,0x49,0x2e,0x74,0xe8,0x2e,0x21,0x89,0xed,0x0f,0xb4,0x40,0xd1,0x87,0xf3,0x82,0x27,0x0c,0xb4,
                    0x55,0xf2,0x1d,0xd1,0x85
            };
    ak_uint8 test128shake[32]=
            {
                    0x7b,0x6d,0xf6,0xff,0x18,0x11,0x73,0xb6,0xd7,0x89,0x8d,0x7f,0xf6,0x3f,0xb0,0x7b,0x7c,0x23,0x7d,0xaf,
                    0x47,0x1a,0x5a,0xe5,0x60,0x2a,0xdb,0xcc,0xef,0x9c,0xcf,0x4b
            };
    ak_uint8 test256shake[64]=
            {
                    0x98,0xbe,0x04,0x51,0x6c,0x04,0xcc,0x73,0x59,0x3f,0xef,0x3e,0xd0,0x35,0x2e,0xa9,0xf6,0x44,0x39,
                    0x42,0xd6,0x95,0x0e,0x29,0xa3,0x72,0xa6,0x81,0xc3,0xde,0xaf,0x45,0x35,0x42,0x37,0x09,0xb0,0x28,0x43,
                    0x94,0x86,0x84,0xe0,0x29,0x01,0x0b,0xad,0xcc,0x0a,0xcd,0x83,0x03,0xfc,0x85,0xfd,0xad,0x3e,0xab,0xf4,
                    0xf7,0x8c,0xae,0x16,0x56
            };

    /* инициализируем библиотеку */
    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
        return ak_libakrypt_destroy();

    /* создаем дескриптор функции хеширования sha3-224 */
    if(( handle = ak_hash_new_sha3_224(NULL)) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    printf("data: %s\n", data );

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }


    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash224: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer,ak_false ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash224: %s (expected)\n\n", str = ak_ptr_to_hexstr( test, sizeof( test ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования sha3-256 */
    if(( handle = ak_hash_new_sha3_256(NULL)) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash256: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer,ak_false ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);
    /* вывод заранее подсчитанной константы */
    printf("hash256: %s (expected)\n\n", str = ak_ptr_to_hexstr( test256, sizeof( test256 ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования sha3-384 */
    if(( handle = ak_hash_new_sha3_384(NULL)) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash384: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer,ak_false ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash384: %s (expected)\n\n", str = ak_ptr_to_hexstr( test384, sizeof( test384 ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования sha3-512 */
    if(( handle= ak_hash_new_sha3_512(NULL)) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash512: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer,ak_false ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash512: %s (expected)\n\n", str = ak_ptr_to_hexstr( test512, sizeof( test512 ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования shake128 */
    if(( handle= ak_hash_new_shake128(NULL)) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes", (int) ak_hash_get_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("\nobtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash_shake128: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer,ak_false ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash_shake128: %s (expected)\n\n", str = ak_ptr_to_hexstr( test128shake, sizeof( test128shake ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования shake256 */
    if(( handle= ak_hash_new_shake256(NULL)) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes", (int) ak_hash_get_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("\nobtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash_shake256: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer,ak_false ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash_shake256: %s (expected)\n\n", str = ak_ptr_to_hexstr( test256shake, sizeof( test256shake ), ak_false ));
    free(str);

    return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
