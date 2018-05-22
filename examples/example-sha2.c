//
// Created by Андрей Зорькин on 20.05.18.
//

#include <stdio.h>
#include "libakrypt.h"

int main(){

    char *str = NULL;
    /* определяем дескриптор и инициализируем его */
    ak_handle handle = ak_error_wrong_handle;
    /* определяем данные для хэширования */
    ak_uint8 data[] = "abc";

    /* буффер для хранения результата */
    ak_buffer buffer = NULL;
    /* значение, которое должно быть вычислено */
    ak_uint8 lazy[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };

    /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
        return ak_libakrypt_destroy();
    }

    /* создаем дескриптор функции хеширования */
    if(( handle = ak_hash_new_sha256()) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
    free(str);
    buffer = ak_buffer_delete( buffer );

    /* вывод заранее подсчитанной константы */
    printf("hash: %s (expected)\n", str = ak_ptr_to_hexstr( lazy, sizeof( lazy ), ak_false ));
    free(str);

    return ak_libakrypt_destroy();
}

