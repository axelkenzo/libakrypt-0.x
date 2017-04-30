#include <stdio.h>
#include <libakrypt.h>

int main( void )
{
    /* Инициализируем библиотеку */
    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
        return ak_libakrypt_destroy();

    /* Пример работы шифра RC6*/
    return ak_libakrypt_destroy();
}
