#include <libakrypt.h>
#include <ak_skey.h>

int main( void )
{
    /* Инициализируем библиотеку */
    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
        return ak_libakrypt_destroy();

    /* Тестовая функция RC6 */
    ak_bckey_test_rc6();

    /* Пример работы шифра RC6*/
    return ak_libakrypt_destroy();
}
