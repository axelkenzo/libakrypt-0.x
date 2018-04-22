#include <libakrypt.h>

int main ( void ) {
    //ak_handle (ak_int64) - дескриптор произвольного объекта библиотеки
    ak_handle BBShandle;
    ak_buffer randBuffer = NULL;

    //Инициализация библиотеки
    //(ak_function_log_stderr будет использоваться в качестве лога,
    //и эта функция выводит сообщения в стандартный поток для вывода ошибок):
    if ( ak_libakrypt_create(ak_function_log_stderr) != ak_true )
        return ak_libakrypt_destroy();

    //Создание генератора
    if ( (BBShandle = ak_random_new_bbs()) == ak_error_wrong_handle )
        return ak_libakrypt_destroy();

    //Получение буфера со случайными значениями, сгенерированными генератором с дексриптором BBShandle,
    //и вывод его на экран
    if ((randBuffer = ak_random_buffer(BBShandle, 64)) != NULL) {
        char *bufStr = ak_buffer_to_hexstr(randBuffer);
        printf("%d-bytes length random data by BBS:\n%s\n", (int) ak_buffer_get_size(randBuffer), bufStr);

        free( bufStr );
        randBuffer = ak_buffer_delete( randBuffer );
    }

    //Остановка библиотеки (и удаление объектов библиотеки,
    //в том числе и только что созданного генератора)
    return ak_libakrypt_destroy();
}
