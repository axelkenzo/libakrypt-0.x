#include <libakrypt.h>

int main()
{

  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();
  ak_handle handle; /* дескриптор генератора */
  ak_buffer buffer = NULL; /* буффер для хранения случайных значений */

  /* создаем генератор */
  if(( handle = ak_random_new_tc26("streebog512")) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();

  /* вырабатываем случайные данные и выводим их в консоль */
  if(( buffer = ak_random_buffer( handle, 256 )) != NULL ) {
    char *str = ak_buffer_to_hexstr( buffer );
    printf("random data (%d bytes):\n%s\n",(int) ak_buffer_get_size( buffer),str);
    free( str );
    /* удаляем буффер */
    buffer = ak_buffer_delete( buffer );
  }

  return ak_libakrypt_destroy();
}
