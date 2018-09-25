 #include <libakrypt.h>

 int main( void )
{
 int i = 0;
 ak_handle handle; /* дескриптор генератора */
 ak_uint8 buffer[32]; /* буффер для хранения случайных значений */

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем генератор, предоставляющий интерфейс к системному генератору */
#if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
  if(( handle = ak_random_new_dev_random( )) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();
  printf("use a dev-random generator\n");
#endif
#ifdef _WIN32
  if(( handle = ak_random_new_winrtl( )) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();
  printf("use a generator from default (RSA_PROV) Windows crypto provider\n");
#endif
#if !(defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))) && !defined(_WIN32)
  return ak_libakrypt_destroy();
#endif

 /* вырабатываем случайные данные блоками по 32 байта и выводим их в консоль */
  for( i = 0; i < 4; i++ ) {
    printf("generation of block number %d: ", i ); fflush( stdout );
    if( ak_random_ptr( handle, buffer, sizeof( buffer )) == ak_error_ok ) {
      char *str = NULL;

      printf("Ok\n%s\n", str = ak_ptr_to_hexstr( buffer, sizeof( buffer ), ak_false ));
      free( str );

    } else { printf("Wrong\n"); break; }
  }

 /* самостоятельно удаляем дескриптор генератора */
  ak_handle_delete( handle );

 return ak_libakrypt_destroy();
}
