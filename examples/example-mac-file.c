/* ----------------------------------------------------------------------------------------------- *
   Пример иллюстрирует создание вычисление имитовставки от заданного файла при помощи всех
   доступных библиотеке алгоритмов выработки имитовставки.
   Внимание: используются неэкспортируемые функции.                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 #include <ak_mac.h>

 int main( void )
{
 size_t idx = 0, mbsize = 200;
 char *str= NULL;
 FILE *fp = NULL;
 clock_t time = 0;
 ak_oid oid = NULL;
 ak_uint8 out[128]; /* максимальный размер - подпись 2x64 */

 /* 1. Инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* 2. Создаем файл для тестирования */
 fp = fopen( "data.dat", "rb" );
 if( fp == NULL ) {
   ak_uint8 memory[1024];
   printf(" generation a %dMB file, wait a few seconds ... ", (int) mbsize ); fflush(stdout);
   fp = fopen("data.dat", "wb");
   for( idx = 0; idx < mbsize*1024; idx++ ) { // mbsize MB
      memset( memory, (ak_uint8)idx, 1024 );
      fwrite( memory, 1, 1024, fp );
   }
   fflush(fp);
 } else printf(" found file 'data.dat' for testing \n");
 fclose(fp);
 printf("\n");

 /* 3. Прямой поиск: от OID к дескриптору функции хеширования */
 oid = ak_oid_find_by_engine( mac_function );
 while( oid != NULL ) {
   if( oid->mode == algorithm ) {
     struct mac mac;
     ak_mac_create_oid( &mac, oid );
     ak_mac_context_set_password( &mac, "password", 8, "waltz", 5 );
     printf(" name: %s (%s)\n", oid->name, oid->id );

         time = clock();
          ak_mac_context_file( &mac, "data.dat", out );
         time = clock() - time;

      printf(" mac: %s\n time: %fs, per 1MB = %fs\n\n", str = ak_ptr_to_hexstr( out, mac.hsize, ak_false ),
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ));
      free(str);
      ak_mac_destroy( &mac );
   }
   oid = ak_oid_findnext_by_engine( oid, mac_function );
 }

 return ak_libakrypt_destroy();
}
