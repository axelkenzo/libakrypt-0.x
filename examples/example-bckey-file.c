/* ----------------------------------------------------------------------------------------------- *
   Пример иллюстрирует выполнение алгоритмов блочного шифрования Магма и Кузнечик в режиме
   гаммирования из ГОСТ Р 34.13-2015 и в режиме CTR-ACPKM.
   Внимание: используются неэкспортируемые функции.                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 #include <ak_bckey.h>

 int main( void )
{
 size_t idx = 0, mbsize = 200;
 FILE *fp = NULL, *fq = NULL;
 clock_t time = 0;
 struct bckey key;
 int len = 0;
 ak_uint8 buffer[1024];

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

 /* Алгоритм Магма, режим гаммирования */
 printf("Magma\n");
 ak_bckey_create_magma( &key );
 ak_bckey_context_set_password( &key, "password", 8, "12345", 5 );

 fp = fopen( "data.dat", "rb" );
 fq = fopen( "data.dat.enc.magma", "wb" );

 time = clock();
 len = fread( buffer, 1, 1024, fp );
 if( len > 0 ) {
   ak_bckey_context_xcrypt( &key, buffer, buffer, len, "12345678", 8 );
   fwrite( buffer, 1, len, fq );
 }
 do{
    if(( len = fread( buffer, 1, 1024, fp )) > 0 ) {
      ak_bckey_context_xcrypt_update( &key, buffer, buffer, len );
      fwrite( buffer, 1, len, fq );
    }
 } while( len );
 time = clock() - time;
 printf(" time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );
 ak_bckey_destroy( &key );

 /* Алгоритм Кузнечик, режим гаммирования */
 printf("Kuznechik\n");
 ak_bckey_create_kuznechik( &key );
 ak_bckey_context_set_password( &key, "password", 8, "12345", 5 );

 fp = fopen( "data.dat", "rb" );
 fq = fopen( "data.dat.enc.kuznechik", "wb" );

 time = clock();
 len = fread( buffer, 1, 1024, fp );
 if( len > 0 ) {
   ak_bckey_context_xcrypt( &key, buffer, buffer, len, "12345678", 8 );
   fwrite( buffer, 1, len, fq );
 }

 do{
    if(( len = fread( buffer, 1, 1024, fp )) > 0 ) {
      ak_bckey_context_xcrypt_update( &key, buffer, buffer, len );
      fwrite( buffer, 1, len, fq );
    }
 } while( len );
 time = clock() - time;
 printf(" time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );
 ak_bckey_destroy( &key );

 /* Алгоритм Магма, режим CTR-ACPKM */
 printf("Magma CTR-ACPKM mode\n");
 ak_bckey_create_magma( &key );
 ak_bckey_context_set_password( &key, "password", 8, "12345", 5 );

 fp = fopen( "data.dat", "rb" );
 fq = fopen( "data.dat.enc.magma.ctr.acpkm", "wb" );

 time = clock();
 len = fread( buffer, 1, 1024, fp );
 if( len > 0 ) {
   ak_bckey_context_xcrypt_acpkm( &key, buffer, buffer, len, "12345678", 8, 1024 );
   fwrite( buffer, 1, len, fq );
 }
 do{
    if(( len = fread( buffer, 1, 1024, fp )) > 0 ) {
      ak_bckey_context_xcrypt_acpkm_update( &key, buffer, buffer, len );
      fwrite( buffer, 1, len, fq );
    }
 } while( len );
 time = clock() - time;
 printf(" time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );
 ak_bckey_destroy( &key );

 /* Алгоритм Кузнечик, режим CTR-ACPKM */
 printf("Kuznechik CTR-ACPKM mode\n");
 ak_bckey_create_kuznechik( &key );
 ak_bckey_context_set_password( &key, "password", 8, "12345", 5 );

 fp = fopen( "data.dat", "rb" );
 fq = fopen( "data.dat.enc.kuznechik.ctr.acpkm", "wb" );

 time = clock();
 len = fread( buffer, 1, 1024, fp );
 if( len > 0 ) {
   ak_bckey_context_xcrypt_acpkm( &key, buffer, buffer, len, "12345678", 8, 4096 );
   fwrite( buffer, 1, len, fq );
 }
 do{
    if(( len = fread( buffer, 1, 1024, fp )) > 0 ) {
      ak_bckey_context_xcrypt_acpkm_update( &key, buffer, buffer, len );
      fwrite( buffer, 1, len, fq );
    }
 } while( len );
 time = clock() - time;
 printf(" time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );
 ak_bckey_destroy( &key );

 return ak_libakrypt_destroy();
}
