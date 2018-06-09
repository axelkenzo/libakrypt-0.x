 #include <time.h>
 #include <stdio.h>
 #include <sys/types.h>
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
 } else printf(" found file for testing with %dMB size\n", (int) mbsize );
 fclose(fp);
 printf("\n");

 /* ключ */
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
 printf(" magma time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );
 ak_bckey_destroy( &key );
  
 /* ключ */
 ak_bckey_create_masked_magma( &key );
 ak_bckey_context_set_password( &key, "password", 8, "12345", 5 );

 fp = fopen( "data.dat", "rb" );
 fq = fopen( "data.dat.enc.magma.masked", "wb" );

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
 printf(" masked magma time: %fs, per 1MB = %fs, %f MBs\n\n",
         (double) time / (double) CLOCKS_PER_SEC,
         (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );
  
 fclose( fp );
 fclose( fq );
 ak_bckey_destroy( &key );

 /* ключ II*/
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
 printf(" kuznechik time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );

 ak_uint32 buf[256];
 ak_uint8 out[16];
 int i, j, n;

    for (i = 0; i < 256; i++) buf[i] = i;
    for (n = 100, time = 0; time < 2 * CLOCKS_PER_SEC; n <<= 1) {
        time = clock();
        for (j = 0; j < n; j++) {
            for (i = 0; i < 0x100; i += 4) key.encrypt( &key.key, &buf[i], out);
        }
        time = clock() - time;
        printf(" %s(): %.3f MBs (n=%dkB, t=%.3fs)\r", "str",
            ((double) CLOCKS_PER_SEC * n) / (1024*((double) time)),
            n, ((double) time) / ((double) CLOCKS_PER_SEC));
        fflush(stdout);
    }
    printf("\n");




 ak_bckey_destroy( &key );

 return ak_libakrypt_destroy();
}

