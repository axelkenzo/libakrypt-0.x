/* Тестовый пример иллюстрирует применение режима CBC - простой замены с зацеплением (Кузнечик).
   Внимание! Используются не экспортируемые функции.

   test-bckey04.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>

/*
   инверитрованные тестовые значения взяты из
   https://github.com/gost-engine/engine/blob/master/test_grasshopper.c
*/

 int main( int argc, char *argv[] )
{
  int result = EXIT_FAILURE;

 /* устанавливаем флаг совместимости с openssl: 0 - нет совместимости, 1 - есть */
  int i, j, oc = 0;
  ak_uint8 buf[128], *ptr;
  struct bckey bkey, mkey;

 /* значение секретного ключа согласно ГОСТ Р 34.12-2015 */
  ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
  };

 /* последовательность символов для передачи в командную строку
    8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef */
  ak_uint8 openssl_key[32] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
  };

  ak_uint8 magma_key[32] = { /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.2 */
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
 /* последовательность символов для передачи в командную строку
    ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff */
  ak_uint8 openssl_magma_key[32] = { /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.2 (развернутый) */
     0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
     0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
  };

 /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 in[64] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
  };
  ak_uint8 openssl_in[64] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11
  };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.2 */
  ak_uint8 magma_in[32] = {
     0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
     0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
     0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
     0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
 };

  ak_uint8 openssl_magma_in[32] = {
    0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
    0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
    0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
    0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
 };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivcbc[32] = {
    0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
  };

 /* значение синхропосылки для командной строки:  1234567890abcef0a1b2c3d4e5f00112 */
  ak_uint8 openssl_ivcbc[32] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
    0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
  };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 magma_ivcbc[24] = {
    0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0xf1, 0xde, 0xbc, 0x0a, 0x89, 0x67, 0x45, 0x23,
    0x12, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34
  };

  ak_uint8 openssl_magma_ivcbc[24] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,
    0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12
  };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 outcbc[64] = {
    0x27, 0xcc, 0x7d, 0x6d, 0x3d, 0x2e, 0xe5, 0x90, 0x4d, 0xfa, 0x85, 0xa0, 0xd4, 0x72, 0x99, 0x68,
    0xac, 0xa5, 0x5e, 0x8d, 0x44, 0x8e, 0x1e, 0xaf, 0xa6, 0xec, 0x78, 0xb4, 0x61, 0xe6, 0x26, 0x28,
    0xd0, 0x90, 0x9d, 0xf4, 0xb0, 0xe8, 0x40, 0x56, 0xe8, 0x99, 0x19, 0xe9, 0xf1, 0xab, 0x7b, 0xfe,
    0x70, 0x39, 0xb6, 0x60, 0x15, 0x9a, 0x2d, 0x1a, 0x63, 0x5c, 0x89, 0x5a, 0x06, 0x88, 0x76, 0x16
  };
  ak_uint8 openssl_outcbc[64] = {
    0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
    0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
    0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
    0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70
  };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 magma_outcbc[32] = {
    0x19, 0x39, 0x68, 0xea, 0x5e, 0xb0, 0xd1, 0x96,
    0xb9, 0x37, 0xb9, 0xab, 0x29, 0x61, 0xf7, 0xaf,
    0x19, 0x00, 0xbc, 0xc4, 0xa1, 0xb4, 0x58, 0x50,
    0x67, 0xe6, 0xd7, 0x7c, 0x1a, 0x8b, 0xb7, 0x20
  };
  ak_uint8 openssl_magma_outcbc[32] = {
    0x96, 0xd1, 0xb0, 0x5e, 0xea, 0x68, 0x39, 0x19,
    0xaf, 0xf7, 0x61, 0x29, 0xab, 0xb9, 0x37, 0xb9,
    0x50, 0x58, 0xb4, 0xa1, 0xc4, 0xbc, 0x00, 0x19,
    0x20, 0xb7, 0x8b, 0x1a, 0x7c, 0xd7, 0xe6, 0x67
  };

  FILE *fp = NULL;

 /* сохраняем данные в файл, чтобы можно было потом проверить с помощью библиотеки openssl */
  fp = fopen( "in.dat", "wb" ); fwrite( openssl_in, 64, 1, fp ); fclose( fp );
  fp = fopen( "mag.dat", "wb" ); fwrite( openssl_in, 32, 1, fp ); fclose( fp );


 /* теперь можно проверить эквивалентность шифрования выполнив следующую команду,
    параметры которой указаны в настоящем файле выше

    openssl enc -e -grasshopper-cbc -in in.dat -out in.dat.enc -iv <значение iv> -K <значение ключа>

    в реальности результат будет различен, поскольку openssl реализует режим cbc с обязательным
    дополнением данных
 */

 /* передаем в программу значение флага совместимости */
  if( argc > 1 ) oc = atoi( argv[1] );
  if( oc != 1 ) oc = 0;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* устанавливаем нужный вариант совместимости и пересчитываем внутренние таблицы */
  ak_libakrypt_set_option( "openssl_compability", oc );
  ak_bckey_context_kuznechik_init_gost_tables();
  oc ? printf("openssl_compability is ON\n") : printf("openssl_compability is NO\n");

 /* создаем секретный ключ алгоритма Кузнечик */
  if( ak_bckey_context_create_kuznechik( &bkey ) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_create_magma( &mkey ) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* устанавливаем секретный ключ */
  ak_bckey_context_set_key( &bkey, oc ? openssl_key : key, sizeof( key ));
  ak_bckey_context_set_key( &mkey, oc ? openssl_magma_key : magma_key, sizeof( magma_key ));

 /* Кузнечик */
 printf("kuznechik\n");

 /* зашифровываем и расшифровываем всего четыре блока данных */
  ak_bckey_context_encrypt_cbc( &bkey, oc ? openssl_in : in, buf, sizeof( in ),
                            oc ? openssl_ivcbc : ivcbc, oc ? sizeof(openssl_ivcbc) : sizeof(ivcbc) );
  fp = fopen( "in.dat.encx", "wb" ); fwrite( buf, 64, 1, fp ); fclose( fp );
  printf("encrypted:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 16; j++ ) printf(" %02x", buf[i*16+j] );
    printf("\n");
  }

  ptr = oc ? openssl_outcbc : outcbc;
  printf("\nexpected:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 16; j++ ) printf(" %02x", ptr[i*16+j] );
    printf("\n");
  }

  if( ak_ptr_is_equal( buf, ptr, 64 )) {
    printf("Ok\n\n");
    result = EXIT_SUCCESS;
  }  else printf("Wrong\n\n");

  ak_bckey_context_decrypt_cbc( &bkey, oc ? openssl_outcbc : outcbc, buf, sizeof( in ),
                            oc ? openssl_ivcbc : ivcbc, oc ? sizeof(openssl_ivcbc) : sizeof(ivcbc) );
  printf("decrypted:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 16; j++ ) printf(" %02x", buf[i*16+j] );
    printf("\n");
  }

  ptr = oc ? openssl_in : in;
  printf("\nexpected:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 16; j++ ) printf(" %02x", ptr[i*16+j] );
    printf("\n");
  }

  if( ak_ptr_is_equal( buf, ptr, 64 )) {
    printf("Ok\n\n");
    result = EXIT_SUCCESS;
  }  else printf("Wrong\n\n");

 /* Магма */
 printf("magma\n");

 /* зашифровываем и расшифровываем всего четыре блока данных */
  ak_bckey_context_encrypt_cbc( &mkey, oc ? openssl_magma_in : magma_in, buf, sizeof( magma_in ),
        oc ? openssl_magma_ivcbc : magma_ivcbc, sizeof(magma_ivcbc) );
  fp = fopen( "in.dat.encx", "wb" ); fwrite( buf, 32, 1, fp ); fclose( fp );
  printf("encrypted:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", buf[i*8+j] );
    printf("\n");
  }

  ptr = oc ? openssl_magma_outcbc : magma_outcbc;
  printf("\nexpected:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", ptr[i*8+j] );
    printf("\n");
  }

  if( ak_ptr_is_equal( buf, ptr, 32 )) {
    printf("Ok\n\n");
    result = EXIT_SUCCESS;
  }  else printf("Wrong\n\n");

  ak_bckey_context_decrypt_cbc( &mkey, oc ? openssl_magma_outcbc : magma_outcbc, buf, sizeof( magma_outcbc ),
                oc ? openssl_magma_ivcbc : magma_ivcbc, sizeof(magma_ivcbc) );
  printf("decrypted:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", buf[i*8+j] );
    printf("\n");
  }

  ptr = oc ? openssl_magma_in : magma_in;
  printf("\nexpected:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", ptr[i*8+j] );
    printf("\n");
  }

  if( ak_ptr_is_equal( buf, ptr, 32 )) {
    printf("Ok\n");
    result = EXIT_SUCCESS;
  }  else printf("Wrong\n");


 /* удаляем данные */
  ak_bckey_context_destroy( &bkey );
  ak_bckey_context_destroy( &mkey );
  ak_libakrypt_destroy();

 return result;
}
