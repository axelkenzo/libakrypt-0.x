/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_libakrypt.с                                                                            */
/*  - содержит реализацию функций инициализации и тестирования библиотеки.                         */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_PTHREAD
 #include <pthread.h>
#endif
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 #include <emmintrin.h>
#endif
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <windows.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_gf2n.h>
 #include <ak_tools.h>
 #include <ak_curves.h>
#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 #include <ak_mac.h>
 #include <ak_mgm.h>
 #include <ak_sign.h>
 #include <ak_context_manager.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_version( void )
{
#ifdef LIBAKRYPT_VERSION
  return LIBAKRYPT_VERSION;
#else
  return "0.7";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность определения базовых типов данных
    \return В случе успешного тестирования возвращает \ref ak_true (истина).
    В противном случае возвращается ak_false.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_types( void )
{
  union {
    ak_uint8 x[4];
    ak_uint32 z;
  } val;

  if( sizeof( ak_int8 ) != 1 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int8 type" );
    return ak_false;
  }
  if( sizeof( ak_uint8 ) != 1 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint8 type" );
    return ak_false;
  }
  if( sizeof( ak_int32 ) != 4 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int32 type" );
    return ak_false;
  }
  if( sizeof( ak_uint32 ) != 4 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint32 type" );
    return ak_false;
  }
  if( sizeof( ak_int64 ) != 8 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int64 type" );
    return ak_false;
  }
  if( sizeof( ak_uint64 ) != 8 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint64 type" );
    return ak_false;
  }

  if( ak_log_get_level() >= ak_log_maximum ) {
    ak_error_message_fmt( ak_error_ok, __func__, "size of pointer is %d", sizeof( ak_pointer ));

 /* определяем тип платформы: little-endian или big-endian */
  val.x[0] = 0; val.x[1] = 1; val.x[2] = 2; val.x[3] = 3;

   #ifdef LIBAKRYPT_LITTLE_ENDIAN
    if( val.z != 50462976 ) {
      ak_error_message( ak_error_wrong_endian, __func__,
       "incorrect endian: library runs on big endian, but compiled for little endian platform");
      return ak_false;
    } else ak_error_message( ak_error_ok, __func__ , "library runs on little endian platform" );
   #else
    if( val.z != 66051 ) {
      ak_error_message( ak_error_wrong_endian, __func__,
       "incorrect endian: library runs on little endian, but compiled for big endian platform");
      return ak_false;
    } else ak_error_message( ak_error_ok, __func__ , "library runs on big endian platform" );
   #endif

   #ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
    ak_error_message( ak_error_ok, __func__ , "library applies __m128i base type" );
   #endif
   #ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
    ak_error_message( ak_error_ok, __func__ , "library applies clmulepi64 instruction" );
   #endif
   #ifdef LIBAKRYPT_HAVE_BUILTIN_MULQ_GCC
    ak_error_message( ak_error_ok, __func__ , "library applies assembler code for mulq command" );
   #endif
   #ifdef LIBAKRYPT_HAVE_PTHREAD
    ak_error_message( ak_error_ok, __func__ , "library runs with pthreads support" );
   #endif
   #ifdef LIBAKRYPT_HAVE_GMP_H
    ak_error_message( ak_error_ok, __func__ , "library runs with gmp support" );
   #endif
   #ifdef LIBAKRYPT_FIOT
    ak_error_message( ak_error_ok, __func__ , "library includes implementation of fiot protocol" );
   #endif
  }
 return ak_true;
}

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов хэширования
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_hash_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing hash functions started" );

 /* тестируем функцию Стрибог256 */
  if( ak_hash_test_streebog256() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog256 testing" );
    return ak_false;
  }

 /* тестируем функцию Стрибог512 */
  if( ak_hash_test_streebog512() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog512 testing" );
    return ak_false;
  }

  /* тестируем функцию SHA3-224 */
    if( ak_hash_test_sha3_224() != ak_true )
    {
        ak_error_message( ak_error_get_value(), __func__, "incorrect sha3_224 testing" );
        return ak_false;
    }
    /* тестируем функцию SHA3-256 */
    if( ak_hash_test_sha3_256() != ak_true )
    {
        ak_error_message( ak_error_get_value(), __func__, "incorrect sha3_256 testing" );
        return ak_false;
    }
    /* тестируем функцию SHA3-384 */
    if( ak_hash_test_sha3_384() != ak_true )
    {
        ak_error_message( ak_error_get_value(), __func__, "incorrect sha3_384 testing" );
        return ak_false;
    }
    /* тестируем функцию SHA3-512 */
    if( ak_hash_test_sha3_512() != ak_true )
    {
        ak_error_message( ak_error_get_value(), __func__, "incorrect sha3_512 testing" );
        return ak_false;
    }
    /* тестируем функцию SHAKE128 */
    if( ak_hash_test_shake128() != ak_true )
    {
        ak_error_message( ak_error_get_value(), __func__, "incorrect shake128 testing" );
        return ak_false;
    }
    /* тестируем функцию SHAKE256 */
    if( ak_hash_test_shake256() != ak_true )
    {
        ak_error_message( ak_error_get_value(), __func__, "incorrect shake256 testing" );
        return ak_false;
    }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing hash functions ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации блочных шифрова и режимов их использования.
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_block_ciphers( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing block ciphers started" );

 /* тестируем корректность реализации блочного шифра Магма */
  if( ak_bckey_test_magma()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of magma block cipher" );
    return ak_false;
  }

 /* тестируем корректность реализации блочного шифра Кузнечик */
  if( ak_bckey_test_kuznechik()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect testing of kuznechik block cipher" );
    return ak_false;
  }

 /* тестируем дополнительные режимы работы */
  if( ak_bckey_test_mgm()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                               "incorrect testing of mgm mode for block ciphers" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing block ciphers ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов итерационного сжатия
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_mac_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing mac algorithms started" );

 /* тестирование механизмов hmac и pbkdf2 */
  if( ak_hmac_test_streebog() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect testing of hmac functions" );
    return ak_false;
  }
  if( ak_hmac_test_pbkdf2() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect testing of pbkdf2 function" );
    return ak_false;
  }

  /* тестируем механизм итерационного сжатия для ключевых и бесключевых функций хеширования */
  if( ak_mac_test_hash_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__,
                                  "incorrect testing mac algorithms based on hash functions" );
    return ak_false;
  }
  if( ak_mac_test_hmac_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect testing hmac algorithms" );
    return ak_false;
  }

  if( ak_mac_test_omac_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__,
                                   "incorrect testing mac algorithms based on block ciphers" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing mac algorithms ended successfully" );

 return ak_true;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации асимметричных криптографических алгоритмов
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_asymmetric_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing asymmetric mechanisms started" );

 /* тестируем корректность реализации операций с эллиптическими кривыми в короткой форме Вейерштрасса */
  if( ak_wcurve_test() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of Weierstrass curves" );
    return ak_false;
  }

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 /* тестируем корректность реализации алгоритмов электронной подписи */
  if( ak_signkey_test() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of digital signatures" );
    return ak_false;
  }
#endif

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing asymmetric mechanisms ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция проверяет корректность работы всех криптографических механизмов библиотеки
    с использованием как значений, содержащихся в нормативных документах и стандартах,
    так и с использованием случайных значений, вырабатываемых в хде тестирвоания.                  */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_dynamic_control_test( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ , "testing started" );

 /* тестируем арифметические операции в конечных полях */
  if( ak_gfn_multiplication_test() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                          "incorrect testing of multiplication in Galois fields" );
    return ak_false;
  }

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 /* проверяем корректность реализации алгоритмов бесключевого хеширования */
  if( ak_libakrypt_test_hash_functions( ) != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of hash functions" );
    return ak_false;
  }

 /* тестируем работу алгоритмов блочного шифрования */
  if( ak_libakrypt_test_block_ciphers() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "error while testing block ciphers" );
    return ak_false;
  }

 /* проверяем корректность реализации алгоритмов итерационного сжатия */
   if( ak_libakrypt_test_mac_functions( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of mac algorithms" );
     return ak_false;
   }
#endif

 /* тестируем работу алгоритмов выработки и проверки электронной подписи */
  if( ak_libakrypt_test_asymmetric_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                        "error while testing digital signature mechanisms" );
    return ak_false;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ , "testing is Ok" );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна вызываться перед использованием любых криптографических механизмов библиотеки.

   Пример использования функции.

   \code
    int main( void )
   {
     if( ak_libakrypt_create( NULL ) != ak_true ) {
       // инициализация выполнена не успешна => выход из программы
       return ak_libakrypt_destroy();
     }

     // ... здесь код программы ...

    return ak_libakrypt_destroy();
   }
   \endcode

   \param logger Указатель на функцию аудита. Может быть равен NULL.
   \return Функция возвращает \ref ak_true (истина) в случае успешной инициализации и тестирования
   библиотеки. В противном случае, возвращается \ref ak_false. Код ошибки может быть получен
   с помощью вызова функции ak_error_get_value()                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create( ak_function_log *logger )
{
 int error;

 /* в случае, когда компилируются сетевые функции, инициализируем работу с сокетами */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
  #if defined( LIBAKRYPT_FIOT ) || defined( LIBAKRYPT_TLS_13 )
    WSADATA wj;
    WSAStartup( MAKEWORD(2,2), &wj );
  #endif
#endif

 /* перед стартом все должно быть хорошо */
   ak_error_set_value( error = ak_error_ok );

 /* инициализируем систему аудита (вывод сообщений) */
   if(( error = ak_log_set_function( logger )) != ak_error_ok ) {
     ak_error_message( error, __func__ , "audit mechanism not started" );
     return ak_false;
   }

#ifndef LIBAKRYPT_CONST_CRYPTO_PARAMS
 /* считываем настройки криптографических алгоритмов */
   if( ak_libakrypt_load_options() != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ ,
                                        "unsuccessful load options from libakrypt.conf file" );
     return ak_false;
   }
#endif
 /* выводим значения установленных параметров библиотеки */
   ak_libakrypt_log_options();

 /* проверяем длины фиксированных типов данных */
   if( ak_libakrypt_test_types() != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "sizes of predefined types is wrong" );
     return ak_false;
   }

 /* инициализируем структуру управления контекстами */
   if(( error = ak_libakrypt_create_context_manager()) != ak_error_ok ) {
     ak_error_message( error, __func__, "initialization of context manager is wrong" );
     return ak_false;
   }

 /* инициализируем константные таблицы для алгоритма Кузнечик */
  if( ak_bckey_init_kuznechik_tables()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                  "incorrect initialization of kuznechik predefined tables" );
    return ak_false;
  }

 /* процедура полного тестирования всех криптографических алгоритмов
    занимает крайне много времени, особенно на встраиваемых платформах,
    поэтому ее запуск должен производиться в соответствии с неким (внешним) регламентом ....

    if( !ak_libakrypt_dynamic_control_test( )) {
      ak_error_message( error, __func__, "incorrect dynamic control test" );
      return ak_false;
    }

    заметим, что функция динамического контроля экспортируется,
    так что она может быть запущена пользователем самостоятельно. */

 if( ak_log_get_level() != ak_log_none )
   ak_error_message( ak_error_ok, __func__ , "creation of libakrypt is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy( void )
{
  int error = ak_error_get_value();
  if( error != ak_error_ok )
    ak_error_message( error, __func__ , "before destroing library holds an error" );

 /* уничтожаем структуру управления контекстами */
  if( ak_libakrypt_destroy_context_manager() != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__, "destroying of context manager is wrong" );
  }

  if( ak_log_get_level() != ak_log_none )
    ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms successfully destroyed" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
