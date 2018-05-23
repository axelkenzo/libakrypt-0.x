/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_oid.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_tools.h>
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Структура, сожержащая указатели на функции зашифрования/расшифрования в режиме счетчика */
 static struct two_pointers block_cipher_counter_functions = {
  (ak_function_void *) ak_bckey_context_xcrypt, /* прямое преобразование - зашифрование */
  (ak_function_void *) ak_bckey_context_xcrypt /* обратное преобразование - расшифрование */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения OID библиотеки */
 struct oid libakrypt_oids[] = {
  /* 1. идентификаторы алгоритмов выработки псевдо-случайных последовательностей,
        значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */
   { random_generator, algorithm, "lcg", "1.2.643.2.52.1.1.1", NULL,
                                                        (ak_function_void *) ak_random_create_lcg },
#if defined(__unix__) || defined(__APPLE__)
   { random_generator, algorithm, "dev-random", "1.2.643.2.52.1.1.2", NULL,
                                                     (ak_function_void *) ak_random_create_random },
   { random_generator, algorithm, "dev-urandom", "1.2.643.2.52.1.1.3", NULL,
                                                    (ak_function_void *) ak_random_create_urandom },
#endif
#ifdef _WIN32
   { random_generator, algorithm, "winrtl", "1.2.643.2.52.1.1.4", NULL,
                                                     (ak_function_void *) ak_random_create_winrtl },
#endif
  /* 2. идентификаторы алгоритмов бесключевого хеширования,
        значения OID взяты из перечней КриптоПро и ТК26 (http://tk26.ru/methods/OID_TK_26/index.php)
        в дереве библиотеки: 1.2.643.2.52.1.2 - функции бесключевого хеширования */
   { hash_function, algorithm, "streebog256", "1.2.643.7.1.1.2.2", NULL,
                                                  (ak_function_void *) ak_hash_create_streebog256 },
   { hash_function, algorithm, "streebog512", "1.2.643.7.1.1.2.3", NULL,
                                                  (ak_function_void *) ak_hash_create_streebog512 },
   { hash_function, algorithm, "gosthash94", "1.2.643.2.2.9", NULL,
                                               (ak_function_void *) ak_hash_create_gosthash94_csp },

  /* 3. идентификаторы параметров алгоритма бесключевого хеширования ГОСТ Р 34.11-94.
        в дереве библиотеки: 1.2.643.2.52.1.3 - параметры функций бесключевого хеширования */
   { hash_function, kbox_params, "id-gosthash94-test-paramset", "1.2.643.2.2.30.0",
                                                                      (ak_pointer) hash_box, NULL },
   { hash_function, kbox_params, "id-gosthash94-rfc4357-paramsetA", "1.2.643.2.2.30.1",
                                                                 (ak_pointer) hash_box_CSPA, NULL },
   { hash_function, kbox_params, "id-gosthash94-verbaO-paramset", "1.2.643.2.2.30.2",
                                                               (ak_pointer) hash_box_VerbaO, NULL },

  /* 4. идентификаторы алгоритмов HMAC согласно Р 50.1.113-2016
        в дереве библиотеки: 1.2.643.2.52.1.4 - функции ключевого хеширования (имитозащиты)
        в дереве библиотеки: 1.2.643.2.52.1.5 - параметры функций ключевого хеширования (имитозащиты) */
   { mac_function, algorithm, "hmac-streebog256", "1.2.643.7.1.1.4.1", NULL,
                                              (ak_function_void *) ak_mac_create_hmac_streebog256 },
   { mac_function, algorithm, "hmac-streebog512", "1.2.643.7.1.1.4.2", NULL,
                                              (ak_function_void *) ak_mac_create_hmac_streebog512 },
   { mac_function, algorithm, "hmac-gosthash94", "1.2.643.2.52.1.4.1", NULL,
                                           (ak_function_void *) ak_mac_create_hmac_gosthash94_csp },

  /* 6. идентификаторы алгоритмов блочного шифрования
        в дереве библиотеки: 1.2.643.2.52.1.6 - алгоритмы блочного шифрования
        в дереве библиотеки: 1.2.643.2.52.1.7 - параметры алгоритмов блочного шифрования */
   { block_cipher, algorithm, "magma", "1.2.643.2.2.21", NULL,
                                                       (ak_function_void *) ak_bckey_create_magma },
   { block_cipher, algorithm, "kuznechik", "1.2.643.7.1.1.5.2", NULL,
                                                   (ak_function_void *) ak_bckey_create_kuznechik },

  /* 8. идентификаторы режимов работы блочных шифров.
        в дереве библиотеки: 1.2.643.2.52.1.8 - режимы работы блочных шифров
        в дереве библиотеки: 1.2.643.2.52.1.9 - параметры режимов работы блочных шифров  */
   { block_cipher, ecb, "ecb", "1.2.643.2.52.1.8.1", NULL, NULL },
   { block_cipher, counter, "counter", "1.2.643.2.52.1.8.2",
                                               (ak_pointer )&block_cipher_counter_functions, NULL },

   // { block_cipher, cfb, "cfb", "1.2.643.2.52.1.8.3", NULL, NULL },
   // { block_cipher, cbc, "cbc", "1.2.643.2.52.1.8.4", NULL, NULL },
   // { block_cipher, ofb, "ofb", "1.2.643.2.52.1.8.5", NULL, NULL },
   // { block_cipher, xts, "xts", "1.2.643.2.52.1.8.6", NULL, NULL },

  /* 10. идентификаторы алгоритмов выработки электронной подписи
        в дереве библиотеки: 1.2.643.2.52.1.10 - алгоритмы выработки электронной подписи */
   { sign_function, algorithm, "sign256", "1.2.643.7.1.1.1.1", NULL, NULL },
   { sign_function, algorithm, "sign512", "1.2.643.7.1.1.1.2", NULL, NULL },
   { sign_function, algorithm, "sign256-gosthash94", "1.2.643.2.52.1.10.1", NULL, NULL },

 /* 11. идентификаторы алгоритмов проверки электронной подписи
        в дереве библиотеки: 1.2.643.2.52.1.11 - алгоритмы проверки электронной подписи */
   { verify_function, algorithm, "verify256", "1.2.643.2.52.1.11.2", NULL, NULL },
   { verify_function, algorithm, "verify512", "1.2.643.2.52.1.11.3", NULL, NULL },
   { verify_function, algorithm, "verify256-gosthash94", "1.2.643.2.52.1.11.1", NULL, NULL },

 /* 12. идентификаторы параметров эллиптических кривых, в частности, из Р 50.1.114-2016
        в дереве библиотеки: 1.2.643.2.52.1.12 - параметры эллиптических кривых в форме Вейерштрасса
        в дереве библиотеки: 1.2.643.2.52.1.12.1 - параметры 256 битных кривых
        в дереве библиотеки: 1.2.643.2.52.1.12.2 - параметры 512 битных кривых */
   { identifier, wcurve_params, "id-tc26-gost3410-2012-256-test-paramset", "1.2.643.7.1.2.1.1.0",
                                      (ak_pointer) &id_tc26_gost3410_2012_256_test_paramset, NULL },
   { identifier, wcurve_params, "id-tc26-gost3410-2012-256-paramsetA", "1.2.643.7.1.2.1.1.1",
                                          (ak_pointer) &id_tc26_gost3410_2012_256_paramsetA, NULL },
   { identifier, wcurve_params, "id-rfc4357-gost3410-2001-paramsetA", "1.2.643.2.2.35.1",
                                           (ak_pointer) &id_rfc4357_gost3410_2001_paramsetA, NULL },
   { identifier, wcurve_params, "id-rfc4357-gost3410-2001-paramsetB", "1.2.643.2.2.35.2",
                                           (ak_pointer) &id_rfc4357_gost3410_2001_paramsetB, NULL },
   { identifier, wcurve_params, "id-rfc4357-gost3410-2001-paramsetC", "1.2.643.2.2.35.3",
                                           (ak_pointer) &id_rfc4357_gost3410_2001_paramsetC, NULL },
   { identifier, wcurve_params, "id-rfc4357-2001dh-paramset", "1.2.643.2.2.36.0",
                                           (ak_pointer) &id_rfc4357_gost3410_2001_paramsetA, NULL },
   { identifier, wcurve_params, "id-axel-gost3410-2012-256-paramsetA", "1.2.643.2.52.1.12.1.1",
                                          (ak_pointer) &id_axel_gost3410_2012_256_paramsetA, NULL },

   { identifier, wcurve_params, "id-tc26-gost3410-2012-512-test-paramset", "1.2.643.7.1.2.1.2.0",
                                      (ak_pointer) &id_tc26_gost3410_2012_512_test_paramset, NULL },
   { identifier, wcurve_params, "id-tc26-gost3410-2012-512-paramsetA", "1.2.643.7.1.2.1.2.1",
                                          (ak_pointer) &id_tc26_gost3410_2012_512_paramsetA, NULL },
   { identifier, wcurve_params, "id-tc26-gost3410-2012-512-paramsetB", "1.2.643.7.1.2.1.2.2",
                                          (ak_pointer) &id_tc26_gost3410_2012_512_paramsetB, NULL },
   { identifier, wcurve_params, "id-tc26-gost3410-2012-512-paramsetC", "1.2.643.7.1.2.1.2.3",
                                          (ak_pointer) &id_tc26_gost3410_2012_512_paramsetC, NULL },
   { identifier, wcurve_params, "id-axel-gost3410-2012-512-paramsetA", "1.2.643.2.52.1.12.2.1",
                                          (ak_pointer) &id_axel_gost3410_2012_512_paramsetA, NULL },

 /* 13. идентификаторы параметров эллиптических кривых, в частности, из Р 50.1.114-2016
        в дереве библиотеки: 1.2.643.2.52.1.13 - параметры эллиптических кривых в форме Эдвардса
        в дереве библиотеки: 1.2.643.2.52.1.13.1 - параметры 256 битных кривых
        в дереве библиотеки: 1.2.643.2.52.1.13.2 - параметры 512 битных кривых */

 /* 14. идентификаторы алгоритмов бесключевого хеширования SHA-2 */
   { hash_function, algorithm, "sha224", "2.16.840.1.101.3.4.2.4", NULL, (ak_function_void *) ak_hash_create_sha224},
   { hash_function, algorithm, "sha256", "2.16.840.1.101.3.4.2.1", NULL, (ak_function_void *) ak_hash_create_sha256 },
   { hash_function, algorithm, "sha384", "2.16.840.1.101.3.4.2.2", NULL, (ak_function_void *) ak_hash_create_sha384 },
   { hash_function, algorithm, "sha512", "2.16.840.1.101.3.4.2.3", NULL, (ak_function_void *) ak_hash_create_sha512 },
   { hash_function, algorithm, "sha512_256", "2.16.840.1.101.3.4.2.6", NULL, (ak_function_void *) ak_hash_create_sha512_256 },
   { hash_function, algorithm, "sha512_224", "2.16.840.1.101.3.4.2.5", NULL, (ak_function_void *) ak_hash_create_sha512_224 },

  /* завершающая константа, должна всегда принимать неопределенные и нулевые значения */
   { undefined_engine, undefined_mode, NULL, NULL, NULL, NULL }
 };

/* ----------------------------------------------------------------------------------------------- */
/*                     реализация функций доступа к глобальному списку OID                         */
/* ----------------------------------------------------------------------------------------------- */
 const size_t ak_libakrypt_oids_count( void )
{
 return ( sizeof( libakrypt_oids )/( sizeof( struct oid )) - 1 );
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_oid_get_name( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }
 return oid->name;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_oid_get_id( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }
 return oid->id;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_oid_get_engine_str( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }
 return ak_libakrypt_get_engine_str( oid->engine );
}

/* ----------------------------------------------------------------------------------------------- */
 const ak_oid_engine ak_libakrypt_oid_get_engine( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return undefined_engine;
  }
 return oid->engine;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_oid_get_mode_str( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }
 return ak_libakrypt_get_mode_str( oid->mode );
}

/* ----------------------------------------------------------------------------------------------- */
 const ak_oid_mode ak_libakrypt_oid_get_mode( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return undefined_mode;
  }
 return oid->mode;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция ищет первый OID с заданным значением engine и возвращает его дескриптор.
    Если такое значение не найдено, возвращается значение \ref ak_error_wrong_handle.
    Если значение engine равно \ref undefined_engine, то возвращается
    первый OID в списке, следовательно, значение \ref undefined_engine может использоваться
    для перебора всех возможных OID библиотеки.

    @param engine тип криптографического механизма.
    @return Функция возвращает дескриптор найденного OID. В случае неверного поиска возвращается
    \ref ak_error_wrong_handle, код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_libakrypt_find_oid_by_engine( ak_oid_engine engine )
{
  size_t idx = 0;
  ak_handle handle = ak_error_wrong_handle;

  if( engine != undefined_engine ) {
    /* переборный цикл с первого элемента массива */
    do{
      if( libakrypt_oids[idx].engine == engine ) break; /* случай совпадения engine */
    } while( ++idx < ak_libakrypt_oids_count( ));
    if( idx == ak_libakrypt_oids_count( )) return handle;
  }

 /* создаем дескриптор */
  if(( handle = ak_context_manager_add_node( ak_libakrypt_get_context_manager(),
                         &libakrypt_oids[idx], oid_engine, "", NULL )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    return ak_error_wrong_handle;
  }

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция продолжает поиск  в структуре управления контекстами OID'а с заданным значением engine и
    возвращает его дескриптор.
    Если такое значение не найдено, возвращается значение \ref ak_error_wrong_handle.
    Если значение engine равно \ref undefined_engine, то возвращается
    следующий OID в списке, следовательно, значение \ref undefined_engine может использоваться
    для перебора всех возможных OID библиотеки.

    Пример для перебора всех существующих OID блочного шифрования.

   \code
     ak_handle handle = ak_libakrypt_find_oid_by_engine( block_cipher );

     while( handle != ak_error_wrong_handle )
       handle = ak_libakrypt_findnext_oid_by_engine( handle, block_cipher );
   \endcode

    @param handle Дескриптор, начиная с которого производится поиск.
    @param engine тип криптографического механизма.
    @return Функция возвращает дескриптор найденного OID. В случае неверного поиска возвращается
    \ref ak_error_wrong_handle, код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_libakrypt_findnext_oid_by_engine( ak_handle handle, ak_oid_engine engine )
{
  size_t idx = 0;
  ak_oid oid = NULL;
  int error = ak_error_ok;
  ak_context_manager manager = ak_libakrypt_get_context_manager();

 /* для того чтобы не создавать новый дескриптор, приходится эмулировать
    работу функции ak_handle_get_context() */
  if( manager == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "null pointer to internal context manager");
    return ak_error_wrong_handle;
  }
  if(( error = ak_context_manager_handle_check( manager, handle, &idx ))!= ak_error_ok ) {
    ak_error_message( error, __func__, "wrong handle" );
    return ak_error_wrong_handle;
  }
  if( manager->array[idx]->engine != oid_engine ) {
    ak_error_message( ak_error_oid_engine, __func__, "using wrong engine for given handle" );
    return ak_error_wrong_handle;
  }

 /* получаем рабочий указатель на OID в качестве элемента глобального массива контекстов */
  if(( oid = (ak_oid) manager->array[idx]->ctx ) == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                           "using null pointer in handle to internal structure" );
    return ak_error_wrong_handle;
  }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->engine != undefined_engine ) {
   /* в случае успешного поиска устанавливаем новое значение контекста в глобальном массиве */
    if( engine == undefined_engine ) { manager->array[idx]->ctx = oid; return handle; }
    if( oid->engine == engine ) { manager->array[idx]->ctx = oid; return handle; }
  }
  if(( error = ak_handle_delete( handle )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect handle destroying");
 return ak_error_wrong_handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param name Человекочитаемое имя разыскиваемого идентификатора.
    @return Функция возвращает дескриптор найденного OID. В случае неверного поиска возвращается
    \ref ak_error_wrong_handle, код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_libakrypt_find_oid_by_name( const char *name )
{
  size_t idx = 0;
  ak_handle handle = ak_error_wrong_handle;

 /* переборный цикл с первого элемента массива */
  do{
     if( ak_ptr_is_equal( (void *) name,
                      (void *)libakrypt_oids[idx].name, strlen( libakrypt_oids[idx].name ))) break;
  } while( ++idx < ak_libakrypt_oids_count( ));
  if( idx == ak_libakrypt_oids_count( )) return handle;

 /* создаем дескриптор */
  if(( handle = ak_context_manager_add_node( ak_libakrypt_get_context_manager(),
                         &libakrypt_oids[idx], oid_engine, "", NULL )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    return ak_error_wrong_handle;
  }

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param id Идентификатор, заданный в виде последовательности чисел, разделенных точками
    @return Функция возвращает дескриптор найденного OID. В случае неверного поиска возвращается
    \ref ak_error_wrong_handle, код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_libakrypt_find_oid_by_id( const char *id )
{
  size_t idx = 0;
  ak_handle handle = ak_error_wrong_handle;

 /* переборный цикл с первого элемента массива */
  do{
     if( ak_ptr_is_equal( (void *) id,
                        (void *)libakrypt_oids[idx].id, strlen( libakrypt_oids[idx].id ))) break;
  } while( ++idx < ak_libakrypt_oids_count( ));
  if( idx == ak_libakrypt_oids_count( )) return handle;

 /* создаем дескриптор */
  if(( handle = ak_context_manager_add_node( ak_libakrypt_get_context_manager(),
                         &libakrypt_oids[idx], oid_engine, "", NULL )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    return ak_error_wrong_handle;
  }

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          поиск OID - функции внутреннего интерфейса                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_name( const char *name )
{
  size_t idx = 0;
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }
  do{
     if(( strlen( name ) == strlen( libakrypt_oids[idx].name )) &&
            ak_ptr_is_equal( (char *)name, (char *)libakrypt_oids[idx].name,
                                strlen( libakrypt_oids[idx].name ))) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_name, __func__, "searching oid with wrong name" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_id( const char *id )
{
  size_t idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid identifier" );
    return NULL;
  }

  do{
     if(( strlen( id ) == strlen( libakrypt_oids[idx].id )) &&
            ak_ptr_is_equal( (char *)id, (char *)libakrypt_oids[idx].id,
                                strlen( libakrypt_oids[idx].id ))) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_id, __func__, "searching oid with wrong idetifier" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_engine( ak_oid_engine engine )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].engine == engine ) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_name, __func__, "searching oid with wrong engine" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_findnext_by_engine( ak_oid startoid, ak_oid_engine engine )
{
 ak_oid oid = startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->engine != undefined_engine ) {
    if( oid->engine == engine ) return oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                 вспомогательные функции для типов ak_oid_engine и ak_oid_mode                   */
/* ----------------------------------------------------------------------------------------------- */
 const size_t ak_libakrypt_engines_count( void )
{
 return ( 1 + (size_t)oid_engine );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографического механизма
    @return Функция возвращает указатель на строку, сожержащую описание типа криптографического
    механизма. Если значение engine неверно, то возбуждается ошибка и возвращается указатель на
    null-строку                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_engine_str( ak_oid_engine engine )
{
  switch( engine )
 {
   case undefined_engine:  return "undefined engine";
   case identifier:        return "identifier";
   case block_cipher:      return "block cipher";
   case stream_cipher:     return "stream cipher";
   case hybrid_cipher:     return "hybrid cipher";
   case hash_function:     return "hash function";
   case mac_function:      return "mac function";
   case sign_function:     return "digital signature sign function";
   case verify_function:   return "digital signature verify fucntion";
   case random_generator:  return "random generator";
   case update_engine:     return "update engine";
   case oid_engine:        return "oid";
   default:                break;
 }
  ak_error_message_fmt( ak_error_undefined_value, __func__,
                                                "using a non defined engine's value %d", engine );
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param str символьное описание, должно в точности совпадать с тем, что возвращает функция
               ak_engine_get_str().
    @return В случае успеха, возвращается значение, соответстующее символьному описанию.
    В случае, если описание неверно, то возбуждается ошибка и возвращается значение
    \ref undefined_engine.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid_engine ak_libakrypt_get_engine( const char *str )
{
  if(( strlen( str ) == 16 ) && ak_ptr_is_equal( "undefined engine", (void *)str, 16 ))
                                                                            return undefined_engine;
  if(( strlen( str ) == 10 ) && ak_ptr_is_equal( "identifier", (void *)str, 10 )) return identifier;
  if(( strlen( str ) == 12 ) && ak_ptr_is_equal( "block cipher", (void *)str, 12 ))
                                                                                return block_cipher;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "stream cipher", (void *)str, 13 ))
                                                                               return stream_cipher;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "hybrid cipher", (void *)str, 13 ))
                                                                               return hybrid_cipher;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "hash function", (void *)str, 13 ))
                                                                               return hash_function;
  if(( strlen( str ) == 12 ) && ak_ptr_is_equal( "mac function", (void *)str, 12 ))
                                                                                return mac_function;
  if(( strlen( str ) == 31 ) && ak_ptr_is_equal( "digital signature sign function",
                                                            (void *)str, 31 )) return sign_function;
  if(( strlen( str ) == 33 ) && ak_ptr_is_equal( "digital signature verify function",
                                                          (void *)str, 33 )) return verify_function;
  if(( strlen( str ) == 16 ) && ak_ptr_is_equal( "random generator", (void *)str, 16 ))
                                                                            return random_generator;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "update engine", (void *)str, 13 ))
                                                                               return update_engine;
  if(( strlen( str ) == 3 ) && ak_ptr_is_equal( "oid", (void *)str, 3 )) return oid_engine;

  ak_error_message_fmt( ak_error_undefined_value, __func__,
                                             "string \"%s\" is not valid engine description", str );
 return undefined_engine;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param mode режим использованиея криптографического механизма
    @return Функция возвращает указатель на строку, сожержащую описание типа криптографического
    механизма. Если значение engine неверно, то возбуждается ошибка и возвращается указатель на
    null-строку                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_mode_str( ak_oid_mode mode )
{
  switch( mode )
 {
   case undefined_mode:  return "undefined mode";
   case algorithm:       return "algorithm";
   case parameter:       return "parameter";
   case wcurve_params:   return "weierstrass curve parameters";
   case ecurve_params:   return "edwards curve parameters";
   case kbox_params:     return "kboxes";
   case ecb:             return "ecb mode";
   case ofb:             return "ofb mode";
   case counter:         return "counter mode";
   case counter_gost:    return "gost28147-89 counter mode";
   case cfb:             return "cfb mode";
   case cbc:             return "cbc mode";
   case xts:             return "xts mode";
   case xts_mac:         return "xts mode with authenication";
   case xcrypt:          return "stream cipher xor mode";
   case a8:              return "stream cipher addition mode";
   case signify:         return "signify mode";
   case verify:          return "verify mode";
   default:              break;
 }
  ak_error_message_fmt( ak_error_undefined_value, __func__,
                                                      "using a non defined mode's value %d", mode );
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example example-oid.c                                                                        */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
