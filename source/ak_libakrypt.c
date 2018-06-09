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
/*   ak_libakrypt.c                                                                                */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_LIMITS_H
 #include <limits.h>
#endif

#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif

#ifdef LIBAKRYPT_HAVE_FCNTL_H
  #include <fcntl.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <errno.h>
 #include <sys/stat.h>

 #include <ak_mac.h>
 #include <ak_tools.h>
 #include <ak_curves.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип данных для хранения одной опции библиотеки */
 typedef struct {
  /*! \brief Человекочитаемое имя опции, используется для поиска и установки значения */
   const char *name;
  /*! \brief Численное значение опции (целое неотрицательное число) */
   int value;
 } ak_option;

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения опций (значения по-умолчанию) */
 ak_option options[] = {
     { "big_endian_architecture", ak_false },
     { "log_level", ak_log_standard },
     { "context_manager_size", 32 },
     { "context_manager_max_size", 4096 },
     { "key_number_length", 16 },
     { "pbkdf2_iteration_count", 2000 },
     { "hmac_key_count_resource", 65536 },
     { "magma_cipher_resource", 32*4194304 }, //!!!!!
     { "kuznechik_cipher_resource", 8*4194304 },
     { NULL, 0 } /* завершающая константа, должна всегда принимать нулевые значения */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает общее количество опций библиотеки.
    \return Общее количество опций библиотеки.                                                     */
/* ----------------------------------------------------------------------------------------------- */
 const size_t ak_libakrypt_options_count( void )
{
  return ( sizeof( options )/( sizeof( ak_option ))-1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает значение опции с заданным именем.

    \param name Имя опции
    \return Значение опции с заданным именем. Если имя указано неверно, то возвращается
    ошибка \ref ak_error_wrong_option.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_get_option( const char *name )
{
  size_t i = 0;
  int result = ak_error_wrong_option;
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
     if( strncmp( name, options[i].name, strlen( options[i].name )) == 0 ) result = options[i].value;
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает значение опции с заданным именем.

    \param name Имя опции
    \param value Значение опции

    \return В случае удачного установления значения опции возввращается \ref ak_error_ok.
     Если имя опции указано неверно, то возвращается ошибка \ref ak_error_wrong_option.            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_option( const char *name, const int value )
{
  size_t i = 0;
  int result = ak_error_wrong_option;
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
     if( strncmp( name, options[i].name, strlen( options[i].name )) == 0 ) {
       options[i].value = value;
       result = ak_error_ok;
     }
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция возвращает указатель на константную строку, содержащую
    человекочитаемое имя опции библиотеки.

    \param index Индекс опции, должен быть от нуля до значения,
    возвращаемого функцией ak_libakrypt_options_count().

    \return Строка симовлов, содержащая имя функции, в случае правильно определенного индекса.
    В противном случае, возвращается констанный указатель на (null).                              */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_option_name( const size_t index )
{
 if( index >= ak_libakrypt_options_count() ) return ak_null_string;
  else return options[index].name;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция возвращает значение опции библиотеки с заданным индексом.

    \param index Индекс опции, должен быть от нуля до значения,
    возвращаемого функцией ak_libakrypt_options_count().

    \return Целое неотрицательное число, содержащее значение опции с заданным индексом.
    В случае неправильно определенного индекса возвращается значение \ref ak_error_wrong_option.   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_get_option_value( const size_t index )
{
 if( index >= ak_libakrypt_options_count() ) return ak_error_wrong_option;
  else return options[index].value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает имя файла в котором содержатся настройки библиотеки.

   @param filename Массив, куда помещается имя файла. Память под массив
          должна быть быделена заранее.
   @param size Размер выделенной памяти.
   @return Функция возвращает код ошибки.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_create_filename_for_options( char *filename, size_t size )
{
 char drive[FILENAME_MAX], hpath[FILENAME_MAX], append[FILENAME_MAX];

  memset( (void *)filename, 0, size );
  memset( (void *)drive, 0, FILENAME_MAX );
  memset( (void *)hpath, 0, FILENAME_MAX );
  memset( (void *)append, 0, FILENAME_MAX );

#ifdef LIBAKRYPT_OPTIONS_PATH
  {
   /* здесь мы обрабатываем путь, заданный из командной строки при сборке библиотеки */
    size_t len = 0;
    if(( len = strlen( LIBAKRYPT_OPTIONS_PATH )) > FILENAME_MAX-16 ) {
      ak_error_message( ak_error_wrong_length, __func__ , "wrong length of predefined filepath" );
      return ak_error_wrong_length;
    }
    memcpy( hpath, LIBAKRYPT_OPTIONS_PATH, len ); /* массивы drive и append остаются пустыми */
  }
#else
 /* здесь обработка пути к файлу вручную */
 #ifdef _WIN32
  /* в начале определяем, находимся ли мы в консоли MSys */
   GetEnvironmentVariableA( "HOME", hpath, FILENAME_MAX-1 );
  /* если мы находимся не в консоли, то строка hpath должна быть пустой */
   if( strlen( hpath ) == 0 ) {
     GetEnvironmentVariableA( "APPDATA", drive, FILENAME_MAX-1 );
     strncpy( append, "\\libakrypt", 33 );
   } else strncpy( append, "/.config/libakrypt", 18 );
 #else
  ak_snprintf( hpath, FILENAME_MAX, "%s/.config/libakrypt", getenv( "HOME" ));
 #endif
#endif

/* собираем имя файла из нескольких фрагментов */
  #ifdef _WIN32
   ak_snprintf( filename, size, "%s%s%s\\libakrypt.conf", drive, hpath, append );
  #else
   ak_snprintf( filename, size, "%s%s%s/libakrypt.conf", drive, hpath, append );
  #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_load_option( const char *string, const char *field, ak_uint64 *value )
{
  char *ptr = NULL, *endptr = NULL;
  if(( ptr = strstr( string, field )) != NULL ) {
    ak_uint64 val = (ak_uint64) strtol( ptr += strlen(field), &endptr, 10 ); // strtoll
    if(( endptr != NULL ) && ( ptr == endptr )) {
      ak_error_message_fmt( ak_error_undefined_value, __func__,
                                    "using an undefinded value for variable %s", field );
      return ak_false;
    }
    if(( errno == ERANGE && ( val == LONG_MAX || val == LONG_MIN )) || (errno != 0 && val == 0)) {
      ak_error_message_fmt( ak_error_undefined_value, __func__,
                                                     "%s for field %s", strerror( errno ), field );
    } else {
             *value = ( ak_uint64 ) val;
             return ak_true;
           }
  }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_load_options( void )
{
 size_t idx = 0;
 int fd = 0, off = 0, error = ak_error_ok;
 char ch;
 struct stat st;
 char localbuffer[1024], filename[FILENAME_MAX];

 /* создаем имя файла */
  if(( error = ak_libakrypt_create_filename_for_options( filename, FILENAME_MAX )) != ak_error_ok )
  {
    ak_error_message( error, __func__ , "invalid creation of filename for libakrypt options" );
    return ak_false;
  }

 /* проверяем наличие файла и прав доступа к нему */
  if(( fd = open( filename, O_RDONLY | O_BINARY )) < 0 ) {
    ak_error_message_fmt( ak_error_open_file,
                     __func__, "wrong open file \"%s\" with error %s", filename, strerror( errno ));
    return ak_false;
  }
  if( fstat( fd, &st ) ) {
    close( fd );
    ak_error_message_fmt( ak_error_access_file, __func__ ,
                               "wrong stat file \"%s\" with error %s", filename, strerror( errno ));
    return ak_false;
  }

 /* нарезаем входные на строки длиной не более чем 1022 символа */
  memset( localbuffer, 0, 1024 );
  for( idx = 0; idx < (size_t) st.st_size; idx++ ) {
     if( read( fd, &ch, 1 ) != 1 ) {
       ak_error_message( ak_error_read_data, __func__ , "unexpected end of libakrypt.conf" );
       close(fd);
       return ak_false;
     }
     if( off > 1022 ) {
       ak_error_message( ak_error_read_data, __func__ ,
                                   "libakrypt.conf has a line with more than 1022 symbols" );
       close( fd );
       return ak_false;
     }
    if( ch == '\n' ) {
      if((strlen(localbuffer) != 0 ) && ( strchr( localbuffer, '#' ) == 0 )) {
        ak_uint64 value = 0, value2 = 0;

        /* устанавливаем уровень аудита */
        if( ak_libakrypt_load_option( localbuffer, "log_level = ", &value ))
          // libakrypt_options.log_level = ( int )value;
          ak_libakrypt_set_option( "log_level", value );

        /* устанавливаем минимальный размер структуры управления контекстами */
        if( ak_libakrypt_load_option( localbuffer, "context_manager_size = ", &value )) {
          int len = 0;
          while( value ) { value>>=1; len++; } /* вычисляем число значащих бит */
          if( len < 2 ) len = 2;
          if( len >= 32 ) len = 31;
          // libakrypt_options.context_manager_size = ((size_t)1 << len );
          ak_libakrypt_set_option( "context_manager_size", value2 = ( 1 << len ));
        }

       /* устанавливаем максимально возможный размер структуры управления контекстами */
        if( ak_libakrypt_load_option( localbuffer, "context_manager_max_size = ", &value )) {
          int len = 0;
          while( value ) { value>>=1; len++; } /* вычисляем число значащих бит */
          if( len < 2 ) len = 2;
          if( len > 63 ) len = 63;
          // libakrypt_options.context_manager_max_size = ((size_t)1 << len );
          ak_libakrypt_set_option( "context_manager_max_size", ak_max( value2, 1 << len ));
        }

       /* устанавливаем длину номера ключа */
        if( ak_libakrypt_load_option( localbuffer, "key_number_length = ", &value )) {
          if( value < 16 ) value = 16;
          if( value > 32 ) value = 32;
          // libakrypt_options.key_number_length = (int) value;
          ak_libakrypt_set_option( "key_number_length", value );
        }

       /* устанавливаем количество циклов в алгоритме pbkdf2 */
        if( ak_libakrypt_load_option( localbuffer, "pbkdf2_iteration_count = ", &value )) {
          if( value < 1000 ) value = 1000;
          if( value > 2147483647 ) value = 2147483647;
          // libakrypt_options.pbkdf2_iteration_count = (int) value;
          ak_libakrypt_set_option( "pbkdf2_iteration_count", value );
        }

       /* устанавливаем ресурс ключа выработки имитовставки для алгоритма HMAC */
        if( ak_libakrypt_load_option( localbuffer, "hmac_key_counter_resource = ", &value )) {
          if( value < 1024 ) value = 1024;
          if( value > 2147483647 ) value = 2147483647;
          // libakrypt_options.hmac_key_count_resource = (size_t) value;
          ak_libakrypt_set_option( "hmac_key_count_resource", value );
        }

      } /* далее мы очищаем строку независимо от ее содержимого */
      off = 0;
      memset( localbuffer, 0, 1024 );
    } else localbuffer[off++] = ch;
  }

  /* закрываем */
  close(fd);

  /* выводим сообщение об установленных параметрах библиотеки */
  if( ak_libakrypt_get_option( "log_level" ) > ak_log_standard ) {
    int i = 0;

    ak_error_message_fmt( ak_error_ok, __func__, "libakrypt version: %s", ak_libakrypt_version( ));
    /* далее мы пропускаем вывод информации об архитектуре,
       поскольку она будет далее тестироваться отдельно     */
    for( i = 1; i < ak_libakrypt_options_count(); i++ )
       ak_error_message_fmt( ak_error_ok, __func__, "option [%s = %d]", options[i].name, options[i].value );
  }
  return ak_true;
 }

/* ----------------------------------------------------------------------------------------------- */
 int ak_log_get_level( void ) { return ak_libakrypt_get_option("log_level"); }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Установка уровня аудита библиотеки.

  Все сообщения библиотеки могут быть разделены на три уровня.

  \li Первый уровень аудита определяется константой \ref ak_log_none. На этом уровне выводятся
  сообщения об ошибках, а также минимальный набор сообщений, включающий в себя факт
  успешного тестирования работоспособности криптографических механизмов.

  \li Второй уровень аудита определяется константой \ref ak_log_standard. На этом уровене
  выводятся все сообщения из первого уровня, а также сообщения о фактах использования
  ключевой информации.

  \li Третий (максимальный) уровень аудита определяется константой \ref ak_log_maximum.
  На этом уровне выводятся все сообщения, доступные на первых двух уровнях, а также
  сообщения отладочного характера, позхволяющие прослдедить логику работы функций библиотеки.

  \param level Уровень аудита, может принимать значения \ref ak_log_none,
  \ref ak_log_standard и \ref ak_log_maximum.

  \return Функция всегда возвращает ak_error_ok (ноль).                                            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_level( int level )
{
 if( level >= ak_log_maximum )
   return ak_libakrypt_set_option("log_level", ak_log_maximum );
 if( level <= ak_log_none )
   return ak_libakrypt_set_option("log_level", ak_log_none );

 return ak_libakrypt_set_option("log_level", ak_log_standard );
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_version( void )
{
#ifdef LIBAKRYPT_VERSION
  return LIBAKRYPT_VERSION;
#else
  return "0.6";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность определения базовых типов данных
   \return В случе успешного тестирования возвращает ak_true (истина).
   В противном случае возвращается ak_false.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_test_types( void )
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

  if( ak_log_get_level() >= ak_log_maximum )
    ak_error_message_fmt( ak_error_ok, __func__, "size of pointer is %d", sizeof( ak_pointer ));

 /* определяем тип платформы: little-endian или big-endian */
  val.x[0] = 0; val.x[1] = 1; val.x[2] = 2; val.x[3] = 3;

#ifdef LIBAKRYPT_BIG_ENDIAN
  ak_libakrypt_set_option("big_endian_architecture", ak_true );
  if( val.z == 50462976 ) {
    ak_error_message( ak_error_wrong_endian, __func__ ,
      "library runs on little endian platform, don't use LIBAKRYPT_BIG_ENDIAN flag while compile library" );
    return ak_false;
  }
#else
  if( val.z == 66051 ) {
    ak_error_message( ak_error_wrong_endian, __func__ ,
      "library runs on big endian platform, use LIBAKRYPT_BIG_ENDIAN flag while compiling library" );
    return ak_false;
  }
#endif

  if( ak_log_get_level() >= ak_log_maximum ) {
    if( ak_libakrypt_get_option( "big_endian_architecture" ) )
      ak_error_message( ak_error_ok, __func__ , "library runs on big endian platform" );
    else ak_error_message( ak_error_ok, __func__ , "library runs on little endian platform" );
  }

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "library applies __m128i base type" );
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов хеширования
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_test_hash_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing hash functions started" );

 /* тестируем функцию ГОСТ Р 34.11-94 */
  if( ak_hash_test_gosthash94() != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect gosthash94 testing" );
   return ak_false;
  }

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

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing hash functions ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов выработки имитовставки
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_test_mac_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing mac functions started" );

 /* тестируем функции hmac-streebog согласно Р 50.1.113-2016 */
  if( ak_hmac_test_streebog() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect hmac testing" );
    return ak_false;
  }

 /* тестируем алгоритм pbkdf2 согласно Р 50.1.111-2016 */
  if( ak_hmac_test_pbkdf2() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect hmac testing" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing mac functions ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации асимметричных криптографических алгоритмов
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_test_asymmetric_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing asymmetric mechanisms started" );

 /* тестируем корректность реализации операций с эллиптическими кривыми в короткой форме Вейерштрасса */
  if( ak_wcurve_test() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of Weierstrass curves" );
    return ak_false;
  }

 /* тестируем корректность реализации алгоритмов электронной подписи */
  if( ak_signkey_test() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of digital signatures" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing asymmetric mechanisms ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_test_block_ciphers( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing block ciphers started" );

 /* тестируем корректность реализации блочного шифра Магма */
  if( ak_bckey_test_magma()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of magma block cipher" );
    return ak_false;
  }

 /* тестируем корректность маскированной реализации блочного шифра Магма */
  if( ak_bckey_test_masked_magma() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of masked magma block cipher" );
    return ak_false;
  }

 /* инициализируем константные таблицы для алгоритма Кузнечик */
  if( ak_bckey_init_kuznechik_tables()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                       "incorrect initialization of kuznechik predefined tables" );
    return ak_false;
  }

 /* тестируем корректность реализации блочного шифра Кузнечик */
  if( ak_bckey_test_kuznechik()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect testing of kuznechik block cipher" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing block ciphers ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна вызываться перед использованием криптографических механизмов библиотеки.

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
   \return Функция возвращает ak_true (истина) в случае успешной инициализации и тестирования
   библиотеки. В противном случае, возвращается ak_false. Код ошибки может быть получен с помощью
   вызова функции ak_error_get_value()                                                            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create( ak_function_log *logger )
{
 int error;
   ak_error_set_value( error = ak_error_ok );

 /* инициализируем систему аудита (вывод сообщений) */
   if(( error = ak_log_set_function( logger )) != ak_error_ok ) {
     ak_error_message( error, __func__ , "audit mechanism not started" );
     return ak_false;
   }

 /* считываем настройки криптографических алгоритмов */
   if( ak_libakrypt_load_options() != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "unsuccessful load of libakrypt.conf" );
     return ak_false;
   }

 /* проверяем длины фиксированных типов данных */
   if( ak_libakrypt_test_types( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "sizes of predefined types is wrong" );
     return ak_false;
   }

 /* инициализируем структуру управления контекстами */
   if(( error = ak_libakrypt_create_context_manager()) != ak_error_ok ) {
     ak_error_message( error, __func__, "initialization of context manager is wrong" );
     return ak_false;
   }

 /* тестируем работу функций хеширования */
  if( ak_libakrypt_test_hash_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "error while testing hash functions" );
    return ak_false;
  }

 /* тестируем работу алгоритмов блочного шифрования */
  if( ak_libakrypt_test_block_ciphers() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "error while testing block ciphers" );
    return ak_false;
  }

 /* тестируем работу алгоритмов выработки имитовставки */
  if( ak_libakrypt_test_mac_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "error while testing mac functions" );
    return ak_false;
  }

 /* тестируем работу алгоритмов выработки и проверки электронной подписи */
  if( ak_libakrypt_test_asymmetric_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                        "error while testing digital signature mechanisms" );
    return ak_false;
  }

 ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms tested successfully" );
return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy( void )
{
  int error = ak_error_get_value();
  if( error != ak_error_ok )
    ak_error_message( error, __func__ , "before destroing library holds an error" );

 /* деактивируем структуру управления контекстами */
  if(( error = ak_libakrypt_destroy_context_manager()) != ak_error_ok )
    ak_error_message( error, __func__, "destroying of context manager is wrong" );

  ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms successfully destroyed" );
 return ak_error_get_value();
}

/* ----------------------------------------------------------------------------------------------- */
/*! \include doc/libakrypt.dox
    \include doc/libakrypt-compile.dox                                                             */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
