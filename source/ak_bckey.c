/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*   ak_bckey.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_bckey.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает параметры алгоритма блочного шифрования, передаваемые в качестве
    аргументов. После инициализации остаются неопределенными следующие поля и методы,
    зависящие от конкретной реализации алгоритма блочного шифрования:

    - bkey.encrypt -- алгоритм зашифрования одного блока
    - bkey.decrypt -- алгоритм расшифрования одного блока
    - bkey.shedule_keys -- алгоритм развертки ключа и генерации раундовых ключей
    - bkey.delete_keys -- функция удаления раундовых ключей
    - bkey.key.data -- указатель на служебную область памяти
    - bkey.key.resource.counter -- максимально возможное число обрабатываемых блоков информации
    - bkey.key.oid -- идентификатор алгоритма шифрования
    - bkey.key.set_mask -- функция установки маски ключа
    - bkey.key.remask -- функция выработки и установки новой маски ключа
    - bkey.key.set_icode -- функция вычисления кода целостности
    - bkey.key.check_icode -- функция проверки кода целостности

    Перечисленные методы должны определяться в производящих функциях,
    создающих объекты конкретных алгоритмов блочного шифрования.

    @param bkey контекст ключа алгоритма блочного шифрованния
    @param keysize длина ключа в байтах
    @param blocksize длина блока обрабатываемых данных в байтах
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create( ak_bckey bkey, size_t keysize, size_t blocksize )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using a null pointer to block cipher context" );
  if( !keysize ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using block cipher key with zero length" );
  if( !blocksize ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using cipher with zero block length" );
 /* теперь инициализируем данные,
    для ключей блочного шифрования длина контрольной суммы всегда равна 8 байт */
  if(( error = ak_skey_create( &bkey->key, keysize, 8 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of secret key" );

 /* длина инициализационного вектора всегда совпадает с длиной блока данных */
  if(( error = ak_buffer_create_size( &bkey->ivector, blocksize )) != ak_error_ok ) {
    if( ak_skey_destroy( &bkey->key ) != ak_error_ok )
      ak_error_message( ak_error_get_value(), __func__, "wrong destroying a secret key" );
    return ak_error_message( error, __func__, "wrong memory allocation for temporary vector");
  }
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;
  bkey->data = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @return В случае успеха функция возввращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_destroy( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to block cipher context" );
  if( bkey->delete_keys != NULL ) {
    if(( error = bkey->delete_keys( &bkey->key )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong deleting of round keys" );
    }
  }
  if(( error = ak_buffer_wipe( &bkey->ivector, &bkey->key.generator )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong wiping a temporary vector");
  if(( error = ak_buffer_destroy( &bkey->ivector )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying a temporary vector" );
  if( bkey->data != NULL ) {
    free( bkey->data );
    bkey->data = NULL;
  }
  if(( error = ak_skey_destroy( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying a secret key" );

  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_bckey_delete( ak_pointer bkey )
{
  if( bkey != NULL ) {
    ak_bckey_destroy( bkey );
    free( bkey );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                         "using null pointer to block cipher key" );
 return NULL;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа алгоритма блочного шифрования заданное значение,
    содержащееся в области памяти, на которую указывает аргумент функции ptr.
    При инициализации значение ключа \b копируется в контекст ключа, если флаг cflag истиннен.
    Если флаг ложен, то копирования (размножения ключевой информации) не происходит.
    Поведение функции при копировании аналогично поведению функции ak_buffer_set_ptr().

    Перед присвоением ключа контекст должен быть инициализирован.
    После присвоения ключа производится его маскирование и выработка контрольной суммы.

    Предпалагается, что основное использование функции ak_bckey_context_set_ptr()
    заключается в тестировании алгоритма блочного шифрования на заданных (тестовых)
    значениях ключей.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param size Размер области памяти, содержащей значение ключа.
    @param cflag Флаг владения данными. Если он истинен, то данные копируются в область памяти,
    которой владеет ключевой контекст.

    @return Функция возвращает код ошибки. В случае успеха возвращается \ref ak_error_ok.          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_ptr( ak_bckey bkey,
                                   const ak_pointer keyptr, const size_t size, const ak_bool cflag )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to secret key context" );
  if( keyptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                  "using null pointer to key data" );
  if( size != bkey->key.key.size ) return ak_error_message( ak_error_wrong_length, __func__,
                                          "using a constant value of secret key with wrong length" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_set_ptr( &bkey->key, keyptr, size, cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of key data" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) bkey->schedule_keys( &bkey->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа алгоритма блочного шифрования случайное
    или псевдо-случайным значение, вырабатываемой заданным генератором. Размер вырабатываемого
    значения определяется длиной ключа.

    Перед присвоением ключа контекст должен быть инициализирован.
    После присвоения ключа производится его маскирование и выработка контрольной суммы.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param generator Rонтекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_random( ak_bckey bkey, ak_random generator )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to random number generator" );
 /* вырабатываем ключевой буффер */
  if(( error = ak_skey_set_random( &bkey->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect generation of secret key random value" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) bkey->schedule_keys( &bkey->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи алгоритма,
    описанного  в рекомендациях по стандартизации Р 50.1.111-2016.

    Пароль является секретным значением и должен быть не пустой строкой символов в формате utf8.
    Используемое при выработке ключа значение инициализационного вектора может быть не секретным.
    Перед присвоением ключа контекст должен быть инициализирован.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param pass Пароль, представленный в виде строки символов в формате utf8.
    @param pass_size Длина пароля в байтах
    @param salt Инициализационный вектор, представленный в виде строки символов.
    @param salt_size Длина инициализационного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_password( ak_bckey bkey, const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to block cipher key context" );
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                  "using null pointer to password" );
  if( pass_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                                 "using password with zero length" );
  if( salt == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector" );
  if( salt_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using initial vector with zero length" );
 /* вырабатываем ключевой буффер */
  if(( error = ak_skey_set_password( &bkey->key, pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect generation of secret key random value" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) bkey->schedule_keys( &bkey->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                        теперь режимы шифрования                                 */
/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование информации
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах). Для режима простой замены
    длина зашифровываемых данных должна быть кратна длине блока.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_encrypt_ecb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  ak_int64 blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->ivector.size != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = (ak_uint64 ) size/bkey->ivector.size;
  if( bkey->key.resource.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= blocks;

 /* теперь приступаем к зашифрованию данных */
  if( bkey->ivector.size == 8 ) { /* здесь длина блока равна 64 бита */
    do {
        bkey->encrypt( &bkey->key, inptr++, outptr++ );
    } while( --blocks > 0 );
  }
  if( bkey->ivector.size == 16 ) { /* здесь длина блока равна 128 бит */
    do {
        bkey->encrypt( &bkey->key, inptr, outptr );
        inptr+=2; outptr+=2;
    } while( --blocks > 0 );
  }

  /* перемаскируем ключ */
  if( bkey->key.remask( &bkey->key ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Ключ алгоритма блочного шифрования, на котором происходит расшифрование информации
    @param in Указатель на область памяти, где хранятся входные (расшифровываемые) данные
    @param out Указатель на область памяти, куда помещаются расшифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер расшировываемых данных (в байтах). Для режима простой замены
    длина расшифровываемых данных должна быть кратна длине блока.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_decrypt_ecb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  ak_int64 blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->ivector.size != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = (ak_uint64 ) size/bkey->ivector.size;
  if( bkey->key.resource.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= blocks;

 /* теперь приступаем к расшифрованию данных */
  if( bkey->ivector.size == 8 ) { /* здесь длина блока равна 64 бита */
    do {
        bkey->decrypt( &bkey->key, inptr++, outptr++ );
    } while( --blocks > 0 );
  }
  if( bkey->ivector.size == 16 ) { /* здесь длина блока равна 128 бит */
    do {
        bkey->decrypt( &bkey->key, inptr, outptr );
        inptr+=2; outptr+=2;
    } while( --blocks > 0 );
  }

  /* перемаскируем ключ */
  if( bkey->key.remask( &bkey->key ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Поскольку операцией заширования является гаммирование (сложение открытого текста по модулю два
    с последовательностью, вырабатываемой шифром), то операция расшифрования производится также
    наложением гаммы по модулю два. Таким образом, для зашифрования и расшифрования
    информациии используется одна и таже функция.

    @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование/расшифрование информации.
    @param in Указатель на область памяти, где хранятся входные (открытые) данные.
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in).
    @param size Размер зашировываемых данных (в байтах).
    @param iv Синхропосылка. Согласно  стандарту ГОСТ Р 34.13-2015 длина синхропосылки должна быть
    ровно в два раза меньше, чем длина блока, то есть 4 байта для Магмы и 8 байт для Кузнечика.
    @param iv_size Длина синхропосылки (в байтах).

    Значение синхропосылки преобразуется и сохраняется в контексте секретного ключа. Данное значение
    может быть использовано в дальнейшем при вызове функции ak_bckey_xcrypt_update().

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_xcrypt( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                     ak_pointer iv, size_t iv_size )
{
  ak_int64 blocks = (ak_int64)size/bkey->ivector.size,
            tail = (ak_int64)size%bkey->ivector.size;
  ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                   "incorrect integrity code of secret key value" );
 /* проверяем длину синхропосылки (если меньше половины блока, то плохо)
    если больше - то лишнее не используется */
  if( iv_size < ( bkey->ivector.size >> 1 ))
    return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                              "incorrect length of initial value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource,
                                                    __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= ( blocks + ( tail > 0 )); /* уменьшаем ресурс ключа */

 /* теперь приступаем к зашифрованию данных */
  if( bkey->key.flags&ak_flag_xcrypt_update ) bkey->key.flags ^= ak_flag_xcrypt_update;
  memset( bkey->ivector.data, 0, bkey->ivector.size );

  if( blocks ) {
   /* здесь длина блока равна 64 бита */
    if( bkey->ivector.size == 8 ) {
      memcpy( ((ak_uint8 *)bkey->ivector.data)+4, iv, 4 );
      do {
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0];
          outptr++; inptr++; ((ak_uint64 *)bkey->ivector.data)[0]++;
      } while( --blocks > 0 );
    }

   /* здесь длина блока равна 128 бит */
    if( bkey->ivector.size == 16 ) {
      memcpy( ((ak_uint8 *)bkey->ivector.data)+8, iv, 8 );
      do {
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
          *outptr = *inptr ^ yaout[1]; outptr++; inptr++;
          ((ak_uint64 *)bkey->ivector.data)[0]++; // здесь мы не учитываем знак переноса
                                                  // потому что объем данных на одном ключе не должен превышать
                                                  // 2^64 блоков (контролируется через ресурс ключа)
      } while( --blocks > 0 );
    }
  }

  if( tail ) { /* на последок, мы обрабатываем хвост сообщения */
    size_t i;
    bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
    for( i = 0; i < tail; i++ )
        ( (ak_uint8*)outptr )[i] = ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];
   /* запрещаем дальнейшее использование xcrypt_update для данных, длина которых не кратна длине блока */
    memset( bkey->ivector.data, 0, bkey->ivector.size );
    bkey->key.flags |= ak_flag_xcrypt_update;
  }

 /* перемаскируем ключ */
  if( bkey->key.remask( &bkey->key ) != ak_error_ok )
    return ak_error_message( ak_error_get_value(), __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция позволяет зашифровывать/расшифровывать данные после вызова функции ak_bckey_xcrypt()
    со значением синхропосылки, выработанной в ходе предыдущего вызова. Это позволяет
    зашифровывать/расшифровывать данные поступающие блоками, длина которых кратна длине блока
    используемого алгоритма блочного шифрования.

    @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование информации
    @param in Указатель на область памяти, где хранятся входные (открытые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_xcrypt_update( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  ak_int64 blocks = (ak_int64)size/bkey->ivector.size,
            tail = (ak_int64)size%bkey->ivector.size;
  ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* проверяем, что мы можем использовать данный режим */
  if( bkey->key.flags&ak_flag_xcrypt_update )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                  "using this function with previously incorrect xcrypt operation");
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                   "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource,
                                                    __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= ( blocks + ( tail > 0 )); /* уменьшаем ресурс ключа */

 /* теперь приступаем к зашифрованию данных */
  if( blocks ) {
    if( bkey->ivector.size == 8 ) { /* здесь длина блока равна 64 бита */
      do {
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0];
          outptr++; inptr++; ((ak_uint64 *)bkey->ivector.data)[0]++;
      } while( --blocks > 0 );
    }

    if( bkey->ivector.size == 16 ) { /* здесь длина блока равна 128 бит */
      do {
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
          *outptr = *inptr ^ yaout[1]; outptr++; inptr++;
          ((ak_uint64 *)bkey->ivector.data)[0]++;
        } while( --blocks > 0 );
    }
  }

  if( tail ) { /* на последок, мы обрабатываем хвост сообщения */
    size_t i;
    bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
    for( i = 0; i < tail; i++ )
        ( (ak_uint8*)outptr )[i] = ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];
    memset( bkey->ivector.data, 0, bkey->ivector.size );
    bkey->key.flags |= ak_flag_xcrypt_update;
  }

 /* перемаскируем ключ */
  if( bkey->key.remask( &bkey->key ) != ak_error_ok )
    return ak_error_message( ak_error_get_value(), __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* предварительные описания функций, используемых в ak_bckey_context_xcrypt_acpkm
   и ak_bckey_context_xcrypt_acpkm_update */
 void ak_magma_encrypt_acpkm_with_mask( ak_skey , ak_pointer , ak_pointer , ak_pointer );
 void ak_kuznechik_encrypt_acpkm_with_mask( ak_skey , ak_pointer , ak_pointer , ak_pointer );
 void ak_kuznechik_schedule_keys_without_allocation( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, предназначенная для режима CTR-ACPKM */
 struct acpkm {
  /*! \brief Размер всей структуры */
   ak_uint64 size;
  /*! \brief Количество блоков в секции */
   ak_int64 amount;
  /*! \brief Позиция внутри секции */
   ak_int64 counter;
  /*! \brief Ключ */
   ak_uint8 key[32];
  /*! \brief Раундовые ключи Кузнечика */
   ak_uint64 expanded_keys[];
};

/* ----------------------------------------------------------------------------------------------- */
/*! Поскольку операцией заширования является гаммирование (сложение открытого текста по модулю два
    с последовательностью, вырабатываемой шифром), то операция расшифрования производится также
    наложением гаммы по модулю два. Таким образом, для зашифрования и расшифрования
    информациии используется одна и таже функция.

    @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование/расшифрование
    информации.
    @param in Указатель на область памяти, где хранятся входные (открытые) данные.
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in).
    @param size Размер зашировываемых данных (в байтах).
    @param iv Синхропосылка. Согласно  стандарту ГОСТ Р 34.13-2015 длина синхропосылки должна быть
    ровно в два раза меньше, чем длина блока, то есть 4 байта для Магмы и 8 байт для Кузнечика.
    @param iv_size Длина синхропосылки (в байтах).
    @param n_size Длина секции (в байтах).

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_xcrypt_acpkm( ak_bckey bkey, ak_pointer in, ak_pointer out, const size_t size,
                                                                ak_pointer iv, const size_t iv_size,
                                                                                const size_t n_size )
{
  ak_int64 blocks = (ak_int64)size/bkey->ivector.size,
            tail = (ak_int64)size%bkey->ivector.size,
            amount = (ak_int64)n_size/bkey->ivector.size,
            counter;
  size_t i;
  ak_uint64 yaout[4], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
  ak_pointer key_data[2] = { bkey->key.key.data, bkey->key.data };

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                    "incorrect integrity code of secret key value" );
 /* проверяем длину синхропосылки (если меньше половины блока, то плохо,
    если больше - то лишнее не используется) */
  if( iv_size < ( bkey->ivector.size >> 1 ))
    return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                               "incorrect length of initial value" );
 /* проверяем длину секции на кратность длине блока */
  if( (ak_int64)n_size%bkey->ivector.size != 0 )
    return ak_error_message( ak_error_wrong_length, __func__, "incorrect length of section value" );
 /* уменьшаем значение ресурса ключа */
  counter = ak_min( blocks + (tail > 0), amount );
  if( bkey->key.resource.counter < counter )
    return ak_error_message( ak_error_low_key_resource,
                                                      __func__, "low resource of block cipher key" );
   else bkey->key.resource.counter -= counter; /* уменьшаем ресурс ключа */
 /* выставляем флаг уменьшения ресурса ключа в xcrypt_acpkm_update */
  if( !tail && counter < amount )
    bkey->key.flags |= ak_flag_xcrypt_acpkm_resource;

 /* создаем буфер для хранения преобразованного ключа */
  if( bkey->data != NULL ) {
    ak_ptr_wipe( bkey->data, ((struct acpkm *)bkey->data)->size, &bkey->key.generator );
    free( bkey->data );
  }
  if( bkey->ivector.size == 8 ) {
    bkey->data = malloc( 56 );
    ((struct acpkm *)bkey->data)->size = 56;
  }
  if( bkey->ivector.size == 16 ) {
   /* выделяем память с учетом раундовых ключей */
    bkey->data =
#ifdef LIBAKRYPT_HAVE_STDALIGN
    aligned_alloc( 16,
#else
    malloc(
#endif
    704 );
    ((struct acpkm *)bkey->data)->size = 704;
   /* копируем раундовые ключи */
    memcpy( ((struct acpkm *)bkey->data)->expanded_keys + 1, bkey->key.data, 640 );
   /* меняем место нахождения раундовых ключей */
    bkey->key.data = ((struct acpkm *)bkey->data)->expanded_keys + 1;
  }
 /* копируем исходный ключ */
  memcpy( ((struct acpkm *)bkey->data)->key, bkey->key.key.data, 32 );
 /* меняем указатель, где хранится ключ */
  bkey->key.key.data = ((struct acpkm *)bkey->data)->key;

 /* теперь приступаем к зашифрованию данных */
  if( bkey->key.flags&ak_flag_xcrypt_acpkm_update )
    bkey->key.flags ^= ak_flag_xcrypt_acpkm_update;
  counter = 0;
  memset( bkey->ivector.data, 0, bkey->ivector.size );

  if( blocks ) {
   /* здесь длина блока равна 64 бита */
    if( bkey->ivector.size == 8 ) {
      memcpy( ((ak_uint8 *)bkey->ivector.data)+4, iv, 4 );
      do {
          if( counter == amount ) { /* преобразование ключа ACPKM */
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[8], &yaout[1],
                                                               (ak_uint8 *)bkey->key.mask.data + 8 );
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[24], &yaout[3],
                                                              (ak_uint8 *)bkey->key.mask.data + 24 );
            memcpy( bkey->key.key.data, yaout, 32 );
           /* зачищаем значение ключа, которое больше не нужно */
            ak_ptr_wipe( yaout, 32, &bkey->key.generator );
            counter = 0;
          }
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0];
          outptr++; inptr++; ((ak_uint64 *)bkey->ivector.data)[0]++;
          counter++;
      } while( --blocks > 0 );
    }

   /* здесь длина блока равна 128 бит */
    if( bkey->ivector.size == 16 ) {
      memcpy( ((ak_uint8 *)bkey->ivector.data)+8, iv, 8 );
      do {
          if( counter == amount ) { /* преобразование ключа ACPKM */
            ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
            ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
            memcpy( bkey->key.key.data, yaout, 32 );
           /* зачищаем значение ключа, которое больше не нужно */
            ak_ptr_wipe( yaout, 32, &bkey->key.generator );
            ak_kuznechik_schedule_keys_without_allocation( &bkey->key );
            counter = 0;
          }
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
          *outptr = *inptr ^ yaout[1]; outptr++; inptr++;
          ((ak_uint64 *)bkey->ivector.data)[0]++;
          counter++;
      } while( --blocks > 0 );
    }
  }

  if( tail ) { /* напоследок, мы обрабатываем хвост сообщения */
    /* преобразование ключа ACPKM */
    if( counter == amount ) {
      if( bkey->ivector.size == 8 ) {
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[8], &yaout[1],
                                                               (ak_uint8 *)bkey->key.mask.data + 8 );
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[24], &yaout[3],
                                                              (ak_uint8 *)bkey->key.mask.data + 24 );
        memcpy( bkey->key.key.data, yaout, 32 );
       /* зачищаем значение ключа, которое больше не нужно */
        ak_ptr_wipe( yaout, 32, &bkey->key.generator );
        counter = 0;
      }
      if( bkey->ivector.size == 16 ) {
        ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
        ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
        memcpy( bkey->key.key.data, yaout, 32 );
       /* зачищаем значение ключа, которое больше не нужно */
        ak_ptr_wipe( yaout, 32, &bkey->key.generator );
        ak_kuznechik_schedule_keys_without_allocation( &bkey->key );
        counter = 0;
      }
    }
    bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
    for( i = 0; i < tail; i++ )
        ((ak_uint8 *)outptr)[i] = ((ak_uint8 *)inptr)[i]^((ak_uint8 *)yaout)[i];

   /* запрещаем дальнейшее использование xcrypt_acpkm_update для данных, длина которых не кратна
      длине блока */
    memset( bkey->ivector.data, 0, bkey->ivector.size );
    bkey->key.flags |= ak_flag_xcrypt_acpkm_update;
   /* восстанавливаем исходные значения ключей и удаляем буфер */
    bkey->key.key.data = key_data[0];
    bkey->key.data = key_data[1];
    ak_ptr_wipe( bkey->data, ((struct acpkm *)bkey->data)->size, &bkey->key.generator );
    free( bkey->data );
   /* перемаскируем ключ */
    bkey->key.remask( &bkey->key );
  } else {
          /* перемаскируем ключи */
           if( bkey->ivector.size == 8 ) {
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)key_data[0])[i] += ((ak_uint32 *)bkey->key.key.data)[i];
               ((ak_uint32 *)key_data[0])[i] -= ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)key_data[0])[i] -= ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)bkey->key.key.data)[i] += ((ak_uint32 *)key_data[0])[i];
             }
             bkey->key.remask( &bkey->key );
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)bkey->key.key.data)[i] -= ((ak_uint32 *)key_data[0])[i];
               ((ak_uint32 *)key_data[0])[i] += ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)key_data[0])[i] += ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)key_data[0])[i] -= ((ak_uint32 *)bkey->key.key.data)[i];
             }
           }
           if( bkey->ivector.size == 16 ) {
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)key_data[0])[i] ^= ((ak_uint32 *)bkey->key.key.data)[i];
               ((ak_uint32 *)bkey->key.key.data)[i] ^= ((ak_uint32 *)key_data[0])[i];
             }
             bkey->key.remask( &bkey->key );
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)bkey->key.key.data)[i] ^= ((ak_uint32 *)key_data[0])[i];
               ((ak_uint32 *)key_data[0])[i] ^= ((ak_uint32 *)bkey->key.key.data)[i];
             }
           }
          /* восстанавливаем исходные значения ключей и записываем данные, необходимые
             для xcrypt_acpkm_update */
           bkey->key.key.data = key_data[0];
           bkey->key.data = key_data[1];
           ((struct acpkm *)bkey->data)->amount = amount;
           ((struct acpkm *)bkey->data)->counter = counter;
         }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция позволяет зашифровывать/расшифровывать данные после вызова функции ak_bckey_xcrypt_acpkm()
    со значением синхропосылки, выработанной в ходе предыдущего вызова. Это позволяет
    зашифровывать/расшифровывать данные поступающие блоками, длина которых кратна длине блока
    используемого алгоритма блочного шифрования.

    @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование информации
    @param in Указатель на область памяти, где хранятся входные (открытые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_xcrypt_acpkm_update( ak_bckey bkey, ak_pointer in, ak_pointer out,
                                                                                  const size_t size )
{
  ak_int64 blocks = (ak_int64)size/bkey->ivector.size,
            tail = (ak_int64)size%bkey->ivector.size;
  size_t i;
  ak_uint64 yaout[4], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
  struct acpkm *data_ptr = (struct acpkm *)bkey->data;
  ak_pointer key_data[2] = { bkey->key.key.data, bkey->key.data };

 /* проверяем, что мы можем использовать данный режим */
  if( bkey->key.flags&ak_flag_xcrypt_acpkm_update || bkey->data == NULL )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__,
                            "using this function with previously incorrect xcrypt_acpkm operation" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                    "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.flags&ak_flag_xcrypt_acpkm_resource ) {
    ak_int64 counter = ak_min( blocks + (tail > 0), data_ptr->amount - data_ptr->counter );
    if( bkey->key.resource.counter < counter )
      return ak_error_message( ak_error_low_key_resource,
                                                      __func__, "low resource of block cipher key" );
     else bkey->key.resource.counter -= counter; /* уменьшаем ресурс ключа */
    if( counter == data_ptr->amount - data_ptr->counter )
      bkey->key.flags ^= ak_flag_xcrypt_acpkm_resource;
  }

 /* меняем указатели, где хранятся ключи */
  bkey->key.key.data = data_ptr->key;
  bkey->key.data = data_ptr->expanded_keys + 1;

 /* теперь приступаем к зашифрованию данных */
  if( blocks ) {
   /* здесь длина блока равна 64 бита */
    if( bkey->ivector.size == 8 ) {
      do {
          if( data_ptr->counter == data_ptr->amount ) { /* преобразование ключа ACPKM */
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[8], &yaout[1], 
                                                               (ak_uint8 *)bkey->key.mask.data + 8 );
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
            ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[24], &yaout[3],
                                                              (ak_uint8 *)bkey->key.mask.data + 24 );
            memcpy( bkey->key.key.data, yaout, 32 );
           /* зачищаем значение ключа, которое больше не нужно */
            ak_ptr_wipe( yaout, 32, &bkey->key.generator );
            data_ptr->counter = 0;
          }
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0];
          outptr++; inptr++; ((ak_uint64 *)bkey->ivector.data)[0]++;
          data_ptr->counter++;
      } while( --blocks > 0 );
    }

   /* здесь длина блока равна 128 бит */
    if( bkey->ivector.size == 16 ) {
      do {
          if( data_ptr->counter == data_ptr->amount ) { /* преобразование ключа ACPKM */
            ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
            ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
            memcpy( bkey->key.key.data, yaout, 32 );
           /* зачищаем значение ключа, которое больше не нужно */
            ak_ptr_wipe( yaout, 32, &bkey->key.generator );
            ak_kuznechik_schedule_keys_without_allocation( &bkey->key );
            data_ptr->counter = 0;
          }
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
          *outptr = *inptr ^ yaout[1]; outptr++; inptr++;
          ((ak_uint64 *)bkey->ivector.data)[0]++;
          data_ptr->counter++;
      } while( --blocks > 0 );
    }
  }

  if( tail ) { /* напоследок, мы обрабатываем хвост сообщения */
    /* преобразование ключа ACPKM */
    if( data_ptr->counter == data_ptr->amount ) {
      if( bkey->ivector.size == 8 ) {
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[8], &yaout[1],
                                                               (ak_uint8 *)bkey->key.mask.data + 8 );
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
        ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[24], &yaout[3],
                                                              (ak_uint8 *)bkey->key.mask.data + 24 );
        memcpy( bkey->key.key.data, yaout, 32 );
       /* зачищаем значение ключа, которое больше не нужно */
        ak_ptr_wipe( yaout, 32, &bkey->key.generator );
        data_ptr->counter = 0;
      }
      if( bkey->ivector.size == 16 ) {
        ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
        ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
        memcpy( bkey->key.key.data, yaout, 32 );
       /* зачищаем значение ключа, которое больше не нужно */
        ak_ptr_wipe( yaout, 32, &bkey->key.generator );
        ak_kuznechik_schedule_keys_without_allocation( &bkey->key );
        data_ptr->counter = 0;
      }
    }
    bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
    for( i = 0; i < tail; i++ )
        ((ak_uint8 *)outptr)[i] = ((ak_uint8 *)inptr)[i]^((ak_uint8 *)yaout)[i];

   /* запрещаем дальнейшее использование xcrypt_acpkm_update для данных, длина которых не кратна
      длине блока */
    memset( bkey->ivector.data, 0, bkey->ivector.size );
    bkey->key.flags |= ak_flag_xcrypt_acpkm_update;
   /* восстанавливаем исходные значения ключей и удаляем буфер */
    bkey->key.key.data = key_data[0];
    bkey->key.data = key_data[1];
    ak_ptr_wipe( bkey->data, data_ptr->size, &bkey->key.generator );
    free( bkey->data );
   /* перемаскируем ключ */
    bkey->key.remask( &bkey->key );
  } else {
          /* перемаскируем ключи */
           if( bkey->ivector.size == 8 ) {
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)key_data[0])[i] += ((ak_uint32 *)bkey->key.key.data)[i];
               ((ak_uint32 *)key_data[0])[i] -= ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)key_data[0])[i] -= ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)bkey->key.key.data)[i] += ((ak_uint32 *)key_data[0])[i];
             }
             bkey->key.remask( &bkey->key );
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)bkey->key.key.data)[i] -= ((ak_uint32 *)key_data[0])[i];
               ((ak_uint32 *)key_data[0])[i] += ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)key_data[0])[i] += ((ak_uint32 *)bkey->key.mask.data)[i];
               ((ak_uint32 *)key_data[0])[i] -= ((ak_uint32 *)bkey->key.key.data)[i];
             }
           }
           if( bkey->ivector.size == 16 ) {
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)key_data[0])[i] ^= ((ak_uint32 *)bkey->key.key.data)[i];
               ((ak_uint32 *)bkey->key.key.data)[i] ^= ((ak_uint32 *)key_data[0])[i];
             }
             bkey->key.remask( &bkey->key );
             for( i = 0; i < 8; i++ ) {
               ((ak_uint32 *)bkey->key.key.data)[i] ^= ((ak_uint32 *)key_data[0])[i];
               ((ak_uint32 *)key_data[0])[i] ^= ((ak_uint32 *)bkey->key.key.data)[i];
             }
           }
          /* восстанавливаем исходные значения ключей */
           bkey->key.key.data = key_data[0];
           bkey->key.data = key_data[1];
         }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_xcrypt_acpkm_with_mask( ak_bckey bkey, ak_pointer out1, ak_pointer out2,
                                                               ak_pointer mask, const size_t n_size )
{
  ak_int64 blocks = 7 - ( bkey->ivector.size >> 2 ),
            amount = (ak_int64)n_size/bkey->ivector.size,
            counter;
  ak_uint64 yaout[4], *outptr = (ak_uint64 *)out1 + 2, *maskptr = (ak_uint64 *)mask + 2;
  ak_pointer key_data[2] = { bkey->key.key.data, bkey->key.data };

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                    "incorrect integrity code of secret key value" );
 /* проверяем длину секции на кратность длине блока */
  if( (ak_int64)n_size%bkey->ivector.size != 0 )
    return ak_error_message( ak_error_wrong_length, __func__, "incorrect length of section value" );
 /* уменьшаем значение ресурса ключа */
  counter = ak_min( blocks, amount );
  if( bkey->key.resource.counter < counter )
    return ak_error_message( ak_error_low_key_resource,
                                                      __func__, "low resource of block cipher key" );
   else bkey->key.resource.counter -= counter; /* уменьшаем ресурс ключа */
 /* выставляем флаг уменьшения ресурса ключа в xcrypt_acpkm_update */
  if( counter < amount )
    bkey->key.flags |= ak_flag_xcrypt_acpkm_resource;

 /* создаем буфер для хранения преобразованного ключа */
  if( bkey->data != NULL ) {
    ak_ptr_wipe( bkey->data, ((struct acpkm *)bkey->data)->size, &bkey->key.generator );
    free( bkey->data );
  }
  if( bkey->ivector.size == 8 ) {
    bkey->data = malloc( 56 );
    ((struct acpkm *)bkey->data)->size = 56;
  }
  if( bkey->ivector.size == 16 ) {
   /* выделяем память с учетом раундовых ключей */
    bkey->data =
#ifdef LIBAKRYPT_HAVE_STDALIGN
    aligned_alloc( 16,
#else
    malloc(
#endif
    704 );
    ((struct acpkm *)bkey->data)->size = 704;
   /* копируем раундовые ключи */
    memcpy( ((struct acpkm *)bkey->data)->expanded_keys + 1, bkey->key.data, 640 );
   /* меняем место нахождения раундовых ключей */
    bkey->key.data = ((struct acpkm *)bkey->data)->expanded_keys + 1;
  }
 /* копируем исходный ключ */
  memcpy( ((struct acpkm *)bkey->data)->key, bkey->key.key.data, 32 );
 /* меняем указатель, где хранится ключ */
  bkey->key.key.data = ((struct acpkm *)bkey->data)->key;

 /* теперь приступаем к зашифрованию данных */
  counter = 0;
  memset( bkey->ivector.data, 0, bkey->ivector.size );
 /* здесь длина блока равна 64 бита */
  if( bkey->ivector.size == 8 ) {
    outptr++;
    maskptr++;
    memset( ((ak_uint8 *)bkey->ivector.data)+4, 0xff, 4 );
    do {
        if( counter == amount ) { /* преобразование ключа ACPKM */
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[8], &yaout[1],
                                                               (ak_uint8 *)bkey->key.mask.data + 8 );
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[24], &yaout[3],
                                                              (ak_uint8 *)bkey->key.mask.data + 24 );
          memcpy( bkey->key.key.data, yaout, 32 );
         /* зачищаем значение ключа, которое больше не нужно */
          ak_ptr_wipe( yaout, 32, &bkey->key.generator );
          counter = 0;
        }
        if( blocks == 1 )
          bkey->encrypt( &bkey->key, bkey->ivector.data, out2 );
        else {
               ak_magma_encrypt_acpkm_with_mask( &bkey->key, bkey->ivector.data, outptr, maskptr );
               outptr--; maskptr--;
             }
        ((ak_uint64 *)bkey->ivector.data)[0]++;
        counter++;
    } while( --blocks > 0 );
  }

 /* здесь длина блока равна 128 бит */
  if( bkey->ivector.size == 16 ) {
    memset( ((ak_uint8 *)bkey->ivector.data)+8, 0xff, 8 );
    do {
        if( counter == amount ) { /* преобразование ключа ACPKM */
          ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
          ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
          memcpy( bkey->key.key.data, yaout, 32 );
         /* зачищаем значение ключа, которое больше не нужно */
          ak_ptr_wipe( yaout, 32, &bkey->key.generator );
          ak_kuznechik_schedule_keys_without_allocation( &bkey->key );
          counter = 0;
        }
        if( blocks == 1 )
          bkey->encrypt( &bkey->key, bkey->ivector.data, out2 );
        else {
               ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, bkey->ivector.data, outptr,
                                                                                           maskptr );
               outptr--; maskptr--;
               outptr--; maskptr--;
             }
        ((ak_uint64 *)bkey->ivector.data)[0]++;
        counter++;
    } while( --blocks > 0 );
  }

 /* восстанавливаем исходные значения ключей и записываем данные,
    необходимые для xcrypt_acpkm_with_mask_update */
  bkey->key.key.data = key_data[0];
  bkey->key.data = key_data[1];
  ((struct acpkm *)bkey->data)->amount = amount;
  ((struct acpkm *)bkey->data)->counter = counter;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_xcrypt_acpkm_with_mask_update( ak_bckey bkey, ak_pointer out1, ak_pointer out2,
                                                                                    ak_pointer mask )
{
  ak_int64 blocks = 7 - ( bkey->ivector.size >> 2 );
  ak_uint64 yaout[4], *outptr = (ak_uint64 *)out1 + 2, *maskptr = (ak_uint64 *)mask + 2;
  struct acpkm *data_ptr = (struct acpkm *)bkey->data;
  ak_pointer key_data[2] = { bkey->key.key.data, bkey->key.data };

 /* проверяем, что мы можем использовать данную функцию */
  if( bkey->data == NULL )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__,
                  "using this function with previously incorrect xcrypt_acpkm_with_mask operation" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                    "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.flags&ak_flag_xcrypt_acpkm_resource ) {
    ak_int64 counter = ak_min( blocks, data_ptr->amount - data_ptr->counter );
    if( bkey->key.resource.counter < counter )
      return ak_error_message( ak_error_low_key_resource,
                                                      __func__, "low resource of block cipher key" );
     else bkey->key.resource.counter -= counter; /* уменьшаем ресурс ключа */
    if( counter == data_ptr->amount - data_ptr->counter )
      bkey->key.flags ^= ak_flag_xcrypt_acpkm_resource;
  }

 /* меняем указатели, где хранятся ключи */
  bkey->key.key.data = data_ptr->key;
  bkey->key.data = data_ptr->expanded_keys + 1;

 /* теперь приступаем к зашифрованию данных */

 /* здесь длина блока равна 64 бита */
  if( bkey->ivector.size == 8 ) {
    outptr++;
    maskptr++;
    do {
        if( data_ptr->counter == data_ptr->amount ) { /* преобразование ключа ACPKM */
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[8], &yaout[1],
                                                               (ak_uint8 *)bkey->key.mask.data + 8 );
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
          ak_magma_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[24], &yaout[3],
                                                              (ak_uint8 *)bkey->key.mask.data + 24 );
          memcpy( bkey->key.key.data, yaout, 32 );
         /* зачищаем значение ключа, которое больше не нужно */
          ak_ptr_wipe( yaout, 32, &bkey->key.generator );
          data_ptr->counter = 0;
        }
        if( blocks == 1 )
          bkey->encrypt( &bkey->key, bkey->ivector.data, out2 );
        else {
               ak_magma_encrypt_acpkm_with_mask( &bkey->key, bkey->ivector.data, outptr, maskptr );
               outptr--; maskptr--;
             }
        ((ak_uint64 *)bkey->ivector.data)[0]++;
        data_ptr->counter++;
    } while( --blocks > 0 );
  }

 /* здесь длина блока равна 128 бит */
  if( bkey->ivector.size == 16 ) {
    do {
        if( data_ptr->counter == data_ptr->amount ) { /* преобразование ключа ACPKM */
          ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[0], &yaout[0],
                                                                               bkey->key.mask.data );
          ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, (ak_pointer)&acpkm_d[16], &yaout[2],
                                                              (ak_uint8 *)bkey->key.mask.data + 16 );
          memcpy( bkey->key.key.data, yaout, 32 );
         /* зачищаем значение ключа, которое больше не нужно */
          ak_ptr_wipe( yaout, 32, &bkey->key.generator );
          ak_kuznechik_schedule_keys_without_allocation( &bkey->key );
          data_ptr->counter = 0;
        }
        if( blocks == 1 )
          bkey->encrypt( &bkey->key, bkey->ivector.data, out2 );
        else {
               ak_kuznechik_encrypt_acpkm_with_mask( &bkey->key, bkey->ivector.data, outptr,
                                                                                           maskptr );
               outptr--; maskptr--;
               outptr--; maskptr--;
             }
        ((ak_uint64 *)bkey->ivector.data)[0]++;
        data_ptr->counter++;
    } while( --blocks > 0 );
  }

 /* восстанавливаем исходные значения ключей */
  bkey->key.key.data = key_data[0];
  bkey->key.data = key_data[1];

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-bckey-internal.c                                                              */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_bckey.c  */
/* ----------------------------------------------------------------------------------------------- */
