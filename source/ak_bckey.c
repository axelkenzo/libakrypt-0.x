/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
 #include <ak_skey.h>

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

 /* теперь инициализируем данные */
  if(( error = ak_skey_create( &bkey->key, keysize )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of secret key" );

  bkey->block_size =    blocksize;
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param keysize длина ключа в байтах
    @param blocksize длина блока обрабатываемых данных в байтах
    @return В случае успеха функция возвращает указатель на созданный контекст ключа.
    В противном случае, возвращается NULL. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value()                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new( size_t keysize, size_t blocksize )
{
  ak_bckey bkey = NULL;
  int error = ak_error_ok;

  if(( bkey = ( ak_bckey ) malloc( sizeof( struct bckey ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
    return NULL;
  }
  if(( error = ak_bckey_create( bkey, keysize, blocksize )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of block cipher key context" );
    return( bkey = ak_bckey_delete( bkey ));
  }
 return bkey;
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
  if(( error = ak_skey_destroy( &bkey->key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wronf deleting a secret key" );
  }

  bkey->block_size =      0;
  bkey->encrypt =      NULL;
  bkey->decrypt =      NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =  NULL;

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
/*                                        теперь режимы шифрования                                 */
/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование информации
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_ecb( ak_bckey bkey,
                                                        ak_pointer in, ak_pointer out, size_t size )
{
  ak_uint64 blocks = 0, *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->block_size != 0 ) return ak_error_message( ak_error_block_cipher_length,
                          __func__ , "the length of input data is not divided by block length" );

 /* уменьшаем значение ресурса ключа */
  blocks = (ak_uint64 ) size/bkey->block_size;
  if( bkey->key.resource.counter < blocks ) return ak_error_message( ak_error_low_key_resource,
                                                 __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= blocks;

 /* теперь приступаем к зашифрованию данных */
  if( bkey->block_size == 8 ) { /* здесь длина блока равна 64 бита */
    do {
        bkey->encrypt( &bkey->key, inptr++, outptr++ );
    } while( --blocks > 0 );
  }
  if( bkey->block_size == 16 ) { /* здесь длина блока равна 128 бит */
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
    @param out Указатель на область памяти, куда помещаются расшифровыванные данные
    (этот указатель может совпадать с in)
    @param size Размер расшифровываемых данных (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_ecb( ak_bckey bkey,
                                                        ak_pointer in, ak_pointer out, size_t size )
{
  ak_uint64 blocks = 0, *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->block_size != 0 ) return ak_error_message( ak_error_block_cipher_length,
                          __func__ , "the length of input data is not divided on block length" );

 /* уменьшаем значение ресурса ключа */
  blocks = (ak_uint64 ) size/bkey->block_size;
  if( bkey->key.resource.counter < blocks ) return ak_error_message( ak_error_low_key_resource,
                                                 __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= blocks;

 /* теперь приступаем к расшифрованию данных */
  if( bkey->block_size == 8 ) { /* здесь длина блока равна 64 бита */
    do {
        bkey->decrypt( &bkey->key, inptr++, outptr++ );
    } while( --blocks > 0 );
  }
  if( bkey->block_size == 16 ) { /* здесь длина блока равна 128 бит */
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

    @param bkey Ключ алгоритма блочного шифрования, на котором происходит зашифрование информации
    @param in Указатель на область памяти, где хранятся входные (открытые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах)
    @param iv Синхропосылка. Согласно  стандарту ГОСТ Р 34.12-2015 длина синхропосылки должна быть
    ровно в два раза меньше, чем длина блока, то есть 4 байта для Магмы и 8 байт для Кузнечика.
    Поскольку длина блока может быть получена через указатель bkey, то длина синхропосылки
    в функцию не передается.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_xcrypt_ctr( ak_bckey bkey,
                                         ak_pointer in, ak_pointer out, size_t size, ak_pointer iv )
{
  ak_uint64 blocks = (ak_uint64)size/bkey->block_size,
            tail = (ak_uint64)size%bkey->block_size;
  ak_uint64 yain[2], yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource,
                                                    __func__ , "low resource of block cipher key" );
   else bkey->key.resource.counter -= ( blocks + ( tail > 0 )); /* уменьшаем ресурс ключа */

 /* теперь приступаем к зашифрованию данных */
  if( bkey->block_size == 8 ) { /* здесь длина блока равна 64 бита */
    memcpy( &yain, iv, 4 );
    yain[0] <<= 32;
    do {
        bkey->encrypt( &bkey->key, yain, yaout );
        *outptr = *inptr ^ yaout[0];
        outptr++; inptr++; yain[0]++;
    } while( --blocks > 0 );
  }

  if( bkey->block_size == 16 ) { /* здесь длина блока равна 128 бит */

  }

  if( tail ) { /* на последок, мы обрабатываем хвост сообщения */
    size_t i;
    bkey->encrypt( &bkey->key, yain, yaout );
    for( i = 0; i < tail; i++ )
        ( (ak_uint8*)outptr )[i] = ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];
  }

 /* перемаскируем ключ */
  if( bkey->key.remask( &bkey->key ) != ak_error_ok )
    return ak_error_message( ak_error_get_value(), __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_bckey.c  */
/* ----------------------------------------------------------------------------------------------- */
