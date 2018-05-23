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
/*  ak_mac.c                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_compress.h>

/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_oid( ak_mac mac, ak_oid oid )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( mac == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to mac context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to mac function oid" );
 /* проверяем, что oid от ключевой функции хеширования */
  if( oid->engine != mac_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что oid от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                           "using oid with undefined constructor function" );
 /* инициализируем контекст */
  if(( error = (( ak_function_mac_create *)oid->func)( mac )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of hash function context");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac контекст алгоритма выработки имитовставки
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_destroy( ak_mac mac )
{
  int error = ak_error_ok;
  if( mac == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "destroying a null pointer to mac key context" );
  switch( mac->type ) {
   case type_hmac:
         if(( error = ak_skey_destroy( &mac->choice._hmac.key )) != ak_error_ok )
           ak_error_message( error, __func__ , "incorrect destroying secret key of mac context" );
         if(( error = ak_hash_destroy( &mac->choice._hmac.ctx )) != ak_error_ok )
           ak_error_message( error, __func__ , "incorrect destroying hash function of mac context" );
         break;

  case type_omac_acpkm:
         if(( error = ak_bckey_destroy( &mac->choice._omac_acpkm.key )) != ak_error_ok )
           ak_error_message( error, __func__,
                                          "incorrect destroying secret master key of omac context" );
         if(( error = ak_skey_destroy( &mac->choice._omac_acpkm.key_e )) != ak_error_ok )
           ak_error_message( error, __func__,
                                       "incorrect destroying secret temporary key of omac context" );
         mac->choice._omac_acpkm.change_period = 0;
         mac->choice._omac_acpkm.section_size = 0;
         mac->choice._omac_acpkm.blocks_n = 0;
         free( mac->choice._omac_acpkm.tmp_ptr );
         free( mac->choice._omac_acpkm.k_ptr );
         break;

   case type_block_cipher:
         break;

   case type_signify:
         break;

   default:
         break;
  }

  mac->type = type_undefined;
  mac->bsize = 0;
  mac->hsize = 0;
  mac->clean = NULL;
  mac->update = NULL;
  mac->finalize = NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac контекст ключа алгоритма hmac
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_mac_delete( ak_pointer mac )
{
  if( mac != NULL ) {
      ak_mac_destroy(( ak_mac ) mac );
      free( mac );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to mac key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает указатель на секретный ключ алгоритма выработки имитовставки. */
/* ----------------------------------------------------------------------------------------------- */
 static inline ak_skey ak_mac_context_get_secret_key( ak_mac mac )
{
  switch( mac->type ) {
   case type_hmac:  return ( ak_skey ) &mac->choice._hmac.key; break;
   case type_block_cipher: return ( ak_skey ) &mac->choice._bckey.key; break;
   case type_signify:  return ( ak_skey ) &mac->choice._signkey.key; break;
   case type_omac_acpkm: return ( ak_skey ) &mac->choice._omac_acpkm.key.key; break;
   default:
     ak_error_message( ak_error_undefined_value, __func__,
                                                   "using undefined type of mac secret key" );
     break;
  }
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac контекст ключа алгоритма вычисления имитовставки, должен быть предварительно
    инициализирован.

    \return Функция возвращает указатель на константный oid. Если контекст не определен,
    то возвращается NULL;                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_mac_context_get_oid( ak_mac mac )
{
  ak_skey key = ak_mac_context_get_secret_key( mac );

  if(( key == NULL ) || ( key->oid == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect using mac secret key oid");
   return NULL;
  }
  return key->oid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти на которую
    указывает in. Размер памяти задается в байтах в переменной size. Результат вычислений помещается
    в область памяти, на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param mac контекст ключа алгоритма вычисления имитовставки, должен быть предварительно
    инициализирован и содержать в себе ключ.
    @param in указатель на входные данные для которых вычисляется хеш-код.
    @param size размер входных данных в байтах.
    @param out область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hmac_get_icode_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений.                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mac_context_ptr( ak_mac mac, const ak_pointer in, const size_t size, ak_pointer out )
{
  ak_skey skey = NULL;
  int error = ak_error_ok;
  size_t quot = 0, offset = 0;

  if( mac == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "using null pointer to secret mac key context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to input data" );
    return NULL;
  }

 /* проверяем наличие ключа ( ресурс ключа проверяется при вызове clean ) */
  if(( skey = ak_mac_context_get_secret_key( mac )) == NULL ) return NULL;
  if( !((skey->flags)&ak_skey_flag_set_key )) {
    ak_error_message( ak_error_key_value, __func__ , "using mac key with unassigned value" );
    return NULL;
  }

 /* вычищаем результаты предыдущих вычислений + инициализируем переменные */
  if(( error = mac->clean( &mac->choice )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect cleaning of mac secret key context" );
    return NULL;
  }

 /* вычисляем фрагмент, длина которого кратна длине блока входных данных для хеш-функции */
  quot = size/mac->bsize;
  offset = quot*mac->bsize;
  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 )
    if(( error = mac->update( &mac->choice, in, offset )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong caclucation of mac update function" );
      return NULL;
    }

  /* обрабатываем хвост */
 return mac->finalize( &mac->choice, (unsigned char *)in + offset, size - offset, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданного файла. Результат вычислений помещается в область
    памяти, на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает указатель на
    созданный буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param mac Контекст алгоритма ключевого хеширования, должен быть отличен от NULL.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mac_context_file( ak_mac mac, const char *filename, ak_pointer out )
{
  struct compress comp;
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( mac == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to mac context" );
    return NULL;
  }

  if(( error = ak_compress_create_mac( &comp, mac )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation a compress context" );
    return NULL;
  }

  result = ak_compress_file( &comp, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect hash code calculation" );

  ak_compress_destroy( &comp );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст ключа алгоритма выработки имитовставки.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    \b Внимание! Данные всегда копируются во внутреннюю память контекста алгоритма.
    @param size Размер данных, на которые указывает ptr (размер в байтах)
    @return В случае успеха функция возвращает указатель на созданный контекст. В противном случае
    возвращается NULL. Код возникшей ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_set_ptr( ak_mac mac, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;

  if( mac == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using a null pointer to mac key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to constant key value" );
 /* присваиваем ключевой буффер */
  if( mac->type == type_omac_acpkm ) {
    if(( error = ak_skey_set_ptr( ak_mac_context_get_secret_key( mac ), ptr, size,
                                                                          ak_true )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect assigning of key data" );
    if( mac->choice._omac_acpkm.key.ivector.size == 16 )
      mac->choice._omac_acpkm.key.schedule_keys( &mac->choice._omac_acpkm.key.key );
  } else if(( error = ak_skey_set_ptr( ak_mac_context_get_secret_key( mac ), ptr,
                                              ak_min( size, mac->bsize ), ak_true )) != ak_error_ok )
           return ak_error_message( error, __func__, "incorrect assigning of key data" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу алгоритма выработки имитовставки случайное (псевдо-случайное)
    значение, размер которого определяется размером блока обрабатываемых данных используемой
    функции хеширования. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param mac Контекст ключа алгоритма выработки имитовставки. К моменту вызова функции контекст
    должен быть инициализирован.
    @param generator контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_set_random( ak_mac mac, ak_random generator )
{
  ak_skey skey = NULL;
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( mac == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                         "using null pointer to mac context" );
  if(( skey = ak_mac_context_get_secret_key( mac )) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to mac secret key" );

  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using non initialized mac secret key" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                             "using null pointer to random number generator" );
 /* присваиваем секретный ключ */
  if(( error = ak_skey_set_random(
                           ak_mac_context_get_secret_key( mac ), generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation of mac secret key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи алгоритма,
    описанного  в рекомендациях по стандартизации Р 50.1.111-2016.

    Пароль является секретным значением и должен быть не пустой строкой символов в формате utf8.
    Используемое при выработке ключа значение инициализационного вектора может быть не секретным.
    Перед присвоением ключа контекст должен быть инициализирован.

    @param mac Контекст ключа алгоритма выработки имитовставки.
    @param pass Пароль, представленный в виде строки символов в формате utf8.
    @param pass_size Длина пароля в байтах
    @param salt Инициализационный вектор, представленный в виде строки символов.
    @param salt_size Длина инициализационного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_set_password( ak_mac mac, const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( mac == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to mac key context" );
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                  "using null pointer to password" );
  if( pass_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                                 "using password with zero length" );
  if( salt == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector" );
  if( salt_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using initial vector with zero length" );
 /* вырабатываем ключевой буффер */
  if(( error = ak_skey_set_password( ak_mac_context_get_secret_key( mac ),
                                                pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect generation of secret key random value" );
  if( mac->type == type_omac_acpkm && mac->choice._omac_acpkm.key.ivector.size == 16 )
    mac->choice._omac_acpkm.key.schedule_keys( &mac->choice._omac_acpkm.key.key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mac.c  */
/* ----------------------------------------------------------------------------------------------- */
