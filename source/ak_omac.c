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
/*  ak_omac.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция очищает контекст секретного ключа алгоритма выработки имитовставки omac-acpkm, а
    также проверяет ресурс ключа.

    @param ctx контекст ключа алгоритма omac-acpkm
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_omac_acpkm_clean( ak_pointer ctx )
{
  ak_omac_acpkm octx = (ak_omac_acpkm)ctx;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to hmac key context" );
 /* проверяем наличие ключа */
  if( !(octx->key.key.flags&ak_skey_flag_set_key) ) return ak_error_message( ak_error_key_value,
                                                  __func__, "using hmac key with unassigned value" );
 /* нам надо один раз использовать ключ (для CTR-ACPKM) => ресурс должен быть не менее одного */
  if( octx->key.key.resource.counter <= 0 ) return ak_error_message( ak_error_resource_counter,
                                              __func__, "using hmac key context with low resource" );
  /* размер секции должен быть кратен размеру блока */
  if( octx->section_size % octx->key.ivector.size )
    return ak_error_message( ak_error_wrong_length, __func__, "using wrong size of section" );
  /* проверяем значение частоты смены мастер-ключа */
  if( octx->change_period % ( octx->key.ivector.size + octx->key.key.key.size ) )
    return ak_error_message( ak_error_wrong_length, __func__, "using wrong value of change period" );

  octx->blocks_n = 0;
  octx->flags = 0x02;

  if( octx->key.ivector.size == 8 ) {
    memset( octx->tmp_ptr, 0, 8 );
    memset( octx->k_ptr, 0, 8 );
  };
  if( octx->key.ivector.size == 16 ) {
    memset( octx->tmp_ptr, 0, 16 );
    memset( octx->k_ptr, 0, 16 );
  };

  ak_skey_destroy( &octx->key_e );
  ak_skey_create( &octx->key_e, 32, 8 );

 return ak_error_ok;
}

/* предварительные описания функций, используемых в ak_omac_acpkm_update
   и ak_omac_acpkm_finalize */
 int ak_bckey_context_xcrypt_acpkm_with_mask( ak_bckey , ak_pointer , ak_pointer , ak_pointer ,
                                                                                      const size_t );
 int ak_bckey_context_xcrypt_acpkm_with_mask_update( ak_bckey , ak_pointer , ak_pointer ,
                                                                                        ak_pointer );
 void ak_kuznechik_schedule_keys_without_allocation( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция обновляет текущее состояние контекста алгоритма выработки имитовставки omac-acpkm.

    @param ctx контекст ключа алгоритма omac-acpkm
    @param data указатель на обрабатываемые данные
    @param size длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_omac_acpkm_update( ak_pointer ctx, const ak_pointer data, const size_t size )
{
  int error = ak_error_ok;
  ak_omac_acpkm octx = (ak_omac_acpkm)ctx;
  ak_uint64 *data_ptr = (ak_uint64 *)data;
  ak_int64 section_c = octx->section_size/octx->key.ivector.size,
            blocks = (ak_int64)size/octx->key.ivector.size;

 /* выполнение проверок */
  if( octx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to omac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using zero length for authenticated data" );
 /* проверяем наличие ключа */
  if( !(octx->key.key.flags&ak_skey_flag_set_key) ) return ak_error_message( ak_error_key_value,
                                                  __func__, "using omac key with unassigned value" );
 /* уменьшаем значение ресурса ключа */
  if( octx->flags&0x02 ) {
    ak_int64 counter = ak_min( blocks, octx->section_size );
    if( octx->key.key.resource.counter < counter )
      return ak_error_message( ak_error_low_key_resource,
                                              __func__, "using omac key context with low resource" );
     else octx->key.key.resource.counter -= counter; /* уменьшаем ресурс ключа */
    if( counter == octx->section_size )
      octx->flags ^= 0x02;
  }

 /* выполнение алгоритма вычисления имитовставки */
  if( octx->key.ivector.size == 8 ) { /* здесь длина блока равна 64 бита */
   /* вычисление элемента последовательности ключевого материала */
    if( !(octx->flags&0x01) ) {
      if(( error =
            ak_bckey_context_xcrypt_acpkm_with_mask( &octx->key, octx->key_e.key.data, octx->k_ptr,
                                       octx->key_e.mask.data, octx->change_period )) != ak_error_ok )
        return ak_error_message( error, __func__, "invalid 1st ACPKM iteration" );
      octx->key_e.set_icode( &octx->key_e );
      octx->flags |= 0x01;
    } else {
            /* выполнение отложеннной при последем вызове ak_omac_acpkm_update() обработки
               последнего блока */
             octx->key.encrypt( &octx->key_e, octx->tmp_ptr, octx->tmp_ptr );
             octx->blocks_n = ( octx->blocks_n + 1 ) % section_c;
             if( octx->blocks_n == 0 ) {
               if(( error =
                  ak_bckey_context_xcrypt_acpkm_with_mask_update( &octx->key, octx->key_e.key.data,
                                               octx->k_ptr, octx->key_e.mask.data )) != ak_error_ok )
                 return ak_error_message( error, __func__, "invalid ACPKM update iteration" );
               octx->key_e.set_icode( &octx->key_e );
             }
           }
   /* обработка блоков данных, предшествующих последнему блоку */
    while( blocks-- > 1 ) {
      *((ak_uint64 *)octx->tmp_ptr) ^= *data_ptr;
      octx->key.encrypt( &octx->key_e, octx->tmp_ptr, octx->tmp_ptr );
      octx->blocks_n = ( octx->blocks_n + 1 ) % section_c;
      data_ptr++;
     /* вычисление очередного элемента полследовательности ключевого материала */
      if( octx->blocks_n == 0 ) {
        if(( error =
                  ak_bckey_context_xcrypt_acpkm_with_mask_update( &octx->key, octx->key_e.key.data,
                                               octx->k_ptr, octx->key_e.mask.data )) != ak_error_ok )
          return ak_error_message( error, __func__, "invalid ACPKM update iteration" );
        octx->key_e.set_icode( &octx->key_e );
      }
    }
   /* подготовка отложенной обработки последнего блока */
    *((ak_uint64 *)octx->tmp_ptr) ^= *data_ptr;
  }

  if( octx->key.ivector.size == 16 ) { /* здесь длина блока равна 128 бит */
   /* вычисление элемента последовательности ключевого материала */
    if( !(octx->flags&0x01) ) {
      if(( error =
            ak_bckey_context_xcrypt_acpkm_with_mask( &octx->key, octx->key_e.key.data, octx->k_ptr,
                                       octx->key_e.mask.data, octx->change_period )) != ak_error_ok )
        return ak_error_message( error, __func__, "invalid 1st ACPKM iteration" );
      octx->key_e.set_icode( &octx->key_e );
      octx->key.schedule_keys( &octx->key_e );
      octx->flags |= 0x01;
    } else {
            /* выполнение отложеннной при последем вызове ak_omac_acpkm_update() обработки
               последнего блока */
             octx->key.encrypt( &octx->key_e, octx->tmp_ptr, octx->tmp_ptr );
             octx->blocks_n = ( octx->blocks_n + 1 ) % section_c;
             if( octx->blocks_n == 0 ) {
               if(( error =
                  ak_bckey_context_xcrypt_acpkm_with_mask_update( &octx->key, octx->key_e.key.data,
                                               octx->k_ptr, octx->key_e.mask.data )) != ak_error_ok )
                 return ak_error_message( error, __func__, "invalid ACPKM update iteration" );
               octx->key_e.set_icode( &octx->key_e );
               ak_kuznechik_schedule_keys_without_allocation( &octx->key_e );
             }
           }
   /* обработка блоков данных, предшествующих последнему блоку */
    while( blocks-- > 1 ) {
      ((ak_uint64 *)octx->tmp_ptr)[0] ^= *data_ptr;
      data_ptr++;
      ((ak_uint64 *)octx->tmp_ptr)[1] ^= *data_ptr;
      octx->key.encrypt( &octx->key_e, octx->tmp_ptr, octx->tmp_ptr );
      octx->blocks_n = ( octx->blocks_n + 1 ) % section_c;
      data_ptr++;
     /* вычисление очередного элемента полследовательности ключевого материала */
      if( octx->blocks_n == 0 ) {
        if(( error =
                  ak_bckey_context_xcrypt_acpkm_with_mask_update( &octx->key, octx->key_e.key.data,
                                               octx->k_ptr, octx->key_e.mask.data )) != ak_error_ok )
          return ak_error_message( error, __func__, "invalid ACPKM update iteration" );
        octx->key_e.set_icode( &octx->key_e );
        ak_kuznechik_schedule_keys_without_allocation( &octx->key_e );
      }
    }
   /* подготовка отложенной обработки последнего блока */
    ((ak_uint64*)octx->tmp_ptr)[0] ^= data_ptr[0];
    ((ak_uint64*)octx->tmp_ptr)[1] ^= data_ptr[1];
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция завершает вычисление алгоритма выработки имитовставки omac-acpkm.

    @param ctx контекст ключа алгоритма omac-acpkm
    @param data блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    @param size длина блока обрабатываемых данных
    @param out указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 static ak_buffer ak_omac_acpkm_finalize( ak_pointer ctx, const ak_pointer data,
                                                                  const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_omac_acpkm octx = (ak_omac_acpkm)ctx;
  ak_uint64 buff[2];

 /* выполнение проверок */
  if( octx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to omac key context" );
    return NULL;
  }
  if( !(octx->key.key.flags&ak_skey_flag_set_key) ) {
    ak_error_message( ak_error_key_value, __func__, "using omac key with unassigned value" );
    return NULL;
  }
 /* уменьшаем значение ресурса ключа */
  if( octx->flags&0x02 ) {
    if( octx->key.key.resource.counter <= 0 ) {
      ak_error_message( ak_error_low_key_resource, __func__,
                                                        "using omac key context with low resource" );
      return NULL;
    } else octx->key.key.resource.counter--; /* уменьшаем ресурс ключа */
    octx->flags ^= 0x02;
  }

 /* выполнение завершающего этапа алгоритма вычисления имитовставки */
 /* Длина всего сообщения не кратна длине блока, и в функцию передаётся последний блок data
    сообщения размера меньше n. Необходимо вычислить промежуточное значение имитовставки для
    предыдущего блока данных и рассчитать финальное значение. */
  if( size ) {
   /* Выполняем в случае вызова update хотя бы один раз, то есть когда длина всего сообщения равна
      либо больше размера блока. */
    if( octx->flags&0x01 ) {
      octx->key.encrypt( &octx->key_e, octx->tmp_ptr, octx->tmp_ptr );
      octx->blocks_n = ( octx->blocks_n + 1 ) % ( octx->section_size/octx->key.ivector.size );
      if( octx->blocks_n == 0 ) {
        if(( error =
                ak_bckey_context_xcrypt_acpkm_with_mask_update( &octx->key, octx->key_e.key.data,
                                             octx->k_ptr, octx->key_e.mask.data )) != ak_error_ok ) {
          ak_error_message( error, __func__, "invalid ACPKM update iteration" );
          return NULL;
        }
        octx->key_e.set_icode( &octx->key_e );
        if( octx->key.ivector.size == 16 )
          ak_kuznechik_schedule_keys_without_allocation( &octx->key_e );
      }
    } else {
            /* update не вызывался ни разу */
             if(( error = ak_bckey_context_xcrypt_acpkm_with_mask( &octx->key, octx->key_e.key.data,
                        octx->k_ptr, octx->key_e.mask.data, octx->change_period )) != ak_error_ok ) {
               ak_error_message( error, __func__, "invalid 1st ACPKM iteration" );
               return NULL;
             }
             octx->key_e.set_icode( &octx->key_e );
             if( octx->key.ivector.size == 16 )
               octx->key.schedule_keys( &octx->key_e );
           }

    if( octx->key.ivector.size == 8 ) {
      if( *(ak_uint8 *)octx->k_ptr&0x80 )
        *(ak_uint64 *)octx->k_ptr = *(ak_uint64 *)octx->k_ptr << 1 ^ 0x1b;
      else
        *(ak_uint64 *)octx->k_ptr <<= 1;

      buff[0] = 0;
      memcpy( (ak_uint8 *)buff + 8 - size, data, size );
      ((ak_uint8 *)buff)[7 - size] = 0x80;
      *(ak_uint64 *)octx->tmp_ptr ^= *buff;
      *(ak_uint64 *)octx->tmp_ptr ^= *(ak_uint64 *)octx->k_ptr;
    }

    if( octx->key.ivector.size == 16 ) {
      if( *(ak_uint8 *)octx->k_ptr&0x80 ) {
        ((ak_uint64 *)octx->k_ptr)[0] = ((ak_uint64 *)octx->k_ptr)[0] << 1 ^
                                                                 ((ak_uint64 *)octx->k_ptr)[1] >> 63;
        ((ak_uint64 *)octx->k_ptr)[1] = ((ak_uint64 *)octx->k_ptr)[1] << 1 ^ 0x87;
      } else {
               ((ak_uint64 *)octx->k_ptr)[0] = ((ak_uint64 *)octx->k_ptr)[0] << 1 ^
                                                                 ((ak_uint64 *)octx->k_ptr)[1] >> 63;
               ((ak_uint64 *)octx->k_ptr)[1] <<= 1;
             }

      buff[0] = 0; buff[1] = 0;
      memcpy( (ak_uint8 *)buff + 16 - size, data, size );
      ((ak_uint8 *)buff)[15 - size] = 0x80;
      ((ak_uint64 *)octx->tmp_ptr)[0] ^= buff[0]; ((ak_uint64 *)octx->tmp_ptr)[1] ^= buff[1];
      ((ak_uint64 *)octx->tmp_ptr)[0] ^= ((ak_uint64 *)octx->k_ptr)[0];
      ((ak_uint64 *)octx->tmp_ptr)[1] ^= ((ak_uint64 *)octx->k_ptr)[1];
    }
  } else {
          /* Длина всего сообщения кратна длине блока, и в функцию передаётся пустой блок data,
             необходимо зашифровать предыдущий блок. */
           *(ak_uint64 *)octx->tmp_ptr ^= *(ak_uint64 *)octx->k_ptr;
           if( octx->key.ivector.size == 16 )
             ((ak_uint64 *)octx->tmp_ptr)[1] ^= ((ak_uint64 *)octx->k_ptr)[1];
         }

  if( out )
    octx->key.encrypt( &octx->key_e, octx->tmp_ptr, out );
  else {
         octx->key.encrypt( &octx->key_e, octx->tmp_ptr, buff );
         ak_omac_acpkm_clean( ctx );
         return ak_buffer_new_ptr( buff, octx->key.ivector.size, ak_true );
       }

  ak_omac_acpkm_clean( ctx );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @param change_period Период смены мастер-ключа.
    @param section_size Размер секции.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_omac_acpkm_magma( ak_mac mac, const size_t change_period,
                                                                          const size_t section_size )
{
  int error = ak_error_ok;

 /* производим первоначальную очистку контекста и устанавливаем его тип */
  memset( mac, 0, sizeof( struct mac ) );
  mac->type = type_omac_acpkm;

 /* инициализируем контекст ключа блочного шифра, инициализации ключа в функции не происходит */
  if(( error = ak_bckey_create_magma( &mac->choice._omac_acpkm.key )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of magma block cypher context" );

 /* копируем длины (усечение не используется, поэтому длина имитовставки hsize совпадает
    с длиной блока bsize) */
  mac->hsize = mac->bsize = mac->choice._omac_acpkm.key.ivector.size;
  mac->choice._omac_acpkm.change_period = change_period;
  mac->choice._omac_acpkm.section_size = section_size;

  mac->choice._omac_acpkm.tmp_ptr = malloc( 8 );
  mac->choice._omac_acpkm.k_ptr = malloc( 8 );
  ak_skey_create( &mac->choice._omac_acpkm.key_e, 32, 8 );

 /* инициализируем методы */
  mac->clean = ak_omac_acpkm_clean;
  mac->update = ak_omac_acpkm_update;
  mac->finalize = ak_omac_acpkm_finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_omac_acpkm_magma_csp( ak_mac mac )
{
 return ak_mac_create_omac_acpkm_magma( mac, 80, 16 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @param change_period Период смены мастер-ключа.
    @param section_size Размер секции.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_omac_acpkm_kuznechik( ak_mac mac, const size_t change_period,
                                                                          const size_t section_size )
{
  int error = ak_error_ok;

 /* производим первоначальную очистку контекста и устанавливаем его тип */
  memset( mac, 0, sizeof( struct mac ) );
  mac->type = type_omac_acpkm;

 /* инициализируем контекст ключа блочного шифра, инициализации ключа в функции не происходит */
  if(( error = ak_bckey_create_kuznechik( &mac->choice._omac_acpkm.key )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of kuznechik block cypher context" );

 /* копируем длины (усечение не используется, поэтому длина имитовставки hsize совпадает
    с длиной блока bsize) */
  mac->hsize = mac->bsize = mac->choice._omac_acpkm.key.ivector.size;
  mac->choice._omac_acpkm.change_period = change_period;
  mac->choice._omac_acpkm.section_size = section_size;

  mac->choice._omac_acpkm.tmp_ptr = malloc( 16 );
  mac->choice._omac_acpkm.k_ptr = malloc( 16 );
  ak_skey_create( &mac->choice._omac_acpkm.key_e, 32, 8 );

 /* инициализируем методы */
  mac->clean = ak_omac_acpkm_clean;
  mac->update = ak_omac_acpkm_update;
  mac->finalize = ak_omac_acpkm_finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_omac_acpkm_kuznechik_csp( ak_mac mac )
{
 return ak_mac_create_omac_acpkm_kuznechik( mac, 96, 32 );
}

/* ----------------------------------------------------------------------------------------------- */
/*                         функции для тестирования алгоритма omac-acpkm                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_omac_acpkm_test_magma( void )
{
  char *str = NULL;
  ak_uint8 out[8];
  struct mac mkey;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* тестовый ключ OMAC-ACPKM */
  ak_uint8 testkey[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
  };

 /* открытый текст OMAC-ACPKM, приложение А.3.1 */
  ak_uint32 in1[3] = { 0x55667700, 0x11223344, 0xffeeddcc };

 /* результат зашифрования в режиме OMAC-ACPKM, приложение А.3.1 */
  ak_uint64 out1 = 0xa0540e3730acbcf3;

 /* открытый текст OMAC-ACPKM, приложение А.3.2, */
  ak_uint64 in2[5] = {
    0x1122334455667700, 0xffeeddccbbaa9988, 0x0011223344556677, 0x8899aabbcceeff0a,
    0x1122334455667788
  };

 /* результат зашифрования в режиме OMAC-ACPKM, приложение А.3.2 */
  ak_uint64 out2 = 0x34008dad5496bb8e;

  if(( error = ak_mac_create_omac_acpkm_magma( &mkey, 80, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of omac-acpkm key context" );
    return ak_false;
  }
  if(( error = ak_mac_context_set_ptr( &mkey, testkey, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant omac-acpkm key value" );
    return ak_false;
  }

  ak_mac_context_ptr( &mkey, in1, 12, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of omac-acpkm code #1" );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, &out1, 8 )) {
    ak_error_message( ak_error_not_equal_data, __func__ , "wrong test #1 for omac-acpkm" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 8, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( &out1, 8, ak_false )); free( str );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the omac-acpkm code calculation test #1 is Ok" );

  ak_mac_context_ptr( &mkey, in2, 40, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of omac-acpkm code #2" );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, &out2, 8 )) {
    ak_error_message( ak_error_not_equal_data, __func__ , "wrong test #2 for omac-acpkm" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 8, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( &out2, 8, ak_false )); free( str );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the omac-acpkm code calculation test #2 is Ok" );

  ak_mac_destroy( &mkey );

 return ak_true;
}

 ak_bool ak_omac_acpkm_test_kuznechik( void )
{
  char *str = NULL;
  ak_uint8 out[16];
  struct mac mkey;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* тестовый ключ OMAC-ACPKM */
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* открытый текст OMAC-ACPKM, приложение А.4.1 */
  ak_uint32 in1[6] = { 0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0x44556677, 0x00112233 };

 /* результат зашифрования в режиме OMAC-ACPKM, приложение А.4.1 */
  ak_uint32 out1[4] = { 0x5843145e, 0xeb2a648c, 0xb62b995e, 0xb5367f47 };

 /* открытый текст OMAC-ACPKM, приложение А.4.2 */
  ak_uint32 in2[20] = {
    0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0xcceeff0a, 0x8899aabb, 0x44556677, 0x00112233,
    0xeeff0a00, 0x99aabbcc, 0x55667788, 0x11223344, 0xff0a0011, 0xaabbccee, 0x66778899, 0x22334455,
    0x0a001122, 0xbbcceeff, 0x778899aa, 0x33445566 };

 /* результат зашифрования в режиме OMAC-ACPKM, приложение А.4.2 */
  ak_uint32 out2[4] = { 0x00898e5d, 0x35f58c57, 0x45bea67c, 0xfbb8dcee };

  if(( error = ak_mac_create_omac_acpkm_kuznechik( &mkey, 96, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of omac-acpkm key context" );
    return ak_false;
  }
  if(( error = ak_mac_context_set_ptr( &mkey, testkey, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant omac-acpkm key value" );
    return ak_false;
  }

  ak_mac_context_ptr( &mkey, in1, 24, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of omac-acpkm code #1" );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, out1, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ , "wrong test #1 for omac-acpkm" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out1, 16, ak_false )); free( str );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the omac-acpkm code calculation test #1 is Ok" );

  ak_mac_context_ptr( &mkey, in2, 80, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of omac-acpkm code #2" );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, out2, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ , "wrong test #2 for omac-acpkm" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out2, 16, ak_false )); free( str );
    ak_mac_destroy( &mkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the omac-acpkm code calculation test #2 is Ok" );

  ak_mac_destroy( &mkey );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_omac.c  */
/* ----------------------------------------------------------------------------------------------- */
