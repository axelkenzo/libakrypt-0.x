/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2015 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*   ak_kuznechik.c                                                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_bckey.h>
 #include <ak_tools.h>
 #include <ak_parameters.h>

/* ---------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
   #ifdef __x86_64__
    #define LIBAKRYPT_KUZNECHIK_M128
   #endif
#endif

#ifdef LIBAKRYPT_KUZNECHIK_M128
 static __m128i kuz_mat_enc128[16][256];
 static __m128i kuz_mat_dec128[16][256];
#else
 static ak_uint128 kuz_mat_enc128[16][256];
 static ak_uint128 kuz_mat_dec128[16][256];
#endif

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while (y) {
    if (y & 1) z ^= x;
      x = (x << 1) ^ (x & 0x80 ? 0xC3 : 0x00);
      y >>= 1;
  }
 return z;
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига).                                        */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_linear_steps( ak_uint128 *w  )
{
  int i = 0, j = 0;
  const ak_uint8 kuz_lvec[16] = {
   0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94
  };

  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = w->b[0];
     for( i = 1; i < 16; i++ ) {
        w->b[i-1] = w->b[i];
        z ^= ak_kuznechik_mul_gf256( w->b[i], kuz_lvec[i] );
     }
     w->b[15] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x.                */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_matrix_mul_vector( const ak_uint8 D[16][16],
                                                                      ak_uint128 *w, ak_uint128* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_kuznechik_mul_gf256( D[i][0], w->b[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_kuznechik_mul_gf256( D[i][j], w->b[j] );
    x->b[i] = z;
  }
}
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_init_kuznechik_tables( void )
{
  int i, j, l;

#ifdef LIBAKRYPT_KUZNECHIK_M128
  ak_uint128 x, y;
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 256; j++ ) {
        x.q[0] = 0; x.q[1] = 0;
        y.q[0] = 0; y.q[1] = 0;

        for( l = 0; l < 16; l++ ) {
           x.b[l] = ak_kuznechik_mul_gf256( L[l][i], gost_pi[j] );
           y.b[l] = ak_kuznechik_mul_gf256( Linv[l][i], gost_pinv[j] );
        }
      #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
        kuz_mat_enc128[i][j] = _mm_set_epi64x(x.q[1], x.q[0]); // *((__m128i *) &x);
        kuz_mat_dec128[i][j] = _mm_set_epi64x(y.q[1], y.q[0]); // *((__m128i *) &y);
      #else
        kuz_mat_enc128[i][j].m128i_u64[0] = x.q[0]; kuz_mat_enc128[i][j].m128i_u64[1] = x.q[1];
        kuz_mat_dec128[i][j].m128i_u64[0] = y.q[0]; kuz_mat_dec128[i][j].m128i_u64[1] = y.q[1];
      #endif
     }
  }

#else
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         for( l = 0; l < 16; l++ ) {
            kuz_mat_enc128[i][j].b[l] = ak_kuznechik_mul_gf256( L[l][i], gost_pi[j] );
            kuz_mat_dec128[i][j].b[l] = ak_kuznechik_mul_gf256( Linv[l][i], gost_pinv[j] );
         }
      }
  }

#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Раундовые ключи алгоритма Кузнечик. */
 struct kuznechik_expanded_keys {
  ak_uint128 k[10];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура с внутренними данными секретного ключа алгоритма Кузнечик. */
 struct kuznechik_ctx {
  /*! \brief раундовые ключи для алгоритма зашифрования */
  struct kuznechik_expanded_keys encryptkey;
  /*! \brief раундовые ключи для алгоритма расшифрования */
  struct kuznechik_expanded_keys decryptkey;
  /*! \brief маски для раундовых ключей алгоритма зашифрования */
  struct kuznechik_expanded_keys encryptmask;
  /*! \brief маски для раундовых ключей алгоритма расшифрования */
  struct kuznechik_expanded_keys decryptmask;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Кузнечик. */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_delete_keys( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( skey->data == NULL ) return ak_error_message( ak_error_null_pointer,
                                              __func__ , "using a null pointer to internal data" );
 /* теперь очистка и освобождение памяти */
  if(( error = skey->generator.random( &skey->generator,
                                   skey->data, sizeof( struct kuznechik_ctx ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect wiping an internal data" );
    memset( skey->data, 0, sizeof ( struct kuznechik_ctx ));
  }
  if( skey->data != NULL ) {
    free( skey->data );
    skey->data = NULL;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик. */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_schedule_keys( ak_skey skey )
{
  ak_uint128 a0, a1, c, t;
  struct kuznechik_expanded_keys *ekey = NULL, *mkey = NULL;
  struct kuznechik_expanded_keys *dkey = NULL, *xkey = NULL;
  int i = 0, j = 0, l = 0, idx = 0, kdx = 1;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* готовим память для переменных */
  if(( skey->data = /* далее, по-возможности, выделяем выравненную память */
#ifdef LIBAKRYPT_HAVE_STDALIGN
  aligned_alloc( 16,
#else
  malloc(
#endif
    sizeof( struct kuznechik_ctx ))) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
 /* получаем указатели на области памяти */
  ekey = &(( struct kuznechik_ctx * ) skey->data )->encryptkey;
  mkey = &(( struct kuznechik_ctx * ) skey->data )->encryptmask;
  dkey = &(( struct kuznechik_ctx * ) skey->data )->decryptkey;
  xkey = &(( struct kuznechik_ctx * ) skey->data )->decryptmask;

 /* вырабатываем маски */
  skey->generator.random( &skey->generator, mkey, sizeof( struct kuznechik_expanded_keys ));
  skey->generator.random( &skey->generator, xkey, sizeof( struct kuznechik_expanded_keys ));

 /* только теперь выполняем алгоритм развертки ключа */
  a0.q[0] = (( ak_uint128 *) skey->key.data )[0].q[0] ^ (( ak_uint128 *) skey->mask.data )[0].q[0];
  a0.q[1] = (( ak_uint128 *) skey->key.data )[0].q[1] ^ (( ak_uint128 *) skey->mask.data )[0].q[1];
  a1.q[0] = (( ak_uint128 *) skey->key.data )[1].q[0] ^ (( ak_uint128 *) skey->mask.data )[1].q[0];
  a1.q[1] = (( ak_uint128 *) skey->key.data )[1].q[1] ^ (( ak_uint128 *) skey->mask.data )[1].q[1];

  ekey->k[0].q[0] = a1.q[0]^mkey->k[0].q[0];
  dkey->k[0].q[0] = a1.q[0]^xkey->k[0].q[0];

  ekey->k[0].q[1] = a1.q[1]^mkey->k[0].q[1];
  dkey->k[0].q[1] = a1.q[1]^xkey->k[0].q[1];

  ekey->k[1].q[0] = a0.q[0]^mkey->k[1].q[0];
  ekey->k[1].q[1] = a0.q[1]^mkey->k[1].q[1];

  ak_kuznechik_matrix_mul_vector( Linv, &a0, &dkey->k[1] );
  dkey->k[1].q[0] ^= xkey->k[1].q[0]; dkey->k[1].q[1] ^= xkey->k[1].q[1];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
        c.q[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
        c.q[1] = 0;
        ak_kuznechik_linear_steps( &c );

        t.q[0] = a1.q[0] ^ c.q[0]; t.q[1] = a1.q[1] ^ c.q[1];
        for( l = 0; l < 16; l++ ) t.b[l] = gost_pi[t.b[l]];
        ak_kuznechik_linear_steps( &t );

        t.q[0] ^= a0.q[0]; t.q[1] ^= a0.q[1];
        a0.q[0] = a1.q[0]; a0.q[1] = a1.q[1];
        a1.q[0] = t.q[0];  a1.q[1] = t.q[1];
     }
     kdx++;
     ekey->k[kdx].q[0] = a1.q[0]^mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a1.q[1]^mkey->k[kdx].q[1];
     ak_kuznechik_matrix_mul_vector( Linv, &a1, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];

     kdx++;
     ekey->k[kdx].q[0] = a0.q[0]^mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a0.q[1]^mkey->k[kdx].q[1];
     ak_kuznechik_matrix_mul_vector( Linv, &a0, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет маску ключа алгоритма блочного шифрования Кузнечик.                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_remask_xor( ak_skey skey )
{
  size_t idx = 0;
  ak_uint64 mask[20], *kptr = NULL, *mptr = NULL;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined key buffer" );
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                           "key length is wrong" );
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "using undefined mask buffer" );
 /* перемаскируем ключ */
  if(( error = skey->generator.random( &skey->generator, mask, skey->key.size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation random key mask");

  for( idx = 0; idx < 4; idx++ ) {
     ((ak_uint64 *) skey->key.data)[idx] ^= mask[idx];
     ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data)[idx];
     ((ak_uint64 *) skey->mask.data)[idx] = mask[idx];
  }

 /* перемаскируем раундовые ключи зашифрования */
  if(( error = skey->generator.random( &skey->generator, mask, 20*sizeof( ak_uint64 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation random key mask");

  kptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->encryptkey );
  mptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->encryptmask );
  for( idx = 0; idx < 20; idx++ ) {
     kptr[idx] ^= mask[idx];
     kptr[idx] ^= mptr[idx];
     mptr[idx] = mask[idx];
  }

 /* перемаскируем раундовые ключи расшифрования */
  if(( error = skey->generator.random( &skey->generator, mask, 20*sizeof( ak_uint64 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation random key mask");

  kptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->decryptkey );
  mptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->decryptmask );
  for( idx = 0; idx < 20; idx++ ) {
     kptr[idx] ^= mask[idx];
     kptr[idx] ^= mptr[idx];
     mptr[idx] = mask[idx];
  }

 /* удаляем старое */
  memset( mask, 0, 20*sizeof( ak_uint64 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct kuznechik_expanded_keys *ekey = &(( struct kuznechik_ctx * ) skey->data )->encryptkey;
  struct kuznechik_expanded_keys *mkey = &(( struct kuznechik_ctx * ) skey->data )->encryptmask;

#ifdef LIBAKRYPT_KUZNECHIK_M128
  __m128i z, x = *((__m128i *) in);

  for( i = 0; i < 9; i++ ) {
   #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
     x = _mm_xor_si128( x, _mm_set_epi64x( ekey->k[i].q[1], ekey->k[i].q[0] ));
     x = _mm_xor_si128( x, _mm_set_epi64x( mkey->k[i].q[1], mkey->k[i].q[0] ));
   #else
     z.m128i_u64[0] = ekey->k[i].q[0]; z.m128i_u64[1] = ekey->k[i].q[1]; x = _mm_xor_si128( x, z );
     z.m128i_u64[0] = mkey->k[i].q[0]; z.m128i_u64[1] = mkey->k[i].q[1]; x = _mm_xor_si128( x, z );
   #endif

     z = kuz_mat_enc128[ 0][((ak_uint8 *) &x)[ 0]];
     z = _mm_xor_si128( z, kuz_mat_enc128[ 1][((ak_uint8 *) &x)[ 1]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 2][((ak_uint8 *) &x)[ 2]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 3][((ak_uint8 *) &x)[ 3]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 4][((ak_uint8 *) &x)[ 4]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 5][((ak_uint8 *) &x)[ 5]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 6][((ak_uint8 *) &x)[ 6]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 7][((ak_uint8 *) &x)[ 7]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 8][((ak_uint8 *) &x)[ 8]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 9][((ak_uint8 *) &x)[ 9]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[10][((ak_uint8 *) &x)[10]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[11][((ak_uint8 *) &x)[11]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[12][((ak_uint8 *) &x)[12]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[13][((ak_uint8 *) &x)[13]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[14][((ak_uint8 *) &x)[14]]);
     x = _mm_xor_si128( z, kuz_mat_enc128[15][((ak_uint8 *) &x)[15]]);
  }

 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  x = _mm_xor_si128( x, _mm_set_epi64x( ekey->k[9].q[1], ekey->k[9].q[0] ));
  *((__m128i *) out) = _mm_xor_si128( x, _mm_set_epi64x( mkey->k[9].q[1], mkey->k[9].q[0] ));
 #else
  z.m128i_u64[0] = ekey->k[9].q[0]; z.m128i_u64[1] = ekey->k[9].q[1]; x = _mm_xor_si128( x, z );
  z.m128i_u64[0] = mkey->k[9].q[0]; z.m128i_u64[1] = mkey->k[9].q[1];
  *((__m128i *) out) = _mm_xor_si128( x, z );
 #endif

#else
  ak_uint64 t;
  ak_uint128 x;
  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];

  for( i = 0; i < 9; i++ ) {
     x.q[0] ^= ekey->k[i].q[0]; x.q[0] ^= mkey->k[i].q[0];
     x.q[1] ^= ekey->k[i].q[1]; x.q[1] ^= mkey->k[i].q[1];

     t = kuz_mat_enc128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_enc128[10][x.b[10]].q[0] ^
         kuz_mat_enc128[11][x.b[11]].q[0] ^
         kuz_mat_enc128[12][x.b[12]].q[0] ^
         kuz_mat_enc128[13][x.b[13]].q[0] ^
         kuz_mat_enc128[14][x.b[14]].q[0] ^
         kuz_mat_enc128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_enc128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_enc128[10][x.b[10]].q[1] ^
         kuz_mat_enc128[11][x.b[11]].q[1] ^
         kuz_mat_enc128[12][x.b[12]].q[1] ^
         kuz_mat_enc128[13][x.b[13]].q[1] ^
         kuz_mat_enc128[14][x.b[14]].q[1] ^
         kuz_mat_enc128[15][x.b[15]].q[1];
     x.q[0] = t;
  }
  x.q[0] ^= ekey->k[9].q[0]; x.q[1] ^= ekey->k[9].q[1];
  ((ak_uint64 *)out)[0] = x.q[0] ^ mkey->k[9].q[0];
  ((ak_uint64 *)out)[1] = x.q[1] ^ mkey->k[9].q[1];

#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct kuznechik_expanded_keys *dkey = &(( struct kuznechik_ctx * ) skey->data )->decryptkey;
  struct kuznechik_expanded_keys *xkey = &(( struct kuznechik_ctx * ) skey->data )->decryptmask;

#ifdef LIBAKRYPT_KUZNECHIK_M128
  __m128i z, x = *((__m128i *) in);

  for( i = 0; i < 16; i++ ) ((ak_uint8 *) &x)[i] = gost_pi[((ak_uint8 *) &x)[i]];
  for( i = 9; i > 0; i-- ) {
     z = kuz_mat_dec128[ 0][((ak_uint8 *) &x)[ 0]];

     z = _mm_xor_si128( z, kuz_mat_dec128[ 1][((ak_uint8 *) &x)[ 1]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 2][((ak_uint8 *) &x)[ 2]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 3][((ak_uint8 *) &x)[ 3]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 4][((ak_uint8 *) &x)[ 4]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 5][((ak_uint8 *) &x)[ 5]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 6][((ak_uint8 *) &x)[ 6]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 7][((ak_uint8 *) &x)[ 7]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 8][((ak_uint8 *) &x)[ 8]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 9][((ak_uint8 *) &x)[ 9]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[10][((ak_uint8 *) &x)[10]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[11][((ak_uint8 *) &x)[11]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[12][((ak_uint8 *) &x)[12]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[13][((ak_uint8 *) &x)[13]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[14][((ak_uint8 *) &x)[14]]);
     x = _mm_xor_si128( z, kuz_mat_dec128[15][((ak_uint8 *) &x)[15]]);
   #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
     x = _mm_xor_si128( x, _mm_set_epi64x( dkey->k[i].q[1], dkey->k[i].q[0] ));
     x = _mm_xor_si128( x, _mm_set_epi64x( xkey->k[i].q[1], xkey->k[i].q[0] ));
   #else
     z.m128i_u64[0] = dkey->k[i].q[0]; z.m128i_u64[1] = dkey->k[i].q[1]; x = _mm_xor_si128( x, z );
     z.m128i_u64[0] = xkey->k[i].q[0]; z.m128i_u64[1] = xkey->k[i].q[1]; x = _mm_xor_si128( x, z );
   #endif
  }
  for( i = 0; i < 16; i++ ) ((ak_uint8 *) &x)[i] = gost_pinv[((ak_uint8 *) &x)[i]];

 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  x = _mm_xor_si128( x, _mm_set_epi64x( dkey->k[0].q[1], dkey->k[0].q[0] ));
  *((__m128i *) out) = _mm_xor_si128( x, _mm_set_epi64x( xkey->k[0].q[1], xkey->k[0].q[0] ));
 #else
  z.m128i_u64[0] = dkey->k[0].q[0]; z.m128i_u64[1] = dkey->k[0].q[1]; x = _mm_xor_si128( x, z );
  z.m128i_u64[0] = xkey->k[0].q[0]; z.m128i_u64[1] = xkey->k[0].q[1];
  *((__m128i *) out) = _mm_xor_si128( x, z );
 #endif

#else
  ak_uint64 t;
  ak_uint128 x;

  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) x.b[i] = gost_pi[x.b[i]];
  for( i = 9; i > 0; i-- ) {
     t = kuz_mat_dec128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_dec128[10][x.b[10]].q[0] ^
         kuz_mat_dec128[11][x.b[11]].q[0] ^
         kuz_mat_dec128[12][x.b[12]].q[0] ^
         kuz_mat_dec128[13][x.b[13]].q[0] ^
         kuz_mat_dec128[14][x.b[14]].q[0] ^
         kuz_mat_dec128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_dec128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_dec128[10][x.b[10]].q[1] ^
         kuz_mat_dec128[11][x.b[11]].q[1] ^
         kuz_mat_dec128[12][x.b[12]].q[1] ^
         kuz_mat_dec128[13][x.b[13]].q[1] ^
         kuz_mat_dec128[14][x.b[14]].q[1] ^
         kuz_mat_dec128[15][x.b[15]].q[1];

      x.q[0] = t;
      x.q[0] ^= dkey->k[i].q[0]; x.q[1] ^= dkey->k[i].q[1];
      x.q[0] ^= xkey->k[i].q[0]; x.q[1] ^= xkey->k[i].q[1];
  }
  for( i = 0; i < 16; i++ ) x.b[i] = gost_pinv[x.b[i]];

  x.q[0] ^= dkey->k[0].q[0]; x.q[1] ^= dkey->k[0].q[1];
  (( ak_uint64 *) out)[0] = x.q[0] ^ xkey->k[0].q[0];
  (( ak_uint64 *) out)[1] = x.q[1] ^ xkey->k[0].q[1];

#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализируете контекст ключа алгоритма блочного шифрования Кузнечик.
    После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    @param bkey Контекст секретного ключа алгоритма блочного шифрования.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_kuznechik( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to block cipher key context" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_find_by_name( "kuznechik" )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined kuznechik block cipher OID" );
    ak_bckey_destroy( bkey );
    return error;
  };

 /* устанавливаем ресурс использования серетного ключа */
  bkey->key.resource.counter = ak_libakrypt_get_option( "kuznechik_cipher_resource" );

 /* устанавливаем методы */
  bkey->key.data = NULL;
  bkey->key.set_mask =  ak_skey_set_mask_xor;
  bkey->key.remask = ak_kuznechik_remask_xor;
  bkey->key.set_icode = ak_skey_set_icode_xor;
  bkey->key.check_icode = ak_skey_check_icode_xor;

  bkey->schedule_keys = ak_kuznechik_schedule_keys;
  bkey->delete_keys = ak_kuznechik_delete_keys;
  bkey->encrypt = ak_kuznechik_encrypt_with_mask;
  bkey->decrypt = ak_kuznechik_decrypt_with_mask;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование производится в соответствии с ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.              */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_kuznechik( void )
{
  char *str = NULL;
  struct bckey bkey;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.1 */
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 in[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 out[16] = {
    0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint32 inlong[16] = {
    0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0xcceeff0a, 0x8899aabb, 0x44556677, 0x00112233,
    0xeeff0a00, 0x99aabbcc, 0x55667788, 0x11223344, 0xff0a0011, 0xaabbccee, 0x66778899, 0x22334455 };

 /* результат зашифрования в режиме простой замены */
  ak_uint32 outecb[16] = {
    0xb9d4edcd, 0x5a468d42, 0xbebc2430, 0x7f679d90, 0x6718d08b, 0x285452d7, 0x6e0032f9, 0xb429912c,
    0x3bd4b157, 0xf3f5a531, 0x9d247cee, 0xf0ca3354, 0xaa8ada98, 0x3a02c4c5, 0xe830b9eb, 0xd0b09ccd };

 /* результат зашифрования в режиме простой замены с зацеплением */
  ak_uint32 outofb[16] = {
      0x6d7dcc27, 0x90e52e3d, 0xa085fa4d, 0x689972d4, 0x8d5ea5ac, 0xaf1e8e44, 0xb478eca6, 0x2826e661,
      0xf49d90d0, 0x5640e8b0, 0xe91999e8, 0xfe7babf1, 0x60b63970, 0x1a2d9a15, 0x5a895c63, 0x16768806 };


  /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivctr[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };
  /* инициализационный вектор для режима простой замены с зацеплением */
  ak_uint8 ofb_iv[32] = {0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
                         0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23,
                         0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1,
                         0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12};

 /* результат зашифрования в режиме гаммирования (счетчика) */
  ak_uint32 outctr[16] = {
    0x40bda1b8, 0xd57b5fa2, 0xc10ed1db, 0xf195d8be, 0x3c45dee4, 0xf33ce4b3, 0xf6a13e5d, 0x85eee733,
    0x3564a3a5, 0xd5e877f1, 0xe6356ed3, 0xa5eae88b, 0x20bdba73, 0xd1c6d158, 0xf20cbab6, 0xcb91fab1 };

  ak_uint8 myout[64];

 /* 1. Создаем контекст ключа алгоритма Кузнечик и устанавливаем значение ключа */
  if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    return ak_false;
  }

  if(( error = ak_bckey_context_set_ptr( &bkey, testkey, sizeof( testkey ), ak_false )) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation of test key" );
    return ak_false;
  }

 /* 2. Тестируем зашифрование/расшифрование одного блока согласно ГОСТ Р34.12-2015 */
  bkey.encrypt( &bkey.key, in, myout );
  if( !ak_ptr_is_equal( myout, out, 16 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                       "the one block encryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block encryption test from GOST R 34.12-2015 is Ok" );

  bkey.decrypt( &bkey.key, out, myout );
  if( !ak_ptr_is_equal( myout, in, 16 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                       "the one block decryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( in, 16, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block decryption test from GOST R 34.12-2015 is Ok" );

 /* 3. Тестируем режим простой замены согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_encrypt_ecb( &bkey, inlong, myout, 64 )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong ecb mode encryption" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, outecb, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outecb, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the ecb mode encryption test from GOST R 34.13-2015 is Ok" );

  if(( error = ak_bckey_context_decrypt_ecb( &bkey, outecb, myout, 64 )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong ecb mode decryption" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the ecb mode decryption test from GOST R 34.13-2015 is Ok" );

 /* 4. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_xcrypt( &bkey, inlong, myout, 64, ivctr, 8 )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong counter mode encryption" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, outctr, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the counter mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outctr, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the counter mode encryption test from GOST R 34.13-2015 is Ok" );

  if(( error = ak_bckey_context_xcrypt( &bkey, outctr, myout, 64, ivctr, 8 )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong counter mode decryption" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the counter mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the counter mode decryption test from GOST R 34.13-2015 is Ok" );

  /* 5. Тестируем режим простой замены с зацеплением согласно ГОСТ Р34.13-2015 */
  /*encrypt*/
  if(( error = ak_bckey_context_encrypt_cbc(&bkey, inlong, myout, 64, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode encryption" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, outofb, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outofb, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode encryption test from GOST R 34.13-2015 is Ok" );

  /* decrypt */
  if(( error = ak_bckey_context_decrypt_cbc(&bkey, outofb, myout, 64, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode decryption" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( ofb_iv, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode decryption test from GOST R 34.13-2015 is Ok" );

  /* 6. Тестируем режим простой замены с зацеплением с применением update_encrypt */
  if(( error = ak_bckey_context_encrypt_cbc(&bkey, inlong, myout, 32, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode encryption 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if(( error = ak_bckey_context_encrypt_cbc_update(&bkey, inlong + 8, myout + 32, 32)) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode update_encrypt 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, outofb, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode encryption test2 from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outofb, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode encryption with update test from GOST R 34.13-2015 is Ok" );

  /* 7. Тестируем режим простой замены с зацеплением с применением update_decrypt */
  if(( error = ak_bckey_context_decrypt_cbc(&bkey, outofb, myout, 32, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode decryption 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if(( error = ak_bckey_context_decrypt_cbc_update(&bkey, outofb + 8, myout + 32, 32)) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode update_decrypt 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode encryption test3 from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outofb, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode decryption with update test from GOST R 34.13-2015 is Ok" );

  /* 8. Тестируем режим простой замены с зацеплением с применением update_encrypt */
  if(( error = ak_bckey_context_encrypt_cbc(&bkey, inlong, myout, 32, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode encryption 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if(( error = ak_bckey_context_encrypt_cbc_update(&bkey, inlong + 8, myout + 32, 16)) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode update_encrypt 16" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, outofb, 48 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode encryption test4 from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outofb, 64, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode encryption with update test2 from GOST R 34.13-2015 is Ok" );

  /* 9. Тестируем режим простой замены с зацеплением с применением update_decrypt */
  if(( error = ak_bckey_context_decrypt_cbc(&bkey, outofb, myout, 32, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode decryption 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if(( error = ak_bckey_context_decrypt_cbc_update(&bkey, outofb + 8, myout + 32, 16)) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode update_decrypt 16" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, inlong, 48 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode encryption test5 from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 48, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outofb, 48, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode decryption with update test2 from GOST R 34.13-2015 is Ok" );
  /* 10. Тестируем режим простой замены с зацеплением, шифрование 32 */
  if(( error = ak_bckey_context_encrypt_cbc(&bkey, inlong, myout, 32, ofb_iv, sizeof(ofb_iv))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__ , "wrong cipher block chaining mode encryption 32" );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( !ak_ptr_is_equal( myout, outofb, 32 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the cipher block chaining mode encryption test6 from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 32, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outofb, 32, ak_true )); free( str );
    ak_bckey_destroy( &bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the cipher block chaining mode encryption of first 32 from GOST R 34.13-2015 is Ok" );

  /* уничтожаем ключ и выходим */
  ak_bckey_destroy( &bkey );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_kuznechik.c */
/* ----------------------------------------------------------------------------------------------- */
