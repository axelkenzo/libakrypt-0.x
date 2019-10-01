/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_kuznechik.h                                                                            */
/*  - содержит реализацию алгоритма блочного шифрования Кузнечик,                                  */
/*    регламентированного ГОСТ Р 34.12-2015                                                        */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_bckey.h>
 #include <ak_parameters.h>

/* ---------------------------------------------------------------------------------------------- */
 typedef ak_uint64 ak_kuznechik_lookup_matrix[16][256][2];
/*! \brief Таблицы, используемые для реализации алгоритма зашифрования одного блока. */
 static ak_kuznechik_lookup_matrix ak_kuznechik_encryption_matrix;
/*! \brief Таблицы, используемые для реализации алгоритма расшифрования одного блока. */
 static ak_kuznechik_lookup_matrix ak_kuznechik_decryption_matrix;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые раундовые ключи и маски алгоритма Кузнечик.
    \details Массив содержит в себе записанные последовательно следующие ключи и маски
    (последовательно, по 10 ключей из двух 64-х битных слов на каждый ключ)
      - раундовые ключи для алгоритма зашифрования
      - раундовые ключи для алгоритма расшифрования
      - маски для раундовых ключей алгоритма зашифрования
      - маски для раундовых ключей алгоритма расшифрования. */
 typedef ak_uint64 ak_kuznechik_expanded_keys[80];

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while( y ) {
    if( y&0x1 ) z ^= x;
    x = ((ak_uint8)(x << 1)) ^ ( x & 0x80 ? 0xC3 : 0x00 );
    y >>= 1;
  }
 return z;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_init_kuznechik_tables( void )
{
  int i, j, l;
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         ak_uint8 b[16], ib[16];
         for( l = 0; l < 16; l++ ) {
             b[l] = ak_kuznechik_mul_gf256( L[l][i], gost_pi[j] );
            ib[l] = ak_kuznechik_mul_gf256( Linv[l][i], gost_pinv[j] );
         }
         memcpy( ak_kuznechik_encryption_matrix[i][j], b, 16 );
         memcpy( ak_kuznechik_decryption_matrix[i][j], ib, 16 );
      }
  }
  if( ak_log_get_level() >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "initialization is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x.                */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_matrix_mul_vector( const ak_uint8 D[16][16], ak_uint8 *w, ak_uint8* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_kuznechik_mul_gf256( D[i][0], w[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_kuznechik_mul_gf256( D[i][j], w[j] );
    x[i] = z;
  }
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига).                                        */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_linear_steps( ak_uint8 *w  )
{
  int i = 0, j = 0;
  const ak_uint8 kuz_lvec[16] = {
    0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94
  };

  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = w[0];
     for( i = 1; i < 16; i++ ) {
        w[i-1] = w[i];
        z ^= ak_kuznechik_mul_gf256( w[i], kuz_lvec[i] );
     }
     w[15] = z;
  }
}

struct ak_kuznechik_key_data {
  ak_uint64 ekey[2][20];
  ak_uint64 dkey[2][20];
  ak_uint64 mkey[2][20];
  ak_uint64 xkey[2][20];

  ak_kuznechik_lookup_matrix masked_encryption_matrix;
  ak_kuznechik_lookup_matrix masked_decryption_matrix;

  ak_kuznechik_lookup_matrix* encryption_matrices[2];
  ak_kuznechik_lookup_matrix* decryption_matrices[2];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, содержащего развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_delete_keys( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( skey->data != NULL ) {
   /* теперь очистка и освобождение памяти */
    if(( error = ak_ptr_wipe( skey->data, sizeof( struct ak_kuznechik_key_data ),
                                                  &skey->generator, ak_true )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect wiping an internal data" );
      memset( skey->data, 0, sizeof( struct ak_kuznechik_key_data ));
    }
    free( skey->data );
    skey->data = NULL;
  }
 return error;
}

 static int ak_kuznechik_init_masked_key (ak_skey skey) {
   struct ak_kuznechik_key_data* data_ptr = skey->data;
   ak_uint64 delta[2], delta_inv[2];
   skey->generator.random(&skey->generator, delta, sizeof(ak_uint64) * 2);
   ak_kuznechik_matrix_mul_vector(Linv, (ak_uint8*) delta, (ak_uint8*) delta_inv);
   for (int i = 0; i < 20; ++i) {
     data_ptr->ekey[1][i] = data_ptr->ekey[0][i] ^ data_ptr->mkey[0][i] ^ data_ptr->mkey[1][i] ^ delta[i % 2];
     data_ptr->dkey[1][i] = data_ptr->dkey[0][i] ^ data_ptr->xkey[0][i] ^ data_ptr->xkey[1][i] ^ delta_inv[i % 2];
   }
   for(unsigned i = 0; i < 16; i++ ) {
     for(unsigned j = 0; j < 256; j++ ) {
       ak_uint8 b[16], ib[16], *delta_bytes = (ak_uint8 *) delta;
       for(unsigned l = 0; l < 16; l++ ) {
         b[l] = ak_kuznechik_mul_gf256( L[l][i], gost_pi[j^delta_bytes[i]] );
         ib[l] = ak_kuznechik_mul_gf256( Linv[l][i], gost_pinv[j] ^ delta_bytes[i] );
       }
       memcpy( data_ptr->masked_encryption_matrix[i][j], b, 16 );
       memcpy( data_ptr->masked_decryption_matrix[i][j], ib, 16 );
     }
   }

   data_ptr->encryption_matrices[0] = &ak_kuznechik_encryption_matrix;
   data_ptr->encryption_matrices[1] = &data_ptr->masked_encryption_matrix;

   data_ptr->decryption_matrices[0] = &ak_kuznechik_decryption_matrix;
   data_ptr->decryption_matrices[1] = &data_ptr->masked_decryption_matrix;
   return 0;
 }


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, в который помещаются развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_schedule_keys( ak_skey skey )
{
  int i = 0, j = 0, l = 0, kdx = 2;
  ak_uint64 a0[2], a1[2], c[2], t[2], idx = 0;
  ak_uint64 *ekey = NULL, *mkey = NULL, *dkey = NULL, *xkey = NULL;
  struct ak_kuznechik_key_data* data_ptr;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* удаляем былое */
  if( skey->data != NULL ) ak_kuznechik_delete_keys( skey );

 /* далее, по-возможности, выделяем выравненную память */
  if(( data_ptr = ak_libakrypt_aligned_malloc( sizeof( struct ak_kuznechik_key_data ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
  skey->data = data_ptr;
 /* получаем указатели на области памяти */
  ekey = data_ptr->ekey[0];             /* 10 прямых раундовых ключей */
  dkey = data_ptr->dkey[0];           /* 10 обратных раундовых ключей */
  mkey = data_ptr->mkey[0];   /* 10 масок для прямых раундовых ключей */
  xkey = data_ptr->xkey[0]; /* 10 масок для обратных раундовых ключей */

 /* за один вызов вырабатываем маски для прямых и обратных ключей */
  skey->generator.random( &skey->generator, data_ptr->mkey[0], 20*sizeof( ak_uint64 ));
  skey->generator.random( &skey->generator, data_ptr->mkey[1], 20*sizeof( ak_uint64 ));
  skey->generator.random( &skey->generator, data_ptr->xkey[0], 20*sizeof( ak_uint64 ));
  skey->generator.random( &skey->generator, data_ptr->xkey[1], 20*sizeof( ak_uint64 ));

 /* только теперь выполняем алгоритм развертки ключа */
  a0[0] = (( ak_uint64 *) skey->key.data )[0] ^ (( ak_uint64 *) skey->mask.data )[0];
  a0[1] = (( ak_uint64 *) skey->key.data )[1] ^ (( ak_uint64 *) skey->mask.data )[1];
  a1[0] = (( ak_uint64 *) skey->key.data )[2] ^ (( ak_uint64 *) skey->mask.data )[2];
  a1[1] = (( ak_uint64 *) skey->key.data )[3] ^ (( ak_uint64 *) skey->mask.data )[3];

  ekey[0] = a1[0]^mkey[0]; ekey[1] = a1[1]^mkey[1];
  dkey[0] = a1[0]^xkey[0]; dkey[1] = a1[1]^xkey[1];

  ekey[2] = a0[0]^mkey[2]; ekey[3] = a0[1]^mkey[3];
  ak_kuznechik_matrix_mul_vector( Linv, (ak_uint8 *)a0, (ak_uint8 *)( dkey+2 ));
  dkey[2] ^= xkey[2]; dkey[3] ^= xkey[3];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
      #ifdef LIBAKRYPT_LITTLE_ENDIAN
        c[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
      #else
        c[0] = bswap_64( ++idx );
      #endif
        c[1] = 0;
        ak_kuznechik_linear_steps(( ak_uint8 *)c );

        t[0] = a1[0] ^ c[0]; t[1] = a1[1] ^ c[1];
        for( l = 0; l < 16; l++ ) ((ak_uint8 *)t)[l] = gost_pi[ ((ak_uint8 *)t)[l]];
        ak_kuznechik_linear_steps(( ak_uint8 *)t );

        t[0] ^= a0[0]; t[1] ^= a0[1];
        a0[0] = a1[0]; a0[1] = a1[1];
        a1[0] = t[0];  a1[1] = t[1];
     }
     kdx += 2;
     ekey[kdx] = a1[0]^mkey[kdx]; ekey[kdx+1] = a1[1]^mkey[kdx+1];
     ak_kuznechik_matrix_mul_vector( Linv, ( ak_uint8 *)a1, (ak_uint8 *)( dkey+kdx ));
     dkey[kdx] ^= xkey[kdx]; dkey[kdx+1] ^= xkey[kdx+1];

     kdx += 2;
     ekey[kdx] = a0[0]^mkey[kdx]; ekey[kdx+1] = a0[1]^mkey[kdx+1];
     ak_kuznechik_matrix_mul_vector( Linv, ( ak_uint8 *)a0, (ak_uint8 *)( dkey+kdx ));
     dkey[kdx] ^= xkey[kdx]; dkey[kdx+1] ^= xkey[kdx+1];
  }
  ak_kuznechik_init_masked_key(skey);
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct ak_kuznechik_key_data* data = (( struct ak_kuznechik_key_data *)skey->data);
 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 s, t, x[2];
  ak_uint8 *b = (ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];

  ak_uint32 path_val;
  skey->generator.random(&skey->generator, &path_val, sizeof(ak_uint32));
  ak_byte path[10];
  for (int j = 0; j < 10; j++) {
      path[j] = path_val & 0x0001u;
      path_val = path_val >> 1u;
  }

  for(i = 0; i < 9; i++) {
     ak_byte m = path[i];

     x[0] ^= data->ekey[m][2*i    ]; x[0] ^= data->mkey[m][2*i    ];
     x[1] ^= data->ekey[m][2*i + 1]; x[1] ^= data->mkey[m][2*i + 1];

     t  = (*data->encryption_matrices[m])[ 0][b[ 0]][0];
     t ^= (*data->encryption_matrices[m])[ 1][b[ 1]][0];
     t ^= (*data->encryption_matrices[m])[ 2][b[ 2]][0];
     t ^= (*data->encryption_matrices[m])[ 3][b[ 3]][0];
     t ^= (*data->encryption_matrices[m])[ 4][b[ 4]][0];
     t ^= (*data->encryption_matrices[m])[ 5][b[ 5]][0];
     t ^= (*data->encryption_matrices[m])[ 6][b[ 6]][0];
     t ^= (*data->encryption_matrices[m])[ 7][b[ 7]][0];
     t ^= (*data->encryption_matrices[m])[ 8][b[ 8]][0];
     t ^= (*data->encryption_matrices[m])[ 9][b[ 9]][0];
     t ^= (*data->encryption_matrices[m])[10][b[10]][0];
     t ^= (*data->encryption_matrices[m])[11][b[11]][0];
     t ^= (*data->encryption_matrices[m])[12][b[12]][0];
     t ^= (*data->encryption_matrices[m])[13][b[13]][0];
     t ^= (*data->encryption_matrices[m])[14][b[14]][0];
     t ^= (*data->encryption_matrices[m])[15][b[15]][0];

     s  = (*data->encryption_matrices[m])[ 0][b[ 0]][1];
     s ^= (*data->encryption_matrices[m])[ 1][b[ 1]][1];
     s ^= (*data->encryption_matrices[m])[ 2][b[ 2]][1];
     s ^= (*data->encryption_matrices[m])[ 3][b[ 3]][1];
     s ^= (*data->encryption_matrices[m])[ 4][b[ 4]][1];
     s ^= (*data->encryption_matrices[m])[ 5][b[ 5]][1];
     s ^= (*data->encryption_matrices[m])[ 6][b[ 6]][1];
     s ^= (*data->encryption_matrices[m])[ 7][b[ 7]][1];
     s ^= (*data->encryption_matrices[m])[ 8][b[ 8]][1];
     s ^= (*data->encryption_matrices[m])[ 9][b[ 9]][1];
     s ^= (*data->encryption_matrices[m])[10][b[10]][1];
     s ^= (*data->encryption_matrices[m])[11][b[11]][1];
     s ^= (*data->encryption_matrices[m])[12][b[12]][1];
     s ^= (*data->encryption_matrices[m])[13][b[13]][1];
     s ^= (*data->encryption_matrices[m])[14][b[14]][1];
     s ^= (*data->encryption_matrices[m])[15][b[15]][1];

     x[0] = t; x[1] = s;
  }
  x[0] ^= data->ekey[0][18]; x[1] ^= data->ekey[0][19];
  ((ak_uint64 *)out)[0] = x[0] ^ data->mkey[0][18];
  ((ak_uint64 *)out)[1] = x[1] ^ data->mkey[0][19];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct ak_kuznechik_key_data* data = (( struct ak_kuznechik_key_data *)skey->data);

  /* чистая реализация для 64х битной архитектуры */
  ak_uint64 s, t, x[2];
  ak_uint8 *b = (ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  ak_uint32 path_val;
  skey->generator.random(&skey->generator, &path_val, sizeof(ak_uint32));
  ak_byte path[10];
  for (int j = 0; j < 10; j++) {
    path[j] = path_val & 0x0001u;
    path_val = path_val >> 1u;
  }


  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) b[i] = gost_pi[b[i]];

  for( i = 9; i > 0; i--) {
     ak_byte m = path[i];

     t  = (*data->decryption_matrices[m])[ 0][b[ 0]][0];
     t ^= (*data->decryption_matrices[m])[ 1][b[ 1]][0];
     t ^= (*data->decryption_matrices[m])[ 2][b[ 2]][0];
     t ^= (*data->decryption_matrices[m])[ 3][b[ 3]][0];
     t ^= (*data->decryption_matrices[m])[ 4][b[ 4]][0];
     t ^= (*data->decryption_matrices[m])[ 5][b[ 5]][0];
     t ^= (*data->decryption_matrices[m])[ 6][b[ 6]][0];
     t ^= (*data->decryption_matrices[m])[ 7][b[ 7]][0];
     t ^= (*data->decryption_matrices[m])[ 8][b[ 8]][0];
     t ^= (*data->decryption_matrices[m])[ 9][b[ 9]][0];
     t ^= (*data->decryption_matrices[m])[10][b[10]][0];
     t ^= (*data->decryption_matrices[m])[11][b[11]][0];
     t ^= (*data->decryption_matrices[m])[12][b[12]][0];
     t ^= (*data->decryption_matrices[m])[13][b[13]][0];
     t ^= (*data->decryption_matrices[m])[14][b[14]][0];
     t ^= (*data->decryption_matrices[m])[15][b[15]][0];

     s  = (*data->decryption_matrices[m])[ 0][b[ 0]][1];
     s ^= (*data->decryption_matrices[m])[ 1][b[ 1]][1];
     s ^= (*data->decryption_matrices[m])[ 2][b[ 2]][1];
     s ^= (*data->decryption_matrices[m])[ 3][b[ 3]][1];
     s ^= (*data->decryption_matrices[m])[ 4][b[ 4]][1];
     s ^= (*data->decryption_matrices[m])[ 5][b[ 5]][1];
     s ^= (*data->decryption_matrices[m])[ 6][b[ 6]][1];
     s ^= (*data->decryption_matrices[m])[ 7][b[ 7]][1];
     s ^= (*data->decryption_matrices[m])[ 8][b[ 8]][1];
     s ^= (*data->decryption_matrices[m])[ 9][b[ 9]][1];
     s ^= (*data->decryption_matrices[m])[10][b[10]][1];
     s ^= (*data->decryption_matrices[m])[11][b[11]][1];
     s ^= (*data->decryption_matrices[m])[12][b[12]][1];
     s ^= (*data->decryption_matrices[m])[13][b[13]][1];
     s ^= (*data->decryption_matrices[m])[14][b[14]][1];
     s ^= (*data->decryption_matrices[m])[15][b[15]][1];

     x[0] = t; x[1] = s;

     x[1] ^= data->dkey[m][2*i + 1]; x[1] ^= data->xkey[m][2*i + 1];
     x[0] ^= data->dkey[m][2*i    ]; x[0] ^= data->xkey[m][2*i    ];
  }
  for( i = 0; i < 16; i++ ) b[i] = gost_pinv[b[i]];

  x[0] ^= data->dkey[0][0]; x[1] ^= data->dkey[0][1];
  (( ak_uint64 *) out)[0] = x[0] ^ data->xkey[0][0];
  (( ak_uint64 *) out)[1] = x[1] ^ data->xkey[0][1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    \param bkey Контекст секретного ключа алгоритма блочного шифрования.
    \return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_create_kuznechik( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_context_create( bkey, 32, 16 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_context_find_by_name( "kuznechik" )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined kuznechik block cipher OID" );
    ak_bckey_context_destroy( bkey );
    return error;
  };

 /* ресурс ключа устанавливается в момент присвоения ключа */

 /* устанавливаем методы */
  bkey->schedule_keys = ak_kuznechik_schedule_keys;
  bkey->delete_keys = ak_kuznechik_delete_keys;
  bkey->encrypt = ak_kuznechik_encrypt_with_mask;
  bkey->decrypt = ak_kuznechik_decrypt_with_mask;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование производится в соответствии с контрольными примерами из
    ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_test_kuznechik( void )
{
  char *str = NULL;
  struct bckey bkey;
  bool_t result = ak_true;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.1 */
 /* тестовый ключ из ГОСТ Р 34.13-2015, приложение А.1 */
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
  ak_uint8 inlong[64] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 };

  ak_uint8 outecb[64] = {
    0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f,
    0x8b, 0xd0, 0x18, 0x67, 0xd7, 0x52, 0x54, 0x28, 0xf9, 0x32, 0x00, 0x6e, 0x2c, 0x91, 0x29, 0xb4,
    0x57, 0xb1, 0xd4, 0x3b, 0x31, 0xa5, 0xf5, 0xf3, 0xee, 0x7c, 0x24, 0x9d, 0x54, 0x33, 0xca, 0xf0,
    0x98, 0xda, 0x8a, 0xaa, 0xc5, 0xc4, 0x02, 0x3a, 0xeb, 0xb9, 0x30, 0xe8, 0xcd, 0x9c, 0xb0, 0xd0 };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivctr[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };

 /* результат зашифрования в режиме гаммирования (счетчика) */
  ak_uint8 outctr[64] = {
    0xb8, 0xa1, 0xbd, 0x40, 0xa2, 0x5f, 0x7b, 0xd5, 0xdb, 0xd1, 0x0e, 0xc1, 0xbe, 0xd8, 0x95, 0xf1,
    0xe4, 0xde, 0x45, 0x3c, 0xb3, 0xe4, 0x3c, 0xf3, 0x5d, 0x3e, 0xa1, 0xf6, 0x33, 0xe7, 0xee, 0x85,
    0xa5, 0xa3, 0x64, 0x35, 0xf1, 0x77, 0xe8, 0xd5, 0xd3, 0x6e, 0x35, 0xe6, 0x8b, 0xe8, 0xea, 0xa5,
    0x73, 0xba, 0xbd, 0x20, 0x58, 0xd1, 0xc6, 0xd1, 0xb6, 0xba, 0x0c, 0xf2, 0xb1, 0xfa, 0x91, 0xcb };

  ak_uint8 xiv1[8] = { 0x61, 0x2D, 0x93, 0x42, 0xAE, 0x2E, 0x57, 0x21 };
  ak_uint8 xin1[23] = {
    0x31, 0xEA, 0x54, 0xBB, 0xB7, 0xE5, 0xE5, 0x1C, 0xAE, 0xEB, 0x79, 0x28, 0x71, 0x5E, 0x93, 0xFF,
    0x9B, 0x8D, 0xD4, 0x90, 0xC4, 0x76, 0xBC };
  ak_uint8 xout1[23] = {
    0x30, 0xF6, 0x0A, 0xA9, 0xC0, 0x11, 0x77, 0xCE, 0xCD, 0xE9, 0x40, 0x9A, 0x4B, 0x46, 0x1C, 0x64,
    0xF6, 0xCA, 0xF7, 0xC6, 0x90, 0x18, 0x65 };

 /* значение имитовставки согласно ГОСТ Р 34.13-2015 (раздел А.1.6) */
  ak_uint8 imito[16] = {
     0x67, 0x9C, 0x74, 0x37, 0x5B, 0xB3, 0xDE, 0x4D, 0xE3, 0xFB, 0x59, 0x60, 0x29, 0x4D, 0x6F, 0x33 };

 /* временный буффер */
  ak_uint8 myout[64];

 /* 1. Создаем контекст ключа алгоритма Кузнечик и устанавливаем значение ключа */
  if(( error = ak_bckey_context_create_kuznechik( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    return ak_false;
  }

  if(( error = ak_bckey_context_set_key( &bkey, testkey, sizeof( testkey ), ak_false )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of test key" );
    result = ak_false;
    goto exit;
  }

 /* 2. Тестируем зашифрование/расшифрование одного блока согласно ГОСТ Р34.12-2015 */
  bkey.encrypt( &bkey.key, in, myout );
  if( !ak_ptr_is_equal( myout, out, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                       "the one block encryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block encryption test from GOST R 34.12-2015 is Ok" );

  bkey.decrypt( &bkey.key, out, myout );
  if( !ak_ptr_is_equal( myout, in, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                       "the one block decryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( in, 16, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block decryption test from GOST R 34.12-2015 is Ok" );

 /* 3. Тестируем режим простой замены согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_encrypt_ecb( &bkey, inlong, myout, 64 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ecb mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, outecb, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outecb, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_context_decrypt_ecb( &bkey, outecb, myout, 64 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ecb mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                "the ecb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* 4. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_ctr( &bkey, inlong, myout, 64, ivctr, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong counter mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, outctr, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the counter mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outctr, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_context_ctr( &bkey, outctr, myout, 64, ivctr, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong counter mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the counter mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
               "the counter mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* 5. Тестируем режим гаммирования (счетчика) на длинах, не кратных длине блока. */
  if( ak_bckey_context_ctr( &bkey, xin1, myout, 23, xiv1, 8 ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong plain text encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, xout1, 23 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the counter mode encryption test for 23 octets is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 23, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( xout1, 23, ak_false )); free(str);
    result = ak_false;
    goto exit;
  }

  if( ak_bckey_context_ctr( &bkey, xout1, myout, 23, xiv1, 8 ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong cipher text decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, xin1, 23 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the counter mode decryption test for 23 octets is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 23, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( xin1, 23, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                               "the counter mode encryption/decryption test for 23 octets is Ok" );

 /* 6. Тестируем режим выработки имитовставки (плоская реализация). */
  ak_bckey_context_omac( &bkey, inlong, sizeof( inlong ), myout );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong omac calculation" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, imito, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                   "the omac integrity mode test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( imito, 16, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "the omac integrity mode test from GOST R 34.13-2015 is Ok" );
 /* освобождаем ключ и выходим */
  exit:
  if(( error = ak_bckey_context_destroy( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong destroying of secret key" );
    return ak_false;
  }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_kuznechik.c  */
/* ----------------------------------------------------------------------------------------------- */
