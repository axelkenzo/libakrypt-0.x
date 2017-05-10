/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2008 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*   ak_magma.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>
 #include <ak_hash.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые перестановки из ГОСТ Р 34.12-2015 для алгоритма Магма */
 const magma magma_boxes = {
  {
        108, 100, 102,  98, 106, 101, 107, 105, 110, 104, 109, 103,  96,  99, 111,  97,
        140, 132, 134, 130, 138, 133, 139, 137, 142, 136, 141, 135, 128, 131, 143, 129,
        44,  36,  38,  34,   42,  37,  43,  41,  46,  40,  45,  39,  32,  35,  47,  33,
        60,  52,  54,  50,  58,  53,   59,  57,  62,  56,  61,  55,  48,  51,  63,  49,
        156, 148, 150, 146, 154, 149, 155, 153, 158, 152, 157, 151, 144, 147, 159, 145,
        172, 164, 166, 162, 170, 165, 171, 169, 174, 168, 173, 167, 160, 163, 175, 161,
         92,  84,  86,  82,  90,  85,  91,  89,  94,  88,  93,  87,  80,  83,  95,  81,
        204, 196, 198, 194, 202, 197, 203, 201, 206, 200, 205, 199, 192, 195, 207, 193,
         28,  20,  22,  18,  26,  21,  27,  25,  30,  24,  29,  23,  16,  19,  31,  17,
        236, 228, 230, 226, 234, 229, 235, 233, 238, 232, 237, 231, 224, 227, 239, 225,
         76,  68,  70,  66,  74,  69,  75,  73,  78,  72,  77,  71,  64,  67,  79,  65,
        124, 116, 118, 114, 122, 117, 123, 121, 126, 120, 125, 119, 112, 115, 127, 113,
        188, 180, 182, 178, 186, 181, 187, 185, 190, 184, 189, 183, 176, 179, 191, 177,
        220, 212, 214, 210, 218, 213, 219, 217, 222, 216, 221, 215, 208, 211, 223, 209,
         12,   4,   6,   2,  10,   5,  11,   9,  14,   8,  13,   7,   0,   3,  15,   1,
        252, 244, 246, 242, 250, 245, 251, 249, 254, 248, 253, 247, 240, 243, 255, 241 },
  {
        203, 195, 197, 200, 194, 207, 202, 205, 206, 193, 199, 196, 204, 201, 198, 192,
        139, 131, 133, 136, 130, 143, 138, 141, 142, 129, 135, 132, 140, 137, 134, 128,
         43,  35,  37,  40,  34,  47,  42,  45,  46,  33,  39,  36,  44,  41,  38,  32,
         27,  19,  21,  24,  18,  31,  26,  29,  30,  17,  23,  20,  28,  25,  22,  16,
        219, 211, 213, 216, 210, 223, 218, 221, 222, 209, 215, 212, 220, 217, 214, 208,
         75,  67,  69,  72,  66,  79,  74,  77,  78,  65,  71,  68,  76,  73,  70,  64,
        251, 243, 245, 248, 242, 255, 250, 253, 254, 241, 247, 244, 252, 249, 246, 240,
        107,  99, 101, 104,  98, 111, 106, 109, 110,  97, 103, 100, 108, 105, 102,  96,
        123, 115, 117, 120, 114, 127, 122, 125, 126, 113, 119, 116, 124, 121, 118, 112,
         11,   3,   5,   8,   2,  15,  10,  13,  14,   1,   7,   4,  12,   9,   6,   0,
        171, 163, 165, 168, 162, 175, 170, 173, 174, 161, 167, 164, 172, 169, 166, 160,
         91,  83,  85,  88,  82,  95,  90,  93,  94,  81,  87,  84,  92,  89,  86,  80,
         59,  51,  53,  56,  50,  63,  58,  61,  62,  49,  55,  52,  60,  57,  54,  48,
        235, 227, 229, 232, 226, 239, 234, 237, 238, 225, 231, 228, 236, 233, 230, 224,
        155, 147, 149, 152, 146, 159, 154, 157, 158, 145, 151, 148, 156, 153, 150, 144,
        187, 179, 181, 184, 178, 191, 186, 189, 190, 177, 183, 180, 188, 185, 182, 176 },
  {
         87,  95,  85,  90,  88,  81,  86,  93,  80,  89,  83,  94,  91,  84,  82,  92,
        215, 223, 213, 218, 216, 209, 214, 221, 208, 217, 211, 222, 219, 212, 210, 220,
        247, 255, 245, 250, 248, 241, 246, 253, 240, 249, 243, 254, 251, 244, 242, 252,
        103, 111, 101, 106, 104,  97, 102, 109,  96, 105,  99, 110, 107, 100,  98, 108,
        151, 159, 149, 154, 152, 145, 150, 157, 144, 153, 147, 158, 155, 148, 146, 156,
         39,  47,  37,  42,  40,  33,  38,  45,  32,  41,  35,  46,  43,  36,  34,  44,
        199, 207, 197, 202, 200, 193, 198, 205, 192, 201, 195, 206, 203, 196, 194, 204,
        167, 175, 165, 170, 168, 161, 166, 173, 160, 169, 163, 174, 171, 164, 162, 172,
        183, 191, 181, 186, 184, 177, 182, 189, 176, 185, 179, 190, 187, 180, 178, 188,
        119, 127, 117, 122, 120, 113, 118, 125, 112, 121, 115, 126, 123, 116, 114, 124,
        135, 143, 133, 138, 136, 129, 134, 141, 128, 137, 131, 142, 139, 132, 130, 140,
         23,  31,  21,  26,  24,  17,  22,  29,  16,  25,  19,  30,  27,  20,  18,  28,
         71,  79,  69,  74,  72,  65,  70,  77,  64,  73,  67,  78,  75,  68,  66,  76,
         55,  63,  53,  58,  56,  49,  54,  61,  48,  57,  51,  62,  59,  52,  50,  60,
        231, 239, 229, 234, 232, 225, 230, 237, 224, 233, 227, 238, 235, 228, 226, 236,
          7,  15,   5,  10,   8,   1,   6,  13,   0,   9,   3,   14, 11,   4,   2,  12 },
  {
         24,  30,  18,  21,  22,  25,  17,  28,  31,  20,  27,  16,  29,  26,  19,  23,
        120, 126, 114, 117, 118, 121, 113, 124, 127, 116, 123, 112, 125, 122, 115, 119,
        232, 238, 226, 229, 230, 233, 225, 236, 239, 228, 235, 224, 237, 234, 227, 231,
        216, 222, 210, 213, 214, 217, 209, 220, 223, 212, 219, 208, 221, 218, 211, 215,
          8,  14,   2,   5,   6,   9,   1,  12,  15,   4,  11,   0,  13,  10,   3,   7,
         88,  94,  82,  85,  86,  89,  81,  92,  95,  84,  91,  80,  93,  90,  83,  87,
        136, 142, 130, 133, 134, 137, 129, 140, 143, 132, 139, 128, 141, 138, 131, 135,
         56,  62,  50,  53,  54,  57,  49,  60,  63,  52,  59,  48,  61,  58,  51,  55,
         72,  78,  66,  69,  70,  73,  65,  76,  79,  68,  75,  64,  77,  74,  67,  71,
        248, 254, 242, 245, 246, 249, 241, 252, 255, 244, 251, 240, 253, 250, 243, 247,
        168, 174, 162, 165, 166, 169, 161, 172, 175, 164, 171, 160, 173, 170, 163, 167,
        104, 110,  98, 101, 102, 105,  97, 108, 111, 100, 107,  96, 109, 106,  99, 103,
        152, 158, 146, 149, 150, 153, 145, 156, 159, 148, 155, 144, 157, 154, 147, 151,
        200, 206, 194, 197, 198, 201, 193, 204, 207, 196, 203, 192, 205, 202, 195, 199,
        184, 190, 178, 181, 182, 185, 177, 188, 191, 180, 187, 176, 189, 186, 179, 183,
         40,  46,  34,  37,  38,  41,  33,  44,  47,  36,  43,  32,  45,  42,  35,  39 }
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует один такт шифрующего преобразования ГОСТ 28147-89 (Mагма) */
 static ak_uint32 ak_magma_gostf( ak_uint32 x )
{
  x = magma_boxes[3][x>>24 & 255] << 24 | magma_boxes[2][x>>16 & 255] << 16 |
                                       magma_boxes[1][x>> 8 & 255] <<  8 | magma_boxes[0][x & 255];
  return x<<11 | x>>(32-11);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования одного блока информации алгоритмом ГОСТ 28147-89 (Магма) */
 static void ak_magma_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  ak_uint32 *kp = (ak_uint32 *) skey->key.data, *mp = (ak_uint32 *) skey->mask.data, p = 0;
  register ak_uint32 n1 = ((ak_uint32 *) in)[0];
  register ak_uint32 n2 = ((ak_uint32 *) in)[1];

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_magma_gostf( p );

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_magma_gostf( p );

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_magma_gostf( p );

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_magma_gostf( p );

 ((ak_uint32 *)out)[0] = n2; ((ak_uint32 *)out)[1] = n1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифрования одного блока информации алгоритмом ГОСТ 28147-89 (Магма) */
 static void ak_magma_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  ak_uint32 *kp = (ak_uint32 *) skey->key.data, *mp = (ak_uint32 *) skey->mask.data, p = 0;
  register ak_uint32 n1 = ((ak_uint32 *) in)[0];
  register ak_uint32 n2 = ((ak_uint32 *) in)[1];

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_magma_gostf( p );

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_magma_gostf( p );

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_magma_gostf( p );

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_magma_gostf( p );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_magma_gostf( p );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_magma_gostf( p );

  ((ak_uint32 *)out)[0] = n2; ((ak_uint32 *)out)[1] = n1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст ключа блочного алгоритма шифрования ГОСТ 28147-89 (Магма)

   После выполнения данной функции создается указатель на контекст ключа и устанавливаются
   обработчики (функции класса). Однако само значение ключу не присваивается -
   поле bkey->key остается равным NULL.

   \b Внимание. Данная функция предназначена для использования другими функциями и не должна
   вызываться напрямую.

   @param oid Параметр oid задает идентификатор таблиц замен, используемых в алгоритме шифрования.
   В случае, если oid равен NULL, используются таблицы по-умолчанию, определяемые ГОСТ Р 34.12-2015.

   @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
   возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value()  */
/* ----------------------------------------------------------------------------------------------- */
 static ak_bckey ak_bckey_magma_new( void )
{
  ak_bckey bkey = NULL;

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( bkey = ak_bckey_new( 32, 8 )) == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "incorrect memory allocation" );
    return NULL;
  }
 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oids_find_by_name( "magma" )) == NULL ) {
    int error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined magma block cipher OID" );
    return ( bkey = ak_bckey_delete( bkey ));
  };

 /* устанавливаем ресурс использования серетного ключа */
  bkey->key.resource.counter = ak_libakrypt_get_magma_resource();

 /* устанавливаем методы */
  bkey->key.data = NULL;
  bkey->key.set_mask = ak_skey_set_mask_additive;
  bkey->key.remask = ak_skey_remask_additive;
  bkey->key.set_icode = ak_skey_set_icode_additive;
  bkey->key.check_icode = ak_skey_check_icode_additive;

  bkey->schedule_keys = NULL;
  bkey->delete_keys = NULL;
  bkey->encrypt = ak_magma_encrypt_with_mask;
  bkey->decrypt = ak_magma_decrypt_with_mask;

 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст ключа алгоритма блочного шифрования ГОСТ 28147-89 (Магма)
    и инициализирует его заданным значением.

    Значение ключа инициализируется значением, содержащемся в области памяти, на которую
    указывает аргумент функции. При инициализации ключевое значение \b копируется в буффер,
    если флаг cflag истиннен. Если флаг ложен, то копирования не происходит.
    Пооведение функции при копировании аналогично поведению функции ak_buffer_set_ptr().

    После присвоения ключа производится его маскирование и выработка контрольной суммы.

    Предпалагается, что основное использование функции ak_bckey_magma_new_buffer()
    заключается в тестировании алгоритма шифрования ГОСТ 28147-89 (Магма) на заданных (тестовых)
    значениях ключей.

    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param cflag флаг владения данными. Если он истинен, то данные копируются в область памяти,
    которой владеет ключевой контекст.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new_magma_ptr( const ak_pointer keyptr, const size_t size, const ak_bool cflag  )
{
  int error = ak_error_ok;
  ak_bckey bkey = NULL;

 /* проверяем входной буффер */
  if( keyptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to key data" );
    return NULL;
  }
  if( size != 32 ) {
    ak_error_message( ak_error_wrong_length, __func__, "using a wrong length of secret key" );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( bkey = ak_bckey_magma_new( )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of magma secret key" );
    return NULL;
  }
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_assign_ptr( &bkey->key, keyptr, size, cflag )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect assigning of key data" );
    return ( bkey = ak_bckey_delete( bkey ));
  }
 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст ключа алгоритма блочного шифрования ГОСТ 28147-89 (Магма)
    и инициализирует его случайным значением.

    Значение ключа вырабатывается генератором псевдо-случайных чисел.
    После присвоения ключа производится его маскирование и выработка контрольной суммы.

    @param generator Указатель на генератор псевдо-случайных чисел.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new_magma_random( ak_random generator )
{
  int error = ak_error_ok;
  ak_bckey bkey = NULL;

 /* проверяем входной буффер */
  if( generator == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                              "using a null pointer to random number generator" );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( bkey = ak_bckey_magma_new( )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of magma secret key" );
    return NULL;
  }
 /* вырабатываем случайные данные */
  if(( error = ak_skey_assign_random( &bkey->key, generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect generation of secret key data" );
    return ( bkey = ak_bckey_delete( bkey ));
  }
 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new_magma_password( const ak_pointer pass, const size_t size )
{
  int error = ak_error_ok;
  ak_bckey bkey = NULL;

 /* проверяем входной буффер */
  if( pass == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to password" );
    return NULL;
  }
  if( size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__, "using a password with zero length" );
    return NULL;
  }

 /* создаем контекст ключа */
  if(( bkey = ak_bckey_magma_new( )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of magma secret key" );
    return NULL;
  }

 /* вырабатываем случайные данные */
  if(( error = ak_skey_assign_password( &bkey->key, pass, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect generation of secret key data" );
    return ( bkey = ak_bckey_delete( bkey ));
  }
 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_magma( void )
{
  int value = 0;
  magma test_boxes;
  char *str = NULL;
  int audit = ak_log_get_level();
  ak_bckey bkey = NULL;

  /*! тестовый ключ из ГОСТ Р 34.12-2015, приложение А.2 */
  ak_uint8 gost3412_2015_key[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  ak_uint8 out[32];
  /*! открытый текст из ГОСТ Р 34.12-2015, приложение А.2, подлежащий зашифрованию */
  ak_uint8 a[8] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
  /*! зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 b[8] = { 0x3d, 0xca, 0xd8, 0xc2, 0xe5, 0x01, 0xe9, 0x4e };
  /*! открытый текст из ГОСТ Р 34.13-2015, приложение А.2 */
  ak_uint64 in_3413_2015_text[4] = {
                   0x92def06b3c130a59, 0xdb54c704f8189d20, 0x4a98fb2e67a8024c, 0x8912409b17b57e41 };
  /*! зашифрованный текст из ГОСТ Р 34.13-2015, приложение А.2 */
  ak_uint64 out_3413_2015_ecb_text[4] = {
                   0x2b073f0494f372a0, 0xde70e715d3556e48, 0x11d8d9e9eacfbc1e, 0x7c68260996c67efb };

  ak_uint8 ctr_iv[4] = { 0x78, 0x56, 0x34, 0x12 };
  ak_uint64 out_3413_2015_ctr_text[4] = {
                   0x4e98110c97b7b93c, 0x3e250d93d6e85d69, 0x136d868807b2dbef, 0x568eb680ab52a12d };

  /* 1. Проверяем корректность развертки перестановок алгоритма Магма */
   ak_kbox_to_magma( (kbox *) cipher_box_magma, test_boxes );
   if(( value = memcmp( test_boxes, magma_boxes, sizeof( magma ))) != 0 ) {
     ak_error_message_fmt( ak_error_not_equal_data, __func__,
                                   "wrong magma boxes comparison with value %d", value );
     return ak_false;
   }

  /* 2. Вырабатываем ключ алгоритма Магма */
   if((bkey = ak_bckey_new_magma_ptr( gost3412_2015_key, 32, ak_false )) == NULL ) {
     ak_error_message( ak_error_get_value(), __func__, "wrong creation of test key" );
     return ak_false;
   }

  /* 3. Тестируем зашифрование/расшифрование одного блока согласно ГОСТ Р34.12-2015 */
   bkey->encrypt( &bkey->key, a, out );
    if( memcmp( out, b, 8 ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                         "the one block encryption test from GOST R 34.12-2015 is wrong");
      ak_log_set_message( str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
      ak_log_set_message( str = ak_ptr_to_hexstr( b, 8, ak_true )); free( str );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the one block encryption test from GOST R 34.12-2015 is Ok" );

   bkey->decrypt( &bkey->key, b, out );
    if( memcmp( out, a, 8 ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                         "the one block decryption test from GOST R 34.12-2015 is wrong");
      ak_log_set_message( str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
      ak_log_set_message( str = ak_ptr_to_hexstr( a, 8, ak_true )); free( str );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the one block decryption test from GOST R 34.12-2015 is Ok" );

  /* 4. Тестируем режим простой замены согласно ГОСТ Р34.13-2015 */
    if( ak_bckey_encrypt_ecb( bkey, in_3413_2015_text, out, 32 ) != ak_error_ok ) {
      ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( memcmp( out, out_3413_2015_ecb_text, 32 ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
      ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free( str );
      ak_log_set_message( str = ak_ptr_to_hexstr( out_3413_2015_ecb_text, 32, ak_true ));
      free( str );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                             "the ecb mode encryption test from GOST R 34.13-2015 is Ok" );

    if( ak_bckey_decrypt_ecb( bkey, out_3413_2015_ecb_text, out, 32 ) != ak_error_ok ) {
      ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( memcmp( out, in_3413_2015_text, 32 ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
      ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free( str );
      ak_log_set_message( str = ak_ptr_to_hexstr( out_3413_2015_ecb_text, 32, ak_true ));
      free( str );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                             "the ecb mode decryption test from GOST R 34.13-2015 is Ok" );

  /* 5. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015 */
    if( ak_bckey_xcrypt_ctr( bkey, in_3413_2015_text, out, 32, ctr_iv ) != ak_error_ok ) {
      ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( memcmp( out, out_3413_2015_ctr_text, 32 ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the ctr mode encryption test from GOST R 34.13-2015 is wrong");
      ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free( str );
      ak_log_set_message( str = ak_ptr_to_hexstr( out_3413_2015_ctr_text, 32, ak_true ));
      free( str );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                             "the ctr mode encryption test from GOST R 34.13-2015 is Ok" );

    if( ak_bckey_xcrypt_ctr( bkey, out_3413_2015_ctr_text, out, 32, ctr_iv ) != ak_error_ok ) {
      ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( memcmp( out, in_3413_2015_text, 32 ) != 0 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the ctr mode decryption test from GOST R 34.13-2015 is wrong");
      ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free( str );
      ak_log_set_message( str = ak_ptr_to_hexstr( in_3413_2015_text, 32, ak_true ));
      free( str );
      bkey = ak_bckey_delete( bkey );
      return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                             "the ctr mode decryption test from GOST R 34.13-2015 is Ok" );

    bkey = ak_bckey_delete( bkey );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_magma.c  */
/* ----------------------------------------------------------------------------------------------- */
