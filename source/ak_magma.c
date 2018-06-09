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
 #include <ak_bckey.h>
 #include <ak_tools.h>
 #include <ak_context_manager.h>

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
/*! \brief  Структура для хранения данных для маскированной реализации Магмы*/
struct masked_magma_data {
  /*! \brief  4 набора s-боксов.*/
  magma* masked_boxes_ptrs[2][2];
  /*! \brief  2 ключевые последовательности - прямая и инвертированная.*/
  ak_uint32 key[2][8];
  /*! \brief  2 маски для 2х ключевых последовательносте соответственно.*/
  ak_uint32 mask[2][8];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует один такт шифрующего преобразования для заданных s-боксов.

    @param x Обрабатываемая половина блока (более детально смотри описание сети Фейстеля).
    @param magma_boxes указытель на s-боксы
    @return Результат криптографического преобразования.                                           */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint32 ak_magma_gostf_boxes( ak_uint32 x, magma* magma_boxes )
{
  x = (*magma_boxes)[3][x>>24 & 255] << 24 | (*magma_boxes)[2][x>>16 & 255] << 16 |
      (*magma_boxes)[1][x>> 8 & 255] <<  8 | (*magma_boxes)[0][x & 255];
  return x<<11 | x>>(32-11);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует один такт шифрующего преобразования ГОСТ 34.12-2015 (Mагма).

    @param x Обрабатываемая половина блока (более детально смотри описание сети Фейстеля).
    @return Результат криптографического преобразования.                                           */
/* ----------------------------------------------------------------------------------------------- */
 static ak_uint32 ak_magma_gostf( ak_uint32 x )
{
  x = magma_boxes[3][x>>24 & 255] << 24 | magma_boxes[2][x>>16 & 255] << 16 |
                                       magma_boxes[1][x>> 8 & 255] <<  8 | magma_boxes[0][x & 255];
  return x<<11 | x>>(32-11);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция развёртывания ключа для маскированной магмы

    В данной функции генерируются дополнительные s-боксы и создаётся инвертированный ключ

    @param skey Указатель на контекст секретного ключа

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static int ak_magma_create_masked_data(ak_skey magma_skey)
{
  struct random r = magma_skey->generator;
  struct masked_magma_data* data = malloc(sizeof(struct masked_magma_data));

  // копируем замаскированный ключ
  memcpy(data->key[0], magma_skey->key.data, sizeof(ak_uint32) * 8);

  // генерируем маску для прямого и инвертированного ключа
  if( r.random(&r, data->mask[0], sizeof(ak_uint32) * 8) != ak_error_ok) {
    return ak_error_message( ak_error_write_data, __func__ , "wrong mask generation for plain key buffer" );
  }
  if( r.random(&r, data->mask[1], sizeof(ak_uint32) * 8) != ak_error_ok) {
    return ak_error_message( ak_error_write_data, __func__ , "wrong mask generation for inverted key buffer" );
  }
  for(int i = 0; i < 8; i++) {
    // добавляем новую маску на прямой ключ
    data->key[0][i] += data->mask[0][i];
    // снимаем старую маску с прямого ключа
    data->key[0][i] -= ((ak_uint32 *) magma_skey->mask.data)[i];
    // инвертируем ключ
    data->key[1][i] = ~(((ak_uint32 *) magma_skey->key.data)[i] - ((ak_uint32 *) magma_skey->mask.data)[i]);
    // добавляем новую маску на инвертированный ключ
    data->key[1][i] += data->mask[1][i];

  }
  // генерируем дополнительные s-боксы
  data->masked_boxes_ptrs[0][0] = (magma *) &magma_boxes;
  data->masked_boxes_ptrs[0][1] = malloc(sizeof(magma));
  data->masked_boxes_ptrs[1][0] = malloc(sizeof(magma));
  data->masked_boxes_ptrs[1][1] = malloc(sizeof(magma));
  for (ak_uint32 i = 0; i < 4; i++) {
    for (ak_uint32 j = 0; j < 256; j++) {
      (*data->masked_boxes_ptrs[0][1])[i][j] = magma_boxes[i][((ak_uint8) j) ^ (ak_uint8) 0xff]; // m1 = 0, m2 = 1
      (*data->masked_boxes_ptrs[1][0])[i][j] = magma_boxes[i][((ak_uint8) j)] ^ (ak_uint8) 0xff; // m1 = 1, m2 = 0
      (*data->masked_boxes_ptrs[1][1])[i][j] = magma_boxes[i][((ak_uint8) j) ^ (ak_uint8) 0xff] ^ (ak_uint8) 0xff; // m1 = 1, m2 = 1
    }
  }

  magma_skey->data = data;
  magma_skey->flags |= ak_skey_flag_data_nonfree;
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция уничтожения развернутых ключей для маскированной магмы

    В данной функции освобождается память выделенная под дополнительные s-боксы а хранящиеся маски
    и ключи заполняются случайнам мусором

    @param skey Указатель на контекст секретного ключа

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static int ak_magma_free_masked_data(ak_skey magma_skey)
{
  struct masked_magma_data* data = magma_skey->data;
  ak_ptr_wipe(data->key[0], sizeof(ak_uint32) * 8, &magma_skey->generator);
  ak_ptr_wipe(data->key[1], sizeof(ak_uint32) * 8, &magma_skey->generator);
  ak_ptr_wipe(data->mask[0], sizeof(ak_uint32) * 8, &magma_skey->generator);
  ak_ptr_wipe(data->mask[1], sizeof(ak_uint32) * 8, &magma_skey->generator);
  free(data->masked_boxes_ptrs[1][1]);
  free(data->masked_boxes_ptrs[1][0]);
  free(data->masked_boxes_ptrs[0][1]);
  free(data);
  return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования одного блока информации алгоритмом ГОСТ 34.12-2015 (Магма).

    @param skey Контекст секретного ключа.
    @param in Блок входной информации (открытый текст).
    @param out Блок выходной информации (шифртекст).                                               */
/* ----------------------------------------------------------------------------------------------- */
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
/*! \brief Функция зашифрования одного блока информации маскированным алгоритмом
    ГОСТ 34.12-2015 (Магма).

    @param skey Контекст секретного ключа.
    @param in Блок входной информации (открытый текст).
    @param out Блок выходной информации (шифртекст).                                               */
/* ----------------------------------------------------------------------------------------------- */
static void ak_masked_magma_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  struct masked_magma_data* magma_data = skey->data;
  ak_uint32 (*kp)[8] = magma_data->key, (*mp)[8]= magma_data->mask, p, mv;
  magma* (*boxes)[2] = magma_data->masked_boxes_ptrs;

  skey->generator.random(&skey->generator, &mv, sizeof(ak_uint32));

  ak_uint8 m[34];
  m[0] = m[33] = 0;
  for (int i = 0; i < 32; i++) {
    m[i+1] = (ak_uint8) ((mv >> i) & 0x01);
  }
  register ak_uint32 n4 = ((ak_uint32 *) in)[1];
  register ak_uint32 n3 = ((ak_uint32 *) in)[0] ^ ( m[1] * 0xffffffff);

  p = (n3 - mp[m[ 1]][7]); p += kp[m[ 1]][7] + m[ 1]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 2] ^ m[ 0]][m[ 1]]);
  p = (n4 - mp[m[ 2]][6]); p += kp[m[ 2]][6] + m[ 2]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 3] ^ m[ 1]][m[ 2]]);
  p = (n3 - mp[m[ 3]][5]); p += kp[m[ 3]][5] + m[ 3]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 4] ^ m[ 2]][m[ 3]]);
  p = (n4 - mp[m[ 4]][4]); p += kp[m[ 4]][4] + m[ 4]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 5] ^ m[ 3]][m[ 4]]);
  p = (n3 - mp[m[ 5]][3]); p += kp[m[ 5]][3] + m[ 5]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 6] ^ m[ 4]][m[ 5]]);
  p = (n4 - mp[m[ 6]][2]); p += kp[m[ 6]][2] + m[ 6]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 7] ^ m[ 5]][m[ 6]]);
  p = (n3 - mp[m[ 7]][1]); p += kp[m[ 7]][1] + m[ 7]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 8] ^ m[ 6]][m[ 7]]);
  p = (n4 - mp[m[ 8]][0]); p += kp[m[ 8]][0] + m[ 8]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 9] ^ m[ 7]][m[ 8]]);

  p = (n3 - mp[m[ 9]][7]); p += kp[m[ 9]][7] + m[ 9]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[10] ^ m[ 8]][m[ 9]]);
  p = (n4 - mp[m[10]][6]); p += kp[m[10]][6] + m[10]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[11] ^ m[ 9]][m[10]]);
  p = (n3 - mp[m[11]][5]); p += kp[m[11]][5] + m[11]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[12] ^ m[10]][m[11]]);
  p = (n4 - mp[m[12]][4]); p += kp[m[12]][4] + m[12]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[13] ^ m[11]][m[12]]);
  p = (n3 - mp[m[13]][3]); p += kp[m[13]][3] + m[13]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[14] ^ m[12]][m[13]]);
  p = (n4 - mp[m[14]][2]); p += kp[m[14]][2] + m[14]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[15] ^ m[13]][m[14]]);
  p = (n3 - mp[m[15]][1]); p += kp[m[15]][1] + m[15]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[16] ^ m[14]][m[15]]);
  p = (n4 - mp[m[16]][0]); p += kp[m[16]][0] + m[16]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[17] ^ m[15]][m[16]]);

  p = (n3 - mp[m[17]][7]); p += kp[m[17]][7] + m[17]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[18] ^ m[16]][m[17]]);
  p = (n4 - mp[m[18]][6]); p += kp[m[18]][6] + m[18]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[19] ^ m[17]][m[18]]);
  p = (n3 - mp[m[19]][5]); p += kp[m[19]][5] + m[19]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[20] ^ m[18]][m[19]]);
  p = (n4 - mp[m[20]][4]); p += kp[m[20]][4] + m[20]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[21] ^ m[19]][m[20]]);
  p = (n3 - mp[m[21]][3]); p += kp[m[21]][3] + m[21]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[22] ^ m[20]][m[21]]);
  p = (n4 - mp[m[22]][2]); p += kp[m[22]][2] + m[22]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[23] ^ m[21]][m[22]]);
  p = (n3 - mp[m[23]][1]); p += kp[m[23]][1] + m[23]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[24] ^ m[22]][m[23]]);
  p = (n4 - mp[m[24]][0]); p += kp[m[24]][0] + m[24]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[25] ^ m[23]][m[24]]);

  p = (n3 - mp[m[25]][0]); p += kp[m[25]][0] + m[25]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[26] ^ m[24]][m[25]]);
  p = (n4 - mp[m[26]][1]); p += kp[m[26]][1] + m[26]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[27] ^ m[25]][m[26]]);
  p = (n3 - mp[m[27]][2]); p += kp[m[27]][2] + m[27]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[28] ^ m[26]][m[27]]);
  p = (n4 - mp[m[28]][3]); p += kp[m[28]][3] + m[28]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[29] ^ m[27]][m[28]]);
  p = (n3 - mp[m[29]][4]); p += kp[m[29]][4] + m[29]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[30] ^ m[28]][m[29]]);
  p = (n4 - mp[m[30]][5]); p += kp[m[30]][5] + m[30]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[31] ^ m[29]][m[30]]);
  p = (n3 - mp[m[31]][6]); p += kp[m[31]][6] + m[31]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[32] ^ m[30]][m[31]]);
  p = (n4 - mp[m[32]][7]); p += kp[m[32]][7] + m[32]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[33] ^ m[31]][m[32]]);

  ((ak_uint32 *)out)[0] = n4 ^ (m[32] * 0xffffffff); ((ak_uint32 *)out)[1] = n3;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифрования одного блока информации алгоритмом ГОСТ 34.12-2015 (Магма).

    @param skey Контекст секретного ключа.
    @param in Блок входной информации (шифртекст).
    @param out Блок выходной информации (открытый текст).                                          */
/* ----------------------------------------------------------------------------------------------- */
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
/*! \brief Функция расшифрования одного блока информации маскированного
    алгоритмом ГОСТ 34.12-2015 (Магма).

    @param skey Контекст секретного ключа.
    @param in Блок входной информации (шифртекст).
    @param out Блок выходной информации (открытый текст).                                          */
/* ----------------------------------------------------------------------------------------------- */
static void ak_masked_magma_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{

  struct masked_magma_data* magma_data = skey->data;
  ak_uint32 (*kp)[8] = magma_data->key, (*mp)[8]= magma_data->mask, p =0, mv;
  magma* (*boxes)[2] = magma_data->masked_boxes_ptrs;

  skey->generator.random(&skey->generator, &mv, sizeof(ak_uint32));

  ak_uint8 m[34];
  m[0] = m[33] = 0;
  for (int i = 0; i < 32; i++) {
    m[i+1] = (ak_uint8) ((mv >> i) & 0x01);
  }

  register ak_uint32 n4 = ((ak_uint32 *) in)[1];
  register ak_uint32 n3 = ((ak_uint32 *) in)[0] ^ ( m[1] * 0xffffffff);

  p = (n3 - mp[m[ 1]][7]); p += kp[m[ 1]][7] + m[ 1]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 2] ^ m[ 0]][m[ 1]]);
  p = (n4 - mp[m[ 2]][6]); p += kp[m[ 2]][6] + m[ 2]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 3] ^ m[ 1]][m[ 2]]);
  p = (n3 - mp[m[ 3]][5]); p += kp[m[ 3]][5] + m[ 3]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 4] ^ m[ 2]][m[ 3]]);
  p = (n4 - mp[m[ 4]][4]); p += kp[m[ 4]][4] + m[ 4]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 5] ^ m[ 3]][m[ 4]]);
  p = (n3 - mp[m[ 5]][3]); p += kp[m[ 5]][3] + m[ 5]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 6] ^ m[ 4]][m[ 5]]);
  p = (n4 - mp[m[ 6]][2]); p += kp[m[ 6]][2] + m[ 6]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 7] ^ m[ 5]][m[ 6]]);
  p = (n3 - mp[m[ 7]][1]); p += kp[m[ 7]][1] + m[ 7]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[ 8] ^ m[ 6]][m[ 7]]);
  p = (n4 - mp[m[ 8]][0]); p += kp[m[ 8]][0] + m[ 8]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[ 9] ^ m[ 7]][m[ 8]]);

  p = (n3 - mp[m[ 9]][0]); p += kp[m[ 9]][0] + m[ 9]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[10] ^ m[ 8]][m[ 9]]);
  p = (n4 - mp[m[10]][1]); p += kp[m[10]][1] + m[10]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[11] ^ m[ 9]][m[10]]);
  p = (n3 - mp[m[11]][2]); p += kp[m[11]][2] + m[11]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[12] ^ m[10]][m[11]]);
  p = (n4 - mp[m[12]][3]); p += kp[m[12]][3] + m[12]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[13] ^ m[11]][m[12]]);
  p = (n3 - mp[m[13]][4]); p += kp[m[13]][4] + m[13]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[14] ^ m[12]][m[13]]);
  p = (n4 - mp[m[14]][5]); p += kp[m[14]][5] + m[14]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[15] ^ m[13]][m[14]]);
  p = (n3 - mp[m[15]][6]); p += kp[m[15]][6] + m[15]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[16] ^ m[14]][m[15]]);
  p = (n4 - mp[m[16]][7]); p += kp[m[16]][7] + m[16]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[17] ^ m[15]][m[16]]);

  p = (n3 - mp[m[17]][0]); p += kp[m[17]][0] + m[17]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[18] ^ m[16]][m[17]]);
  p = (n4 - mp[m[18]][1]); p += kp[m[18]][1] + m[18]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[19] ^ m[17]][m[18]]);
  p = (n3 - mp[m[19]][2]); p += kp[m[19]][2] + m[19]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[20] ^ m[18]][m[19]]);
  p = (n4 - mp[m[20]][3]); p += kp[m[20]][3] + m[20]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[21] ^ m[19]][m[20]]);
  p = (n3 - mp[m[21]][4]); p += kp[m[21]][4] + m[21]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[22] ^ m[20]][m[21]]);
  p = (n4 - mp[m[22]][5]); p += kp[m[22]][5] + m[22]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[23] ^ m[21]][m[22]]);
  p = (n3 - mp[m[23]][6]); p += kp[m[23]][6] + m[23]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[24] ^ m[22]][m[23]]);
  p = (n4 - mp[m[24]][7]); p += kp[m[24]][7] + m[24]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[25] ^ m[23]][m[24]]);

  p = (n3 - mp[m[25]][0]); p += kp[m[25]][0] + m[25]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[26] ^ m[24]][m[25]]);
  p = (n4 - mp[m[26]][1]); p += kp[m[26]][1] + m[26]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[27] ^ m[25]][m[26]]);
  p = (n3 - mp[m[27]][2]); p += kp[m[27]][2] + m[27]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[28] ^ m[26]][m[27]]);
  p = (n4 - mp[m[28]][3]); p += kp[m[28]][3] + m[28]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[29] ^ m[27]][m[28]]);
  p = (n3 - mp[m[29]][4]); p += kp[m[29]][4] + m[29]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[30] ^ m[28]][m[29]]);
  p = (n4 - mp[m[30]][5]); p += kp[m[30]][5] + m[30]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[31] ^ m[29]][m[30]]);
  p = (n3 - mp[m[31]][6]); p += kp[m[31]][6] + m[31]; n4 ^= ak_magma_gostf_boxes(p, boxes[m[32] ^ m[30]][m[31]]);
  p = (n4 - mp[m[32]][7]); p += kp[m[32]][7] + m[32]; n3 ^= ak_magma_gostf_boxes(p, boxes[m[33] ^ m[31]][m[32]]);

  ((ak_uint32 *)out)[0] = n4 ^ (m[32] * 0xffffffff); ((ak_uint32 *)out)[1] = n3;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Наложение аддитивной в кольце \f$ \mathbb Z_{2^{32}}\f$ маски на ключ.

    Функция рассматривает вектор ключа как последовательность \f$ k_1, \ldots, k_n\f$, состоящую
    из элементов кольца  \f$ \mathbb Z_{2^{32}}\f$. Функция вырабатывает случайный вектор
    \f$ x_1, \ldots, x_n\f$ и заменяет ключевой вектор на последовательность значений
    \f$ k_1 + x_1 \pmod{2^{32}}, \ldots, k_n + x_n \pmod{2^{32}}\f$.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_set_mask_additive( ak_skey skey )
{
  size_t idx = 0;
  int error = ak_error_ok;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* проверяем длину ключа */
  if( skey->key.size != 32 ) return ak_error_message( ak_error_undefined_value, __func__ ,
                                                          "using a key buffer with wrong length" );
 /* создаем маску*/
  if( skey->generator.random( &skey->generator, skey->mask.data, skey->mask.size ) != ak_error_ok )
    return ak_error_message( ak_error_write_data, __func__ ,
                                                          "wrong mask generation for key buffer" );
 /* накладываем маску на ключ */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ )
     ((ak_uint32 *) skey->key.data)[idx] += ((ak_uint32 *) skey->mask.data)[idx];

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Смена значения аддитивной в кольце \f$ \mathbb Z_{2^{32}}\f$ маски ключа.


    Функция вычисляет новый случайный вектор \f$ y_1, \ldots, y_n\f$ и изменяет значение
    значение ключа, снимая старую маску и накладывая новую.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_remask_additive( ak_skey skey )
{
  size_t idx = 0;
  ak_uint32 newmask[8];
  int error = ak_error_ok;

  /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                         "key length is too big" );
 /* вырабатываем случайные данные */
  if( skey->generator.random( &skey->generator, newmask, skey->key.size ) != ak_error_ok )
    return ak_error_message( ak_error_undefined_value, __func__ , "wrong random mask generation" );

 /* накладываем маску */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ ) {
     ((ak_uint32 *) skey->key.data)[idx] += newmask[idx];
     ((ak_uint32 *) skey->key.data)[idx] -= ((ak_uint32 *) skey->mask.data)[idx];
     ((ak_uint32 *) skey->mask.data)[idx] = newmask[idx];
  }

 /* удаляем старое */
  memset( newmask, 0, 32 );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Смена значения аддитивной в кольце \f$ \mathbb Z_{2^{32}}\f$
    маски ключа для маскированной Магмы.


    Функция вычисляет новый случайный вектор \f$ y_1, \ldots, y_n\f$ и изменяет значение
    значение ключа, снимая старую маску и накладывая новую.

    Если секретный ключ содержит данные для маскированной магмы, то таже операция применяется к
    прямому и инвертированному ключу.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
static int ak_skey_remask_additive_with_masked_data( ak_skey skey )
{
  size_t idx = 0;
  ak_uint32 newmask[8];
  int error = ak_error_ok;

  /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                      "key length is too big" );
  /* вырабатываем случайные данные */
  if( skey->generator.random( &skey->generator, newmask, skey->key.size ) != ak_error_ok )
    return ak_error_message( ak_error_undefined_value, __func__ , "wrong random mask generation" );

  /* накладываем маску */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ ) {
    ((ak_uint32 *) skey->key.data)[idx] += newmask[idx];
    ((ak_uint32 *) skey->key.data)[idx] -= ((ak_uint32 *) skey->mask.data)[idx];
    ((ak_uint32 *) skey->mask.data)[idx] = newmask[idx];
  }

  if (skey->data != NULL) {
    struct masked_magma_data *masked_data = skey->data;
    ak_uint32 newmask2[8];
    /* вырабатываем случайные данные */
    if( skey->generator.random( &skey->generator, newmask, skey->key.size ) != ak_error_ok )
      return ak_error_message( ak_error_undefined_value, __func__ , "wrong random mask generation" );
    if( skey->generator.random( &skey->generator, newmask2, skey->key.size ) != ak_error_ok )
      return ak_error_message( ak_error_undefined_value, __func__ , "wrong random mask generation" );
    /* накладываем маски */
    for( idx = 0; idx < (skey->key.size >> 2); idx++ ) {
      masked_data->key[0][idx] += newmask[idx];
      masked_data->key[1][idx] += newmask2[idx];
      masked_data->key[0][idx] -= masked_data->mask[0][idx];
      masked_data->key[1][idx] -= masked_data->mask[1][idx];
      masked_data->mask[0][idx] = newmask[idx];
      masked_data->mask[1][idx] = newmask2[idx];
    }
    memset( newmask2, 0, 32 );
  }

 /* удаляем старое */
  memset( newmask, 0, 32 );
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейная перестановка в кольце \f$ \mathbb Z_{2^{64}} \f$

    Функция реализует преобразование, которое можно рассматривать как нелинейную
    перестановку \f$ \pi \f$ элементов кольца \f$ \mathbb Z_{2^{64}} \f$, задаваемое следующим образом.

    Пусть \f$ \overline x \f$ есть побитовое инвертирование переменной x,
    a \f$ f(x,y)\in\mathbb Z[x]\f$ многочлен,
    определяемый равенством \f$ f(x,y) = \frac{1}{2}\left( (x+y)^2 + x + 3y \right)\f$. Тогда
    перестановка \f$ \pi \f$ определяется равенством
    \f$ \pi(x,y) = const \oplus
                    \left\{ \begin{array}{ll}
                              f(x,y), & x+y < 2^{32}, \\
                              \overline{f(\overline{x},\overline{y})}, & 2^{32} \le x+y < 2^{64}.
                            \end{array}
                    \right.\f$

    @param xv Величина \f$ x \in \mathbb Z_{2^{32}} \f$
    @param yv Величина \f$ y \in \mathbb Z_{2^{32}} \f$
    @return Значение перестановки \f$ \pi \f$                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static ak_uint64 ak_skey_icode_permutation( const ak_uint32 xv, const ak_uint32 yv )
{
  ak_uint32 x = xv, y = yv, carry = 0;
  ak_uint64 s =  ( ak_uint64 )x + y, more = s&0x100000000, result = 0;

  if( more ) { x = ~x; y = ~y; s = ( ak_uint64 )x + y; }
  result = y; result *= 3; result += x;
  s *= s; result += s; if( result < s ) carry = 1;

  result >>= 1;
  if( carry ) result ^= 0x8000000000000000L;
  if( more ) result = ~result;
 return result^0xC5BF891B4EF6AA79L; // константа есть \sqrt{\pi}
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Реализация алгоритма вычисления контрольной суммы для аддитивной маски ключа */
 static void ak_skey_icode_additive_sum( ak_skey skey, ak_uint64 *result )
{
  size_t i = 0;
  for( i = 0; i < (skey->key.size >> 2); i+=4 ) {
     ak_uint32 x = ((ak_uint32 *) skey->key.data)[i],
               y = ((ak_uint32 *) skey->key.data)[i+2];
     x += ((ak_uint32 *) skey->key.data)[i+1];
     y += ((ak_uint32 *) skey->key.data)[i+3];
     x -= ((ak_uint32 *) skey->mask.data)[i];
     x -= ((ak_uint32 *) skey->mask.data)[i+1];
     y -= ((ak_uint32 *) skey->mask.data)[i+2];
     y -= ((ak_uint32 *) skey->mask.data)[i+3];
     *result += ak_skey_icode_permutation( x, y );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление значения контрольной суммы ключа.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_set_icode_additive( ak_skey skey )
{
  ak_uint64 result = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* проверяем длину ключа */
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                          "using a key buffer with wrong length" );
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "using undefined mask buffer" );
  if( skey->icode.size != 8 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                 "using integrity code buffer with wrong length" );

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_additive_sum( skey, &result );
  memcpy( skey->icode.data, &result, 8 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка значения контрольной суммы ключа.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 static ak_bool ak_skey_check_icode_additive( ak_skey skey )
{
  ak_uint64 result = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* проверяем наличие и длину ключа */
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "using a key buffer with wrong length" );
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined mask buffer" );
  if( skey->icode.size != 8 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                  "using integrity code buffer with wrong length" );

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_additive_sum( skey, &result );
 /* и сравнение */
  if( memcmp( skey->icode.data, &result, 8 )) return ak_false;
   else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализируете контекст ключа блочного алгоритма шифрования Магма.
    После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    @param bkey Контекст секретного ключа алгоритма блочного шифрования.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_magma( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to block cipher key context" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_create( bkey, 32, 8 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_find_by_name( "magma" )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined magma block cipher OID" );
    ak_bckey_destroy( bkey );
    return error;
  };

 /* устанавливаем ресурс использования серетного ключа */
  bkey->key.resource.counter = ak_libakrypt_get_option( "magma_cipher_resource" );

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

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализируете контекст ключа блочного маскированного алгоритма шифрования Магма.
    После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    @param bkey Контекст секретного ключа алгоритма блочного шифрования.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_masked_magma( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to block cipher key context" );

  /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_create( bkey, 32, 8 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

  /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_find_by_name( "magma" )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined magma block cipher OID" );
    ak_bckey_destroy( bkey );
    return error;
  };

  /* устанавливаем ресурс использования серетного ключа */
  bkey->key.resource.counter = ak_libakrypt_get_option( "magma_cipher_resource" );

  /* устанавливаем методы */
  bkey->key.data = NULL;
  bkey->key.set_mask = ak_skey_set_mask_additive;
  bkey->key.remask = ak_skey_remask_additive_with_masked_data;
  bkey->key.set_icode = ak_skey_set_icode_additive;
  bkey->key.check_icode = ak_skey_check_icode_additive;

  bkey->schedule_keys = ak_magma_create_masked_data;
  bkey->delete_keys = ak_magma_free_masked_data;
  bkey->encrypt = ak_masked_magma_encrypt_with_mask;
  bkey->decrypt = ak_masked_magma_decrypt_with_mask;

  return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализующая общую часть тестирования алгоритма Магма (как обычного так и маскированного)

    @param magma Контекст секретного ключа алгоритма Магма.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_test_magma_common( ak_bckey magma ) {
  char *str = NULL;
  ak_uint8 out[32];
  int error = ak_error_ok, audit = ak_log_get_level();

  ak_uint8 gost3412_2015_key[32] = { /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.2 */
      0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  /* подлежащий зашифрованию открытый текст из ГОСТ Р 34.12-2015, приложение А.2 */
  ak_uint8 a[8] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
  /* зашифрованный текст из ГОСТ Р 34.12-2015 */
  ak_uint8 b[8] = { 0x3d, 0xca, 0xd8, 0xc2, 0xe5, 0x01, 0xe9, 0x4e };

  /* открытый текст из ГОСТ Р 34.13-2015, приложение А.2 */
  ak_uint64 in_3413_2015_text[4] = {
      0x92def06b3c130a59, 0xdb54c704f8189d20, 0x4a98fb2e67a8024c, 0x8912409b17b57e41 };
  /* зашифрованный в режиме простой замены текст из ГОСТ Р 34.13-2015, приложение А.2 */
  ak_uint64 out_3413_2015_ecb_text[4] = {
      0x2b073f0494f372a0, 0xde70e715d3556e48, 0x11d8d9e9eacfbc1e, 0x7c68260996c67efb };

  /* синхропосылка и зашифрованный в режиме гаммирования текст из ГОСТ Р 34.13-2015, приложение А.2 */
  ak_uint8 ctr_iv[4] = { 0x78, 0x56, 0x34, 0x12 };
  ak_uint64 out_3413_2015_ctr_text[4] = {
      0x4e98110c97b7b93c, 0x3e250d93d6e85d69, 0x136d868807b2dbef, 0x568eb680ab52a12d };

  /* 2. Присваиваем ключу константное значение */
  if( ak_bckey_context_set_ptr( magma, gost3412_2015_key, 32, ak_false ) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong assigning a predefined value to magma secret key " );
    return error;
  }

  /* 3. Тестируем зашифрование/расшифрование одного блока согласно ГОСТ Р34.12-2015 */
  magma->encrypt( &magma->key, a, out );
  if( !ak_ptr_is_equal( out, b, 8 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the one block encryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( b, 8, ak_true )); free( str );
    error = ak_error_not_equal_data;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the one block encryption test from GOST R 34.12-2015 is Ok" );
  magma->decrypt( &magma->key, b, out );
  if( !ak_ptr_is_equal( out, a, 8 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the one block decryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( a, 8, ak_true )); free( str );
    error = ak_error_not_equal_data;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the one block decryption test from GOST R 34.12-2015 is Ok" );

  /* 4. Тестируем режим простой замены согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_encrypt_ecb( magma, in_3413_2015_text, out, 32 )) != ak_error_ok )
  {
    ak_error_message_fmt( error, __func__ , "wrong plain text encryption" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, out_3413_2015_ecb_text, 32 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free(str);
    ak_log_set_message( str = ak_ptr_to_hexstr( out_3413_2015_ecb_text, 32, ak_true )); free(str);
    error = ak_error_not_equal_data;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the ecb mode encryption test from GOST R 34.13-2015 is Ok" );

  if(( error = ak_bckey_context_decrypt_ecb( magma, out_3413_2015_ecb_text, out, 32 )) != ak_error_ok )
  {
    ak_error_message_fmt( error, __func__ , "wrong cipher text decryption" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, in_3413_2015_text, 32 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free(str);
    ak_log_set_message( str = ak_ptr_to_hexstr( in_3413_2015_text, 32, ak_true )); free(str);
    error = ak_error_not_equal_data;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the ecb mode decryption test from GOST R 34.13-2015 is Ok" );

  /* 5. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015 */
  if( ak_bckey_context_xcrypt( magma, in_3413_2015_text, out, 32, ctr_iv, sizeof( ctr_iv )) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong plain text encryption" );
    error = ak_error_get_value();
    goto exit;
  }
  if( !ak_ptr_is_equal( out, out_3413_2015_ctr_text, 32 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the counter mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out_3413_2015_ctr_text, 32, ak_true )); free(str);
    error = ak_error_not_equal_data;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the counter mode encryption test from GOST R 34.13-2015 is Ok" );

  if( ak_bckey_context_xcrypt( magma, out_3413_2015_ctr_text, out, 32, ctr_iv, sizeof( ctr_iv )) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong cipher text decryption" );;
    error = ak_error_get_value();
    goto exit;
  }
  if( !ak_ptr_is_equal( out, in_3413_2015_text, 32 )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                          "the counter mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( in_3413_2015_text, 32, ak_true )); free( str );
    error = ak_error_not_equal_data;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                  "the counter mode decryption test from GOST R 34.13-2015 is Ok" );
  /* освобождаем ключ и выходим */
  exit:

  if(ak_bckey_destroy( magma ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong destroying of magma secret key" );
    return ak_error_get_value();
  }

 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование производится в соответствии с примерами из ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015. */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_magma( void )
{
  int error = ak_error_ok, audit = ak_log_get_level();;
  struct bckey bkey; /* контекст используемого для тестов ключа */

  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "start testing of magma block cipher" );

 /* 1. Инициализируем ключ алгоритма Магма */
  if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of magma secret key" );
    return ak_false;
  }

  if (( error = ak_bckey_test_magma_common(&bkey)) != ak_error_ok) {
    ak_error_message( error, __func__ , "testing of magma block cipher failed" );
    return ak_false;
  };

  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing of magma block cipher successfully finished" );

  return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование производится в соответствии с примерами из ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015. */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_bckey_test_masked_magma( void )
{
  int error = ak_error_ok, audit = ak_log_get_level();;
  struct bckey bkey; /* контекст используемого для тестов ключа */

  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "start testing of masked magma block cipher" );

  /* 1. Инициализируем ключ маскированного алгоритма Магма */
  if(( error = ak_bckey_create_masked_magma( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of masked magma secret key" );
    return ak_false;
  }

  if (( error = ak_bckey_test_magma_common(&bkey)) != ak_error_ok) {
    ak_error_message( error, __func__ , "testing masked of magma block cipher failed" );
    return ak_false;
  };

  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing of masked magma block cipher successfully finished" );

  return ak_true;
}
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_magma.c  */
/* ----------------------------------------------------------------------------------------------- */
