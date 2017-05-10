/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2008 - 2017 by Mikhail Tsyganov, tsyganov.michail@yandex.ru                                     */
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
/*   ak_rc6.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */

#include <stdint.h>
#include <stdlib.h>
#include <ak_skey.h>

/* ----------------------------------------------------------------------------------------------- */

#define RC6_ROUNDS  20              /* Количество раундов */
#define KEY_LENGTH  256             /* Длина ключа в битах */
#define W           32              /* Длина машинного слова в битах */
#define P32         0xB7E15163      /* "Магическая" константа на основе экспоненты */
#define Q32         0x9E3779B9      /* "Магическая" константа на основе золотого сечения */
#define LG_W        5               /* Значение двоичного логарифма от W (log2(32)) */

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет циклический сдвиг 32-битного числа влево. */
ak_uint32 rol32(ak_uint32 a, ak_uint8 n)
{
    return (a << n) | (a >> (32 - n));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет циклический сдвиг 32-битного числа вправо. */
ak_uint32 ror32(ak_uint32 a, ak_uint8 n)
{
    return (a >> n) | (a << (32 - n));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет развертку ключа. */
int ak_rc6_key_schedule(ak_skey ctx)
{
    /* Копируем маскированный ключ */
    ctx->data = (ak_uint32 *)calloc(2*RC6_ROUNDS+4, sizeof(ak_uint32));
    ak_uint32 *key = calloc(8, sizeof(ak_uint32));
    memcpy(key, ctx->key.data, 32);

    /* Развертываем начальную последовательность раундовых ключей */
    ((ak_uint32*)ctx->data)[0] = P32;
    ak_uint8 i = 0, j = 0;
    for(i = 1; i <= 2*RC6_ROUNDS+3; ++i)
        ((ak_uint32*)ctx->data)[i] = ((ak_uint32*)ctx->data)[i-1] + Q32;

    /* Модифицируем раундовые ключи с помощью пользовательского ключа */
    i = 0;
    ak_uint32 a = 0, b = 0;
    ak_uint8 masked = 0;
    for(ak_uint8 k=1; k< 3*(2*RC6_ROUNDS+4)+1; ++k)
    {
        if (masked < KEY_LENGTH/W) {
            key[j] -= ((ak_uint32*)ctx->mask.data)[j];
            masked++;
        }
        a = ((ak_uint32 *)ctx->data)[i] = rol32(((ak_uint32 *)ctx->data)[i] + a + b, 3);
        b = key[j] = rol32(key[j] + a + b, a + b);
        i = (i+1) % (2*RC6_ROUNDS+4);
        j = (j+1) % (KEY_LENGTH/W);
    }
    free(key);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет удаление текущих раундовых ключей. */
int ak_rc6_key_delete(ak_skey ctx)
{
    free(ctx->data);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет зашифрование одного блока информации алгоритмом RC6. */
void ak_rc6_encrypt(ak_skey ctx, ak_pointer in, ak_pointer out)
{
    register ak_uint32 A = ((ak_uint32 *)in)[0];
    register ak_uint32 B = ((ak_uint32 *)in)[1];
    register ak_uint32 C = ((ak_uint32 *)in)[2];
    register ak_uint32 D = ((ak_uint32 *)in)[3];

    B += ((ak_uint32 *)(ctx->data))[0];
    D += ((ak_uint32 *)(ctx->data))[1];
    ak_uint32 t=0, u=0, temp_reg;
    for(ak_uint8 i = 1; i < RC6_ROUNDS+1; ++i)
    {
        t = rol32((B * (2 * B + 1)), LG_W);
        u = rol32((D * (2 * D + 1)), LG_W);
        A = rol32(A ^ t, u) + ((ak_uint32*)ctx->data)[2*i];
        C = rol32(C ^ u, t) + ((ak_uint32*)ctx->data)[2*i+1];
        temp_reg = A;
        A = B;
        B = C;
        C = D;
        D = temp_reg;
    }
    A += ((ak_uint32*)ctx->data)[2*RC6_ROUNDS + 2];
    C += ((ak_uint32*)ctx->data)[2*RC6_ROUNDS + 3];
    ((ak_uint32 *)out)[0]=A;
    ((ak_uint32 *)out)[1]=B;
    ((ak_uint32 *)out)[2]=C;
    ((ak_uint32 *)out)[3]=D;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет расшифрование одного блока информации алгоритмом RC6. */
void ak_rc6_decrypt(ak_skey ctx, ak_pointer in, ak_pointer out)
{
    register ak_uint32 A = ((ak_uint32 *)in)[0];
    register ak_uint32 B = ((ak_uint32 *)in)[1];
    register ak_uint32 C = ((ak_uint32 *)in)[2];
    register ak_uint32 D = ((ak_uint32 *)in)[3];

    C -= ((ak_uint32*)ctx->data)[2*RC6_ROUNDS + 3];
    A -= ((ak_uint32*)ctx->data)[2*RC6_ROUNDS + 2];
    ak_uint32 t=0, u=0, temp_reg;
    for(ak_uint8 i = RC6_ROUNDS; i > 0; --i)
    {
        temp_reg = D;
        D = C;
        C = B;
        B = A;
        A = temp_reg;
        t = rol32((B*(2*B+1)), LG_W);
        u = rol32((D*(2*D+1)), LG_W);
        C = ror32((C-((ak_uint32*)ctx->data)[2*i+1]), t) ^ u;
        A = ror32((A-((ak_uint32*)ctx->data)[2*i]), u) ^ t;
    }
    D -= ((ak_uint32*)ctx->data)[1];
    B -= ((ak_uint32*)ctx->data)[0];
    ((ak_uint32 *)out)[0]=A;
    ((ak_uint32 *)out)[1]=B;
    ((ak_uint32 *)out)[2]=C;
    ((ak_uint32 *)out)[3]=D;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст ключа блочного алгоритма шифрования RC6

   После выполнения данной функции создается указатель на контекст ключа и устанавливаются
   обработчики (функции класса). Однако само значение ключу не присваивается -
   поле bkey->key остается равным NULL.

   \b Внимание. Данная функция предназначена для использования другими функциями и не должна
   вызываться напрямую.

   @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
   возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value()  */
/* ----------------------------------------------------------------------------------------------- */
ak_bckey ak_bckey_rc6_new(void)
{
    ak_bckey bkey = NULL;

    /* Cоздаем ключ алгоритма шифрования и определяем его методы */
    if(( bkey = ak_bckey_new( 32, 16 )) == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__ , "incorrect memory allocation" );
        return NULL;
    }

    /* Устанавливаем OID алгоритма шифрования */
    if(( bkey->key.oid = ak_oids_find_by_name( "rc6" )) == NULL ) {
        int error = ak_error_get_value();
        ak_error_message( error, __func__, "wrong search of predefined rc6 block cipher OID" );
        return ( bkey = ak_bckey_delete( bkey ));
    }

    /* Устанавливаем остальные данные ключа */
    bkey->key.data =        NULL;
    bkey->key.set_mask =    ak_skey_set_mask_additive;
    bkey->key.remask =      ak_skey_remask_additive;
    bkey->key.set_icode =   ak_skey_set_icode_additive;
    bkey->key.check_icode = ak_skey_check_icode_additive;

    /* Устанавливаем методы */
    bkey->shedule_keys =    ak_rc6_key_schedule;
    bkey->delete_keys =     ak_rc6_key_delete;
    bkey->encrypt =         ak_rc6_encrypt;
    bkey->decrypt =         ak_rc6_decrypt;

    return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст ключа алгоритма блочного шифрования RC6
    и инициализирует его заданным значением.

    Значение ключа инициализируется значением, содержащемся в области памяти, на которую
    указывает аргумент функции. При инициализации ключевое значение \b копируется в буффер,
    если флаг cflag истиннен. Если флаг ложен, то копирования не происходит.
    Поведение функции при копировании аналогично поведению функции ak_buffer_set_ptr().

    После присвоения ключа производится его развёртка, маскирование и выработка контрольной суммы.

    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param size размер ключа в байтах.
    @param cflag флаг владения данными. Если он истинен, то данные копируются в область памяти,
    которой владеет ключевой контекст.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
ak_bckey ak_bckey_new_rc6_ptr(const ak_pointer keyptr, const size_t size, const ak_bool cflag)
{
    int error = ak_error_ok;
    ak_bckey bkey = NULL;

    /* Проверяем входной буфер */
    if( keyptr == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to key data" );
        return NULL;
    }

    /* Проверяем размер ключа */
    if( size != 32 ) {
        ak_error_message( ak_error_wrong_length, __func__, "using a wrong length of secret key" );
        return NULL;
    }

    /* Создаем контекст ключа */
    if(( bkey = ak_bckey_rc6_new( )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of rc6 secret key" );
        return NULL;
    }

    /* Присваиваем ключевой буфер */
    if(( error = ak_skey_assign_ptr( &bkey->key, keyptr, size, cflag )) != ak_error_ok ) {
        ak_error_message( error, __func__ , "incorrect assigning of key data" );
        return ( bkey = ak_bckey_delete( bkey ));
    }

    /* Генерируем раундовые ключи */
    bkey->shedule_keys(&bkey->key);

    return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция тестирования алгоритма RC6. */
ak_bool ak_bckey_test_rc6(void)
{
    /*! Проверка тестовых векторов для ключа 256 бит
     *  The RC6 (TM) Block Cipher
     *  Ronald L. Rivest, M.J.B. Robshaw, R. Sidney, and Y.L. Yin
     *  Страница 20
     */

    /* Тестовые векторы 1 (нулевые вектора) + шифртекст */
    ak_uint8 user_key_1[32]       = {0};
    ak_uint8 user_text_1[16]      = {0};
    ak_uint8 cipher_text_1[16]    = {0x8f, 0x5f, 0xbd, 0x05, 0x10, 0xd1, 0x5f, 0xa8, 0x93, 0xfa, 0x3f, 0xda, 0x6e, 0x85, 0x7e, 0xc2};

    /* Прочие данные для тестирования */
    ak_uint8 out[16];
    ak_bckey bkey = NULL;
    int audit = ak_log_get_level();
    char *str = NULL;

    /* Создаем тестовый ключ */
    if ((bkey = ak_bckey_new_rc6_ptr(user_key_1, 32, ak_true))==NULL) {
        ak_error_message( ak_error_get_value(), __func__, "[TEST 1] wrong creation of test key" );
        return ak_false;
    }

    /* Тестируем зашифрование одного блока информации */
    bkey->encrypt(&bkey->key, user_text_1, out);
    if (memcmp(out, cipher_text_1, 16) != 0) {
        ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                           "[TEST 1] the one block encryption test from RC6 is wrong");
        ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
        ak_log_set_message( str = ak_ptr_to_hexstr( cipher_text_1, 16, ak_true )); free( str );
        //bkey = ak_bckey_delete(bkey);
        return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "[TEST 1] the one block encryption test from RC6 is Ok" );

    /* Тестируем расшифрование одного блока информации */
    bkey->decrypt(&bkey->key, cipher_text_1, out);
    if (memcmp(user_text_1, out, 16) != 0) {
        ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                           "[TEST 1] the one block decryption test from RC6 is wrong");
        ak_log_set_message( str = ak_ptr_to_hexstr( user_text_1, 16, ak_true )); free( str );
        ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
        //bkey = ak_bckey_delete(bkey);
        return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                            "[TEST 1] the one block decryption test from RC6 is Ok" );

    //bkey = ak_bckey_delete(bkey);

    /* ----------------------------------------------------------------------------------------------- */
    /* Тестовые векторы 2 + шифртекст */

    ak_uint8 user_key_2[32]    = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
                                  0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe};
    ak_uint8 user_text_2[16]   = {0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1};
    ak_uint8 cipher_text_2[16] = {0xc8, 0x24, 0x18, 0x16, 0xf0, 0xd7, 0xe4, 0x89, 0x20, 0xad, 0x16, 0xa1, 0x67, 0x4e, 0x5d, 0x48};

    /* Заново создаем текстовый ключ */
    if ((bkey = ak_bckey_new_rc6_ptr(user_key_2, 32, ak_true))==NULL) {
        ak_error_message( ak_error_get_value(), __func__, "[TEST 2] wrong creation of test key" );
        return ak_false;
    }

    /* Тестируем зашифрование одного блока информации */
    bkey->encrypt(&bkey->key, user_text_2, out);
    if (memcmp(out, cipher_text_2, 16) != 0) {
        ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                           "[TEST 2] the one block encryption test from RC6 is wrong");
        ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
        ak_log_set_message( str = ak_ptr_to_hexstr( cipher_text_2, 16, ak_true )); free( str );
        //bkey = ak_bckey_delete(bkey);
        return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "[TEST 2] the one block encryption test from RC6 is Ok" );

    /* Тестируем расшифрование одного блока информации */
    bkey->decrypt(&bkey->key, cipher_text_2, out);
    if (memcmp(user_text_2, out, 16) != 0) {
        ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                           "[TEST 2] the one block decryption test from RC6 is wrong");
        ak_log_set_message( str = ak_ptr_to_hexstr( user_text_2, 16, ak_true )); free( str );
        ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
        //bkey = ak_bckey_delete(bkey);
        return ak_false;
    }
    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "[TEST 2] the one block decryption test from RC6 is Ok" );

    //bkey = ak_bckey_delete(bkey);
    return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_rc6.c  */
/* ----------------------------------------------------------------------------------------------- */
