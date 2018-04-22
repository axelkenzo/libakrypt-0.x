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
/*   ak_random.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_context_manager.h>
 #include <ak_mpzn.h>

 #include <time.h>
#ifdef LIBAKRYPT_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
  #include <unistd.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct random в значения по-умолчанию.

    @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  rnd->data = NULL;
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = NULL;
  rnd->free = free;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_destroy( ak_random rnd )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ ,"use a null pointer to a random generator" );
  return ak_error_null_pointer;
  }
  if( rnd->data != NULL ) rnd->free( rnd->data );
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = NULL;
  rnd->free = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля, уничтожает генератор псевдо-случайных чисел
    (структуру struct random) и присваивает указателю значение NULL.

    @param rnd указатель на структуру struct random.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_random_delete( ak_pointer rnd )
{
  if( rnd != NULL ) {
   ak_random_destroy(( ak_random ) rnd );
   free( rnd );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                            "use a null pointer to a random generator" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
  static ak_uint32 shift_value = 0; // Внутренняя статическая переменная (счетчик вызовов)

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует для генерации случайного значения текущее время и прочие параметры.
    Несмотря на случайность вырабатываемого значения, функция не должна использоваться для
    генерации значений, для которых требуется криптографическая случайность. Это связано с
    достаточно прогнозируемым изменением значений функции при многократных повторных вызовах.

    Основная задача данной функции - инициализаци программного генератора
    каким-либо знаением, в случае, когда пользователь не инициализирует программный генератор
    самостоятельно.

   \return Функция возвращает случайное число размером 8 байт (64 бита).                                                     */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_value( void )
{
  ak_uint64 vtme = time( NULL );
  ak_uint64 clk = clock();
#ifndef _WIN32
  ak_uint64 pval = getpid();
  ak_uint64 uval = getuid();
#else
  ak_uint64 pval = _getpid();
  ak_uint64 uval = 67;
#endif
  ak_uint64 value = ( shift_value += 11 )*125643267795740073LL + pval;
            value = ( value * 506098983240188723LL ) + 71331*uval + vtme;
  return value ^ clk;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_bbs                                       */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получения одного байта из вырабатываемых генератором бит */
typedef int ( ak_function_random_bbs_uint8 ) ( ak_random rnd, ak_uint8 *byte );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний генератора BBS                                  */
struct random_bbs {
    /*! \brief Модуль генератора (512 бит) */
    ak_mpzn512 modulo;
    /*! \brief Текущее значение внутреннего состояния генератора */
    ak_mpzn512 value;

    /*! \brief Указатель на функцию получения одного байта: */
    ak_function_random_bbs_uint8 *get_byte;
};
typedef struct random_bbs *ak_random_bbs;

/* ----------------------------------------------------------------------------------------------- */
//static лишает функцию внешней связности
static int ak_random_bbs_uint8( ak_random rnd, ak_uint8 *byte )
{
    //static лишает функцию внешней связности
    if ( rnd == NULL )
        //func - макрос, показывающий имя функции
        return ak_error_message(ak_error_null_pointer, __func__, "use a null pointer to a random generator" );

    *byte = 0;
    //Так как младшие 64 бита value совпадают с младшим словом value[0], то найти младший бит value,
    //т.е. value mod 2 совсем нетрудно:
    for ( size_t i = 0; i < 8; ++i ) {
        //Получаем младший бит value, сдвигаем его на старшую незанятую позицию
        //и прибавляем к текущим битам byte:
        *byte ^= ( (( ak_random_bbs ) ( rnd -> data )) -> value[0] & 0x0000000000000001ULL ) << (7 - i);
        rnd -> next( rnd );
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
//Выработка следующего значения генератора:
static int ak_random_bbs_next( ak_random rnd )
{
    if( rnd == NULL )
        return ak_error_message(ak_error_null_pointer, __func__, "use a null pointer to a random generator" );

    //Возведение текущего значения генератора в квадрат,
    //т.е. переход к следующему значению:
    ak_mpzn_mul_montgomery( (( ak_random_bbs ) ( rnd -> data ))->value,
                            (( ak_random_bbs ) ( rnd -> data ))->value,
                            (( ak_random_bbs ) ( rnd -> data ))->value,
                            (( ak_random_bbs ) ( rnd -> data ))->modulo,
                            6455409880403415343ULL, //Младшее слово числа n: r*s - n*modulo = 1,
                                                    //где r > modulo, r = 2^512
                            ak_mpzn512_size );

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
//Функция задает начальное значение генератора равным x0^deg в форме Монтгомери, т.е. (x0^deg)*r (mod modulo)
//где x0 - заданный по умолчанию вычет типа ak_mpzn512, для которого достигается максимальный период генератора,
//а deg - значение ptr;
//size - размер ptr в словах, то есть в ak_uint64
static int ak_random_bbs_randomize_ptr( ak_random rnd, const ak_pointer ptr, const size_t size )
{
    if( rnd == NULL )
        return ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );

    if( ptr == NULL )
        return ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to initial vector" );

    if( !size )
        return ak_error_message( ak_error_zero_length, __func__ , "use initial vector with zero length" );

    //Размер начального вектора не должен быть больше 512 бит:
    if( size > ak_mpzn512_size )
        return ak_error_message( ak_error_wrong_length, __func__ , "use initial vector with wrong length" );

    ak_mpzn512 deg, x0_mon; //x0_mon - вычет x0 в форме Монтгомери, т.е. x0*r (mod modulo)
    ak_mpzn_set_hexstr( x0_mon, ak_mpzn512_size,
                        "2c6db990a757c41270b9b6bc1d6f432ebc8fd68e2cdd54dc73bb0fa93ca9d6e81841c52175e52871369ddf9fa8d4bae58edb607f31952b2c655ad2dfb71df9b4" );

    //На случай, если size < ak_mpzn512_size, скопируем значение ptr в ak_mpzn512,
    //чтобы можно было возвести x0 в заданную степень корректно:
    memset( deg, 0, ak_mpzn512_size*sizeof( ak_uint64 ) );
    memcpy( deg, ptr, size*sizeof( ak_uint64 ) );

    //Порядок x0 есть P1*Q1, где modulo = P*Q, P = 2*P1+1, Q = 2*Q1+1, Q,P,Q1,P1 - простые.
    //Поэтому для сохранения порядка для x0^deg, deg не может равняться P1, Q1 или быть больше или равным P1*Q1,
    //Проверим это:
    ak_mpzn512 Q1, P1, Q1P1;
    ak_mpzn_set_hexstr( Q1, ak_mpzn512_size,
                        "6f865cd09274c0213658f6842bf18f8c59fcb6cbbced58d913a3d85796846f1f" );
    ak_mpzn_set_hexstr( P1, ak_mpzn512_size,
                        "63114becec5bc3c6bd9e84619df7dbc8aa31b679568b279abbd394f097c4ddc7" );
    ak_mpzn_set_hexstr( Q1P1, ak_mpzn512_size,
                        "2b287ee4668362da04857765d80038fefb70af31354b6e06bc105ad9c18a8512504732e3395eb909b45b063bc2f0cad430fd8d0bb93af7daeaeb3d06b19c2419" );
    int degP1Q1cmp = ak_mpzn_cmp( deg, Q1P1, ak_mpzn512_size );
    if ( !ak_mpzn_cmp( deg, Q1, ak_mpzn512_size ) || /*Если deg = Q1*/
         !ak_mpzn_cmp( deg, P1, ak_mpzn512_size ) || /*Если deg = P1*/
         !degP1Q1cmp || /*Если deg = Q1*P1*/
          degP1Q1cmp == 1 /*Если deg > Q1*P1*/ )
        //Выбран наиболее подходящий вариант ошибки:
        return ak_error_message( ak_error_undefined_value, __func__, "use initial vector with wrong value" );

    //Установка начального значения равным (x0^deg)*r (mod modulo),
    //т.е. равным x0^deg в представлении Монтгомери
    ak_mpzn_modpow_montgomery( (( ak_random_bbs ) ( rnd -> data ))->value,
                               x0_mon,
                               deg,
                               (( ak_random_bbs ) ( rnd -> data ))->modulo,
                               6455409880403415343ULL, //Младшее слово числа n: r*s - n*modulo = 1,
                                                       //где r > modulo, r = 2^512
                               ak_mpzn512_size );

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
static int ak_random_bbs_random( ak_random rnd, const ak_pointer ptr, const size_t size ) {
    if( rnd == NULL )
        return ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );

    if( ptr == NULL )
        return ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );

    if( !size )
        return ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );

    ak_uint8 *bytes = ptr; //Заметим, что квалификатор const у ptr относится к указателю,
                           //а не к данным
    for (size_t i = 0; i < size; ++i, ++bytes)
        (( ak_random_bbs ) ( rnd -> data )) -> get_byte( rnd, bytes );

    return ak_error_ok;

}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор вырабатывает последовательность внутренних состояний, удовлетворяющую
    сравнению \f$ x_{n+1} \equiv {x_n}^{2} \pmod{m}, \f$
    в котором константа \f$ m \f$ удовлетворяет соотношению
    \f$ m = p \cdot q, \f$ где \f$ p \f$ и \f$ q \f$ - простые числа, сравнимые с 3 по модулю 4.
    В данной реализации \f$ m = 0xaca1fb919a0d8b681215dd976000e3fbedc2bcc4d52db81af0416b67062a144ae64c1d\
    07e31bebf6b95b0eba9f9601facc530eb90bdce0534a9bceab23032a31 \f$

    Далее, последовательность внутренних состояний преобразуется в выходную последовательность
    бит по следующему правилу: \f$ \gamma_n = x_n \pmod{2}. \f$


    @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
//Функция устанавливает поля generator необходимым для BBS образом:
//устанавливает указатели на функции, выделяет память под внутреннюю структуру BBS и устанавливает её значения

//P.S. Слова create и destroy означают установку и очистку значений полей структур
int ak_random_create_bbs( ak_random generator ) {
    int error = ak_error_ok;
    //ak_random_create устанавливает поля random на NULL, и функцию освобождения памяти free().
    if ( (error = ak_random_create( generator )) != ak_error_ok )
        return ak_error_message( error, __func__ , "wrong initialization of random generator" );

    if ( (generator -> data  = malloc(sizeof(struct random_bbs))) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__ ,
                                 "incorrect memory allocation for an internal variables of random generator" );

    generator -> next = ak_random_bbs_next;
    generator -> randomize_ptr = ak_random_bbs_randomize_ptr;
    generator -> random = ak_random_bbs_random;
    //Функция генерации байта, специфичная для BBS:
    (( ak_random_bbs ) ( generator -> data )) -> get_byte = ak_random_bbs_uint8;

    //Установим модуль генератора:
    ak_mpzn_set_hexstr( (( ak_random_bbs ) ( generator -> data ))->modulo, ak_mpzn512_size,
                        "aca1fb919a0d8b681215dd976000e3fbedc2bcc4d52db81af0416b67062a144ae64c1d07e31bebf6b95b0eba9f9601facc530eb90bdce0534a9bceab23032a31" );

    //Сгенерируем случайный ak_mpzn256 (можно задать длину, кратную 64 битам и не большую 512 бит),
    //который зададим в качестве инициализатора начального значения:
    ak_mpzn256 init;
    //Если было сгенерировано неподходящее значение, то пробуем снова:
    do {
        for (size_t i = 0; i < ak_mpzn256_size; ++i)
            init[i] = ak_random_value();
    } while ( (error = ak_random_bbs_randomize_ptr( generator, &init, ak_mpzn256_size )) == ak_error_undefined_value );

    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_lcg                                       */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний линейного конгруэнтного генератора              */
 struct random_lcg {
  /*! \brief текущее значение внутреннего состояния генератора */
  ak_uint64 val;
};
 typedef struct random_lcg *ak_random_lcg;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_next( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  (( ak_random_lcg ) ( rnd->data ))->val *= 125643267795740073LL;
  (( ak_random_lcg ) ( rnd->data ))->val += 506098983240188723LL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_randomize_ptr( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  size_t idx = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to initial vector" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use initial vector with zero length" );
    return ak_error_null_pointer;
  }
  /* сначала начальное значение, потом цикл по всем элементам массива */
  (( ak_random_lcg ) ( rnd->data ))->val = value[idx];
  do {
        rnd->next( rnd );
        (( ak_random_lcg ) ( rnd->data ))->val += value[idx];
  } while( ++idx < size );
 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  size_t i = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );
    return ak_error_zero_length;
  }

  for( i = 0; i < size; i++ ) {
    value[i] = (ak_uint8) ((( ak_random_lcg ) ( rnd->data ))->val >> 16 );
    rnd->next( rnd );
  }
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор вырабатывает последовательность внутренних состояний, удовлетворяющую
    линейному сравнению \f$ x_{n+1} \equiv a\cdot x_n + c \pmod{2^{64}}, \f$
    в котором константы a и c удовлетворяют равенствам
    \f$ a = 125643267795740073 \f$ и \f$ b = 506098983240188723. \f$

    Далее, последовательность внутренних состояний преобразуется в последовательность
    байт по следующему правилу
    \f$ \gamma_n = \displaystyle\frac{x_n - \hat x_n}{2^{24}} \pmod{256}, \f$
    где \f$\hat x_n \equiv x_n \pmod{2^{24}}. \f$

    @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_lcg( ak_random generator )
{
  int error = ak_error_ok;
  ak_uint64 qword = ak_random_value(); /* вырабатываем случайное число */

  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_lcg ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
              "incorrect memory allocation for an internal variables of random generator" );

  generator->next = ak_random_lcg_next;
  generator->randomize_ptr = ak_random_lcg_randomize_ptr;
  generator->random = ak_random_lcg_random;
 /* функция generator->free уже установлена при вызове ak_random_create */

 /* для корректной работы присваиваем какое-то случайное начальное значение */
  ak_random_lcg_randomize_ptr( generator, &qword, sizeof( ak_uint64 ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_file                                      */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний генератора-файла                                */
 struct random_file {
  /*! \brief файловый дескриптор */
  int fd;
};
 typedef struct random_file *ak_random_file;

/* ----------------------------------------------------------------------------------------------- */
 static void ak_random_file_free( ak_pointer ptr )
{
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
  if( close( (( ak_random_file ) ptr )->fd ) == -1 )
    ak_error_message( ak_error_close_file, __func__ , "wrong closing a file with random data" );
  free(ptr);
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_file_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  ak_uint8 *value = ptr;
  size_t result = 0, count = size;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );
    return ak_error_zero_length;
  }

  /* считываем несколько байт */
  slabel:
  result = read( (( ak_random_file ) ( rnd->data ))->fd, value,
  #ifdef _MSC_VER
    (unsigned int)
  #endif
    count );

  /* если конец файла, то переходим в начало */
  if( result == 0 ) {
    lseek( (( ak_random_file ) ( rnd->data ))->fd, 0, SEEK_SET );
    goto slabel;
  }
  /* если мы считали меньше, чем надо */
  if( result < count ) {
    value += result;
    count -= result;
    goto slabel;
  }
  /* если ошибка чтения, то возбуждаем ошибку */
  if( result == -1 ) {
    ak_error_message( ak_error_read_data, __func__ , "wrong reading data from file" );
    return ak_error_read_data;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор связывается с заданным файлом и возвращает содержащиеся в нем значения
    в качестве случайных чисел. Если данные в файле заканчиваются, то считывание начинается
    с начала файла.

    Основное назначение данного генератора - считывание данных из файловых устройств,
    таких как /dev/randon или /dev/urandom.

    @param generator Контекст создаваемого генератора.
    @param filename Имя файла.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_file( ak_random generator, const char *filename )
{
  int error = ak_error_ok;
  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_file ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );

 /* теперь мы открываем заданный пользователем файл */
  if( ((( ak_random_file ) ( generator->data ))->fd = open( filename, O_RDONLY | O_BINARY )) == -1 ) {
    ak_error_message_fmt( ak_error_open_file, __func__ ,
                                  "wrong opening a file \"%s\" with random data", filename );
    //generator = ak_random_delete( generator );
    ak_random_destroy( generator );
    return ak_error_open_file;
  }

  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_file_random;
  generator->free = ak_random_file_free; /* эта функция должна закрыть открытый ранее файл */

 return error;
}

#if defined(__unix__) || defined(__APPLE__)
/* ----------------------------------------------------------------------------------------------- */
/*! @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_random( ak_random generator )
{
 return ak_random_create_file( generator, "/dev/random" );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_urandom( ak_random generator )
{
 return ak_random_create_file( generator, "/dev/urandom" );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                         реализация класса winrtl                                */
/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 #include <windows.h>
 #include <wincrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения контекста криптопровайдера. */
 struct random_winrtl {
  /*! \brief контекст криптопровайдера */
  HCRYPTPROV handle;
};
 typedef struct random_winrtl *ak_random_winrtl;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_winrtl_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  if( !CryptGenRandom( (( ak_random_winrtl )rnd->data)->handle, (DWORD) size, ptr ))
    return ak_error_message( ak_error_undefined_value, __func__,
                                                    "wrong generation of pseudo random sequence" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static void ak_random_winrtl_free( ak_pointer ptr )
{
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
  if( !CryptReleaseContext( (( ak_random_winrtl )ptr )->handle, 0 )) {
    ak_error_message_fmt( ak_error_close_file,
            __func__ , "wrong closing a system crypto provider with error: %x", GetLastError( ));
  }
  free( ptr );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_winrtl( ak_random generator )
{
  HCRYPTPROV handle = 0;

  int error = ak_error_ok;
  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_winrtl ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );

  /* теперь мы открываем криптопровайдер для доступа к генерации случайных значений
     в начале мы пытаемся создать новый ключ */
  if( !CryptAcquireContext( &handle, NULL, NULL,
                                         PROV_RSA_FULL, CRYPT_NEWKEYSET )) {
    /* здесь нам не удалось создать ключ, поэтому мы пытаемся его открыть */
    if( GetLastError() == NTE_EXISTS ) {
      if( !CryptAcquireContext( &handle, NULL, NULL,
                                         PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT )) {
        ak_error_message_fmt( error = ak_error_open_file, __func__,
                      "wrong open default key for system crypto provider with error: %x", GetLastError( ));
       ak_random_destroy( generator );
       return error;
      }
    } else {
       ak_error_message_fmt( error = ak_error_access_file, __func__,
                      "wrong creation of default key for system crypto provider with error: %x", GetLastError( ));
       ak_random_destroy( generator );
       return error;
     }
  }
  (( ak_random_winrtl )generator->data)->handle = handle;

  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_winrtl_random;
  generator->free = ak_random_winrtl_free; /* эта функция должна закрыть открытый ранее криптопровайдер */

 return error;
}

#endif

/* ----------------------------------------------------------------------------------------------- */
/*                               реализация интерфейсных функций                                   */
/* ----------------------------------------------------------------------------------------------- */
//Функция выделяет память под структуру random и инициализирует её как генератор BBS.

//P.S. Слова new и delete означают выделение и освобождение динамической памяти
//Заметим, что delete происходит при отключении библиотеки при удалении структуры
//управления контекстами (для каждого объекта в этой структуре указывается необходимая функция delete)
ak_handle ak_random_new_bbs( void ) {
    int error = ak_error_ok;
    ak_random generator = NULL;

    //Создание структуры random:
    if ( (generator = malloc(sizeof(struct random))) == NULL ) {
        ak_error_message(ak_error_out_of_memory, __func__,  "wrong creation of random generator context");
        return ak_error_wrong_handle;
    }

    //Инициализация random как генератора BBS:
    if ( (error = ak_random_create_bbs( generator )) != ak_error_ok ) {
        free( generator );
        ak_error_message( error, __func__ , "wrong initialization of random generator" );
        return ak_error_wrong_handle;
    }

    //Помещение созданного объекта библиотеки в структуру управления контекстами (указателями на объекты):
    return ak_libakrypt_new_handle( generator, random_generator, "", ak_random_delete );
}
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_random_new_lcg( void  )
{
  int error = ak_error_ok;
  ak_random generator = NULL;

 /* создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_random_create_lcg( generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_libakrypt_new_handle( generator, random_generator, "", ak_random_delete );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_random_new_file( const char *filename  )
{
 int error = ak_error_ok;
 ak_random generator = NULL;

 /* создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_random_create_file( generator, filename )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization a random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_libakrypt_new_handle( generator, random_generator, "", ak_random_delete );
}

/* ----------------------------------------------------------------------------------------------- */
#if defined(__unix__) || defined(__APPLE__)
 ak_handle ak_random_new_dev_random( void )
{
  return ak_random_new_file( "/dev/random" );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_random_new_dev_urandom( void )
{
  return ak_random_new_file( "/dev/urandom" );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 ak_handle ak_random_new_winrtl( void  )
{
  int error = ak_error_ok;
  ak_random generator = NULL;

 /* создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_random_create_winrtl( generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_libakrypt_new_handle( generator, random_generator, "", ak_random_delete );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid_handle дескриптор OID генератора псевдо-случайных чисел.
    @return Функция возвращает дескриптор созданного генератора псевдо-случайных чисел.
    Если дескриптор не может быть создан, или oid не соотвествует генератору псевдо-случайных чисел,
    то возбуждается ошибка и возвращается значение \ref ak_error_wrong_handle. Кош ошибки может
    быть получен с помощью вызова функции ak_error_get_value().                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_random_new_oid( ak_handle oid_handle )
{
  int error = ak_error_ok;
  ak_random generator = NULL;
  ak_oid oid = ak_handle_get_context( oid_handle, oid_engine );

 /* проверяем, что handle от OID */
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using wrong value of handle" );
    return ak_error_wrong_handle;
  }

 /* проверяем, что OID от генератора псевдо-случайных чисел */
  if( oid->engine != random_generator ) {
    ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
    return ak_error_wrong_handle;
  }

 /* теперь создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ((ak_function_random_create *)oid->func)( generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization a random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_libakrypt_new_handle( generator, random_generator, "", ak_random_delete );
}

/* ----------------------------------------------------------------------------------------------- */
/*              функции, реализующие интерфейс пользователя для класса random                      */
/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @param ptr указатель на область памяти, в которую помещаются значения
    @param size размер памяти в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_ptr( ak_handle handle, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;
  ak_random generator = NULL;

  if(( generator = ak_handle_get_context( handle, random_generator )) == NULL )
    return ak_error_message( error = ak_error_get_value(), __func__ , "wrong handle" );

  if( generator->random != NULL ) {
    if(( error = generator->random( generator, ptr, size )) != ak_error_ok )
      ak_error_message( error, __func__, "wrong generation of random data" );
    return error;
  }
 return ak_error_message( ak_error_undefined_function, __func__ ,
                                                 "use a null pointer to a function " );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @return В случае успеха возвращается псевдо-случайное число.
    В случае возникновения ошибки возвращается ноль. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_uint64( ak_handle handle )
{
  ak_uint64 qword = 0;
  ak_random generator = NULL;

  if(( generator = ak_handle_get_context( handle, random_generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return qword;
  }

  if( generator->random != NULL ) {
    if( generator->random( generator, &qword, sizeof( ak_uint64 )) != ak_error_ok )
      ak_error_message( ak_error_get_value(), __func__, "wrong generation of random data" );
    return qword;
  } ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using a null pointer to a function " );
 return qword;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @return В случае успеха возвращается псевдо-случайное число.
    В случае возникновения ошибки возвращается ноль. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 ak_random_uint8( ak_handle handle )
{
  ak_uint8 byte = 0;
  ak_random generator = NULL;

  if(( generator = ak_handle_get_context( handle, random_generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return byte;
  }

  if( generator->random != NULL ) {
    if( generator->random( generator, &byte, sizeof( ak_uint8 )) != ak_error_ok )
      ak_error_message( ak_error_get_value(), __func__, "wrong generation of random data" );
    return byte;
  } ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using a null pointer to a function " );
 return byte;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @param size размер создаваемого буффера в байтах
    @return В случае успеха возвращается указатель на созданный буффер. В случае возникновения
    ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_random_buffer( ak_handle handle, const size_t size )
{
 ak_buffer buffer = NULL;
 ak_random generator = NULL;

 /* получаем контекст */
  if(( generator = ak_handle_get_context( handle, random_generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return NULL;
  }

 /* проверяем, что функция генерации определена */
  if( generator->random == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ , "use a null pointer to a function " );
    return NULL;
  }

 /* создаем буффер */
  if(( buffer = ak_buffer_new_size( size )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong buffer creation" );
    return NULL;
  }

 /* вырабатываем псевдо-случайные значения */
  if( generator->random( generator, buffer->data, buffer->size ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), __func__, "wrong generation of random data" );

 return buffer;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @param ptr указатель на область памяти, в которую помещаются значения
    @param size размер памяти в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_randomize( ak_handle handle, const ak_pointer ptr, const size_t size )
{
 int error = ak_error_ok;
 ak_random generator = NULL;

  if(( generator = ak_handle_get_context( handle, random_generator )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );

  if( generator->randomize_ptr != NULL ) {
       if(( error = generator->randomize_ptr( generator, ptr, size )) != ak_error_ok )
         ak_error_message( error, __func__, "wrong randomization of random generator" );
       return error;
  }
 return ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "use a null pointer to a function " );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-random.c                                                                      */
/*! \example example-randomize.c                                                                   */
/*! \example example-random-system.c                                                               */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_random.c  */
/* ----------------------------------------------------------------------------------------------- */
