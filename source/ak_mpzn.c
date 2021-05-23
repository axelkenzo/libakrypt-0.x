/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mpzn.c                                                                                 */
/*  - содержит реализации функций для вычислений с большими целыми числами                         */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup math-doc Математические функции
 @{
   \details Библиотека `libakrypt` содержит собственную реализацию математических алгоритмов,
   используемых в криптографических преобразованиях.
   Реализации оптимизированы под размеры параметров, используемых в отечественных стандартах и
   рекомендациях по стандартизации. В настоящее время реализованы:
    - операции с большими целыми числами, такие как сложение, вычитание и умножение чисел;
    - представление Монтгомери для вычетов кольца целых чисел по модулям простых чисел, не превосходящих
    \f$ 2^{256}\f$ и \f$ 2^{512}\f$;
    - операции с проективными и аффинными точками эллиптических кривых,
    заданных в короткой форме Вейерштрасса и искривленной форме Эдвардса;
    - в явном виде определены параметры ряда эллиптических кривых, рекомендованных для использования
    рекомендациями по стандартизации
    [Р 1323565.1.024–2019](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-132356-1-024-2019-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-parametry-ellipticheskikh-krivykh-dlya-kriptograficheskikh-algoritmov-i-protokolov19.html),
    а также параметры, рекомендуемые к использованию авторами библиотеки;
    - операции сложения и умножения элементов конечных полей \f$ \mathbb F_{2^{64}}\f$,
    \f$ \mathbb F_{2^{128}}\f$,  \f$\mathbb F_{2^{256}}\f$ и \f$ \mathbb F_{2^{512}}\f$. *//** @} */
/** \addtogroup mpzn-doc Арифметика больших чисел
 @{ *//** @} */


/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_SYSTYPES_H
 #include <sys/types.h>
#endif
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
#if AK_HAVE_BUILTIN_MULQ_GCC
 #define LIBAKRYPT_HAVE_ASM_CODE
 #define umul_ppmm(w1, w0, u, v) \
   __asm__ ("mulq %3" : "=a,a" (w0), "=d,d" (w1) : "%0,0" (u), "r,m" (v))
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifndef LIBAKRYPT_HAVE_ASM_CODE
 /* очень хочется, чтобы здесь была реализация метода А.А. Карацубы для двух 64-х битных чисел */
 #define umul_ppmm( w1, w0, u, v )                  \
 do {                                               \
    ak_uint64 __x0, __x1, __x2, __x3;               \
    ak_uint32 __ul, __vl, __uh, __vh;               \
    ak_uint64 __u = (u), __v = (v);                 \
                                                    \
    __ul = __u & 0xFFFFFFFF;                        \
    __uh = __u >> 32;                               \
    __vl = __v & 0xFFFFFFFF;                        \
    __vh = __v >> 32;                               \
                                                    \
    __x0 = (ak_uint64) __ul * __vl;					\
    __x1 = (ak_uint64) __ul * __vh;					\
    __x2 = (ak_uint64) __uh * __vl;					\
    __x3 = (ak_uint64) __uh * __vh;					\
                                                    \
    __x1 += ( __x0 >> 32 );                         \
    __x1 += __x2;                                   \
    if (__x1 < __x2) __x3 += ((ak_uint64)1 << 32 ); \
                                                    \
    (w1) = __x3 + (__x1 >> 32 );			        \
    (w0) = ( __x1 << 32 ) + ( __x0 & 0xFFFFFFFF );	\
 } while (0)
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает значение вычета x вычету z. Для оптимизации вычислений проверка
    корректности входных данных не производится.

    @param z Вычет, которому присваивается значение
    @param x Вычет, значение которого присваивается.
    @param size Размер массива в словах типа `ak_uint64`. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.                           */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set( ak_uint64 *z, ak_uint64 *x, const size_t size )
{
  memcpy( z, x, size*sizeof (ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает указатель на массив как вычет одного из типов ak_mpznxxx и присваивает
    этому вычету беззнаковое целое значение value.

    @param x Вычет, в который помещается значение value
    @param size Размер массива в словах типа `ak_uint64`. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.
    @param value Значение, которое присваивается вычету.

    @return В случае успеха, функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set_ui( ak_uint64 *x, const size_t size, const ak_uint64 value )
{
  memset( x, 0, size*sizeof( ak_uint64 ));
  x[0] = value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает указатель на массив как вычет одного из типов ak_mpznxxx и присваивает
    этому вычету случайное значение, вырабатываемое заданным генератором псевдо случайных чисел.

    @param x Указатель на массив, в который помещается значение вычета
    @param size Размер массива в словах типа `ak_uint64`. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.
    @param generator Указатель на генератор псевдо случайных чисел,
    используемый для генерации случайного вычета.

    @return В случае успеха, функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_random( ak_uint64 *x, const size_t size, ak_random generator )
{
  if( x == NULL ) return ak_error_message( ak_error_null_pointer,
                                                      __func__ , "using a null pointer to mpzn" );
  if( !size ) return ak_error_message( ak_error_zero_length,
                                                 __func__ , "using a zero length of input data" );
  if( generator == NULL ) return ak_error_message( ak_error_undefined_value,
                                                __func__, "using an undefined random generator" );

 return generator->random( generator, x, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_random_modulo( ak_uint64 *x, ak_uint64 *p, const size_t size, ak_random generator )
{
  size_t midx = size-1;
  if( x == NULL ) return ak_error_message( ak_error_null_pointer,
                                                       __func__ , "using a null pointer to mpzn" );
  if( p == NULL ) return ak_error_message( ak_error_null_pointer,
                                                     __func__ , "using a null pointer to modulo" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                        "using a zero length for generated data" );
  if( generator == NULL ) return ak_error_message( ak_error_undefined_value,
                                                __func__ , "using an undefined random generator" );

 /*! TODO! Здесь не совсем корректный способ вычисления случайного значения,
           необходимо исправить в дальнейшем */

 /* определяем старший значащий разряд у модуля */
  while( p[midx] == 0 ) {
    if( midx == 0 ) return ak_error_message( ak_error_undefined_value,
                                                            __func__ , "modulo is equal to zero" );
      else --midx;
  }

 /* старший разряд - по модулю, остальное мусор */
  generator->random( generator, x, ( ssize_t )( size*sizeof( ak_uint64 )));
  x[midx] %= p[midx];

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает указатель на массив как вычет одного из типов ak_mpznxxx и присваивает
    этому вычету значение, содержащееся в строке шестнадцатеричных символов.

    @param x Указатель на массив, в который помещается значение вычета
    @param size Размер массива в словах типа `ak_uint64`. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.
    @param str Строка шестнадцатеричных символов,
    значение которой присваивается вычету. Если строка содержит больше символов, чем может
    поместиться в заданный массив, то возбуждается ошибка.

    @return В случае успеха, функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_hexstr( ak_uint64 *x, const size_t size, const char *str )
{
  int error = ak_error_ok;
#ifdef AK_BIG_ENDIAN
  size_t i = 0;
#endif
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero legth of input data" );
    return ak_error_zero_length;
  }
  if( str == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to hexademal string" );
    return ak_error_null_pointer;
  }

  error = ak_hexstr_to_ptr( str, x, size*sizeof( ak_uint64 ), ak_true );
#ifdef AK_BIG_ENDIAN
  for( i = 0; i < size; i++ ) x[i] = bswap_64(x[i]);
#endif
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция возвращает указатель на статическую строку, в которую помещается
    шестнадцатеричное значение вычета.

    @param x Указатель на массив, в который помещается значение вычета
    @param size Размер массива в словах типа `ak_uint64`. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.

    @return В случае успеха, функция указатель на созданную строку. В противном случае возвращается
    NULL. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().             */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_mpzn_to_hexstr( const ak_uint64 *x, const size_t size )
{
#ifdef AK_BIG_ENDIAN
  size_t i = 0;
  ak_mpznmax temp;
#endif
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return NULL;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero length of input data" );
    return NULL;
  }
#ifdef AK_BIG_ENDIAN
  for( i = 0; i < size; i++ ) temp[i] = bswap_64( x[i] );
  return ak_ptr_to_hexstr( temp, size*sizeof( ak_uint64 ), ak_true );
#else
  return ak_ptr_to_hexstr( x, size*sizeof( ak_uint64 ), ak_true );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция возвращает указатель на динамическую строку, в которую помещается
    шестнадцатеричное значение вычета. Память под строку выделяется динамически,
    с использованием функции malloc(), и должна быть позднее удалена пользователем с помощью
    вызова функции free().

    @param x Указатель на массив, в который помещается значение вычета
    @param size Размер массива в словах типа `ak_uint64`. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.

    @return В случае успеха, функция указатель на созданную строку. В противном случае возвращается
    NULL. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().             */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_mpzn_to_hexstr_alloc( ak_uint64 *x, const size_t size )
{
#ifdef AK_BIG_ENDIAN
  size_t i = 0;
  ak_mpznmax temp;
#endif
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return NULL;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero length of input data" );
    return NULL;
  }
#ifdef AK_BIG_ENDIAN
  for( i = 0; i < size; i++ ) temp[i] = bswap_64( x[i] );
  return ak_ptr_to_hexstr_alloc( temp, size*sizeof( ak_uint64 ), ak_true );
#else
  return ak_ptr_to_hexstr_alloc( x, size*sizeof( ak_uint64 ), ak_true );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Вычет `x` записывается в виде последовательности октетов - коэффициентов разложения в системе
    счисления по основанию 256. Запись производится слева (начиная с младших разрядов)
    на право (заканчивая старшими разрядами).
    Память, в которую записывается вычет, должна быть выделена заранее.

    \note Указатель на вычет `x` и указатель `out` на область памяти,
    куда записывается результат сериализации, могут совпадать.

    \param x Вычет, для которого производится преобразование.
    \param size Размер вычета в машинных словах - значение, задаваемое константой
    \ref ak_mpzn256_size или \ref ak_mpzn512_size.
    \param out Указатель на область памяти, в которую будет помещено сериализованное
     представление вычета `x`.
    \param outsize Размер памяти (в октетах) для хранения сериализованного вычета `x`.
    \param reverse Флаг полного разворота данных.
    Если флаг истинен, то после сериализации данные переворачиваются, то есть записываются
    в обратном (big endian) порядке.

    \return В случае успеха, функция возвращает \ref ak_error_ok (ноль). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_to_little_endian( ak_uint64* x, const size_t size,
                                            ak_pointer out, const size_t outsize, bool_t reverse )
{
  ak_uint8 *ptr = out;
  size_t j = 0, idx = 0, cnt = size*sizeof( ak_uint64 );

  if( x == NULL ) return ak_error_message( ak_error_null_pointer,
                                                       __func__ , "using a null pointer to mpzn" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                             "using a zero length of input data" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer,
                                              __func__ , "using a null pointer to output buffer" );
  if( outsize < cnt ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                        "using a small memory buffer for output" );
 /* вычисляем коэффициенты разложения в лоб, без учета используемой архитектуры */
  for( j = 0; j < size; j++ ) {
     ak_uint64 tmp = x[j];
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp%256; tmp >>= 8;
     ptr[idx++] = ( ak_uint8 )tmp;
  }
 /* при необходимости, разворачиваем октеты в обратном порядке */
  if( reverse ) {
    for( j = 0; j < cnt/2; j++ ) {
       ak_uint8 tmp;
       tmp = ptr[cnt-j-1];
       ptr[cnt-j-1] = ptr[j];
       ptr[j] = tmp;
    }
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_little_endian( ak_uint64 *x, const size_t size,
                                     const ak_pointer buff, const size_t buffsize, bool_t reverse )
{
  ak_uint64 tmp = 0;
  ak_uint8 *ptr = buff;
  size_t j = 0, idx = 0, cnt = size*sizeof( ak_uint64 );

  if( x == NULL ) return ak_error_message( ak_error_null_pointer,
                                                       __func__ , "using a null pointer to mpzn" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                              "using a zero legth of input data" );
  if( buff == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using a null pointer to input buffer" );
  if( buffsize > cnt ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                       "using a large buffer for mpzn assigning" );

  if( reverse ) {
    for( j = 0; j < size; j++ ) {
       tmp = ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       tmp <<= 8; tmp += ptr[idx++];
       x[size-1-j] = tmp;
    }
  } else {
      for( j = 0; j < size; j++ ) {
         idx = j*sizeof( ak_uint64 ) + 7;
         tmp = ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; tmp <<= 8;
         tmp += ptr[idx--]; x[j] = tmp;
      }
    }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                  арифметические операции                                        */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию сложения двух вычетов кольца \f$ \mathbb Z_{2^n} \f$, то
    есть реализует операцию \f$ z \equiv x + y \pmod{2^n}\f$.
    В качестве результата функции возвращается знак переноса r, принимающий значение либо 0, либо 1.
    Знак переноса позволяет интерпретировать сложение вычетов как сложение целых чисел, то есть
    записать точное равенство \f$ x + y = z + r\cdot 2^n\f$.

    Допускается использовать в качестве аргумента z один из аргументов x или y.

    Для максимальной эффективности вычислений функция не проверяет допустимые значения параметров.

    @param z    Вычет, в который помещается результат
    @param x    Вычет (левое слагаемое)
    @param y    Вычет (правое слагаемое)
    @param size Размер вычетов в машинных словах - значение, задаваемое
    константой \ref ak_mpzn256_size или \ref ak_mpzn512_size
    @return Функция возвращает значение знака переноса.                                            */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_mpzn_add( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y, const size_t size )
{
  size_t i = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;

  for( i = 0; i < size; i++ ) {
     av = x[i]; bv = y[i];
     bv += cy;
     cy = bv < cy;
     bv += av;
     cy += bv < av;
     z[i] = bv;
  }
  return cy;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию вычитания двух вычетов кольца \f$ \mathbb Z_{2^n} \f$, то
    есть реализует операцию \f$ z \equiv x - y \pmod{2^n}\f$.
    В качестве результата функции возвращается знак переноса r, принимающий значение либо 0, либо 1.
    Знак переноса позволяет интерпретировать операцию как вычитание целых чисел, то есть
    записать равенство \f$ z = x - y + r\cdot 2^n\f$.

    Допускается использовать в качестве аргумента z один из аргументов x или y.

    Для максимальной эффективности вычислений функция не проверяет допустимые значения параметров.

    @param z    Вычет, в который помещается результат
    @param x    Вычет, из которого происходит вычитание
    @param y    Вычитаемое
    @param size Размер вычетов в машинных словах - значение, задаваемое
    константой \ref ak_mpzn256_size или \ref ak_mpzn512_size
    @return Функция возвращает значение знака переноса.                                            */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_mpzn_sub( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y, const size_t size )
{
  size_t i = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;

  for( i = 0; i < size; i++ ) {
     av = x[i]; //b = y[i];
     bv = av - cy;
     cy = bv > av;
     av = bv - y[i];
     cy += av > bv;
     z[i] = av;
  }
  return cy;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию сравнения (реализация операции сравнения основывается на
    операции вычитания вычетов).

    @param x    Левый аргумент операции сравнения
    @param y    Правый аргумент операции сравнения
    @param size Размер вычетов в машинных словах - значение, задаваемое
    константой \ref ak_mpzn256_size или \ref ak_mpzn512_size
    @return Функция возвращает 1, если левый аргумент больше чем правый, -1 если левый аргумент
            меньше, чем правый и 0 если оба аргумента функции совпадают.                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_cmp( ak_uint64 *x, ak_uint64 *y, const size_t size )
{
  size_t i = 0;
  ak_mpznmax z = ak_mpznmax_zero;
  ak_uint64 cy = ak_mpzn_sub( z, x, y, size );

  if( cy ) return -1;
  do{ if( z[i] ) return 1; } while( ++i < size );
  return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает вычет \f$ x \f$ со значением value.  В случае равенства значений возвращается
   \ref ak_true. В противном случае, возвращается \ref ak_false.

   @param x Заданный вычет
   @param size Размер вычетов в машинных словах - значение, задаваемое константой
   \ref ak_mpzn256_size или \ref ak_mpzn512_size
   @param value Значение, с которым происходит сравнение.
   @return Функция возвращает \ref ak_true в случае равенства значений.
   В противном случае, возвращается \ref ak_false.                                                 */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_mpzn_cmp_ui( ak_uint64 *x, const size_t size, const ak_uint64 value )
{
  size_t i = 0;
  if( x[0] != value ) return ak_false;
  if( size > 1 )
    for( i = 1; i < size; i++ ) if( x[i] != 0 ) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения вычета \f$ x\f$, рассматриваемого как целое число,
    на целое число \f$ d \f$. Результат помещается в переменную \f$ z \f$.
    Старший значащий разряд вычисленного произведения возвращается в виде
    возвращаемого значения функции.

    \param z   Переменная, в которую помещается результат
    \param x   Множимое число (многкратной точности)
    \param size Размер множимого числа. Данная величина может принимать значения
    \ref ak_mpzn256_size или \ref ak_mpzn512_size
    \param d   Множитель, беззнаковое число однократной точности.
    \return    Старший значащий разряд вычисленног произведения.                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_mpzn_mul_ui( ak_uint64 *z, ak_uint64 *x, const size_t size, const ak_uint64 d )
{
  size_t j = 0;
  ak_uint64 m = 0;
  ak_mpznmax w = ak_mpznmax_zero;
  for( j = 0; j < size; j++ ) {
        ak_uint64 w1, w0, cy;
        umul_ppmm( w1, w0, d, x[j] );
        w[j] += m;
        cy = w[j] < m;

        w[j] += w0;
        cy += w[j] < w0;
        m = w1 + cy;
     }
  memcpy( z, w, sizeof( ak_uint64 )*size );
 return m;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух вычетов как двух целых чисел, то есть
    для \f$ x, y \in \mathbb Z_{2^n} \f$ вычисляется значение \f$ z \in \mathbb Z_{2^n} \f$
    для которого в точности выполнено равенство \f$ z = x\cdot y\f$.

    Допускается использовать в качестве аргумента z один из аргументов x или y.
    Однако надо обязательно учитывать тот факт, что результат z занимает в два раза
    больше места чем x или y.

    Для максимальной эффективности вычислений функция не проверяет допустимые значения параметров.

    @param z    Вычет, в который помещается результат. Должен иметь длину в два раза большую,
    чем длины вычетов x и y.
    @param x    Вычет (левый множитель)
    @param y    Вычет (равый множитель)
    @param size Размер вычетов x, y в машинных словах - значение, задаваемое константой
    \ref ak_mpzn256_size или \ref ak_mpzn512_size.
    @return Функция не возвращает значение.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_mul( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y, const size_t size )
{
 size_t i = 0, j = 0, ij = 0;
 ak_mpznmax w = ak_mpznmax_zero;

 for( i = 0; i < size; i++ ) {
    ak_uint64 m = 0, d = x[i];
    for( j = 0, ij = i; j < size; j++ , ij++ ) {
       ak_uint64 w1, w0, cy;
       umul_ppmm( w1, w0, d, y[j] );
       w[ij] += m;
       cy = w[ij] < m;

       w[ij] += w0;
       cy += w[ij] < w0;
       m = w1 + cy;
    }
    w[ij] = m;
 }
 memcpy( z, w, 2*sizeof( ak_uint64 )*size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет вычет \f$ r \f$, удовлетворяющий сравнению \f$ r \equiv u \pmod{p}\f$
    При этом предполагается, что вычет \f$ u \f$ и модуль \f$ p \f$ имеют одну и ту же
    длину, т.е. \f$ u, p \in \mathbb Z_{2^n}\f$ для одного и того же натурального \f$ n \f$.

    Более того, для \f$ p \f$ должно выполняться неравенство
    \f$ p > 2^{n-32}\f$. В противном случае результат может оказаться неверным.
    Детальное обоснование работы функции может быть найдено в
    разделе \ref arithmetic_numbers_remainder.

    @param r Результат применения операции вычисления остатка от деления
    @param u Вычет, значение которого приводится по модулю
    @param p Модуль, по которому приводится приведение
    @param size Размер всех трех вычетов, участвующих в вычислениях. Данная переменная должна
    принимать значения \ref ak_mpzn256_size или \ref ak_mpzn512_size.                              */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_rem( ak_uint64 *r, ak_uint64 *u, ak_uint64 *p, const size_t size )
{
  ak_uint64 q = 0;
  ak_mpznmax z, s;

  if( p[size-1] != -1 ) q = u[size-1]/(1+p[size-1]);

 /* проверяем, нужно ли приведение, или же вычет меньше модуля */
  if( q == 0 ) {
    if( r != u ) memcpy( r, u, size*sizeof( ak_uint64 ));
    return;
  }
 /* выполняем умножение и последующее вычитание */
  if( q > 1 )  {
    ak_mpzn_mul_ui( s, p, size, q );
    ak_mpzn_sub( z, u, s, size );
  } else ak_mpzn_sub( z, u, p, size );

  if( ak_mpzn_sub( s, z, p, size )) memcpy( r, z, size*sizeof( ak_uint64 ));
   else memcpy( r, s, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для вычета \f$ x = \sum_{n=0}^{s-1} a_n\cdot \left( 2^{64} \right)^n \f$ в начале вычисляется
    последовательность \f$ r_0 = 0\f$, \f$r_1 = 2^{64} \pmod{p}\f$, \f$r_n = r_1r_{n-1} \pmod{p}\f$.
    После это возвращается результат \f$  \sum_{n=0}^{s-1} \big( a_n*r_n \pmod{p} \big) \pmod{p}\f$.

   \note Реализован простейший алгоритм и, как показывают тесты, он раз в 10
   проигрывает по скорости реализации из GMP. В качестве упражнения можно попробовать реализовать
   этот же алгоритм, но с использованием арифметики Монтгомери. По предварительным расчетам,
   это может дать ускорение в два раза.

    @param x Вычет, который приводится по модулю
    @param size Размер вычета в словах (значение константы ak_mpzn256_size или ak_mpzn512_size )
    @param p Одноразрядное число, по модулю которого приводится вычет `x`.
    В случае, если делитель `p` равен нулю, то возвращается -1. Код ошибки может
    быть получен с помощью вызова функции ak_error_get_value().

    @return Остаток от деления вычета `x` на `p`.                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint32 ak_mpzn_rem_uint32( ak_uint64 *x, const size_t size, ak_uint32 p )
{
  size_t i;
  ak_uint64 t, r1, r = 1, sum = x[0]%p;

  if( !p ) {
    ak_error_message( ak_error_invalid_value, __func__, "divide by zero" );
    return -1;
  }

 /* вычисляем r[i] = 2^{64i} mod (p) */
  r1 = 9223372036854775808ull % p; r1 = ( 2*r1 )%p;

 /* вычисляем остаток от деления */
  for( i = 1; i < size; i++ ) {
    r *= r1; r %= p;
    t = x[i]%p; t *= r; t %= p; sum += t;
  }
  /* приведение после суммирования дает корректный результат только для небольших значений size
     в произвольном случае здесь возникнет ошибка переполнения */
 return sum%p;
}

/* ----------------------------------------------------------------------------------------------- */
/* Операции Монтгомери:                                                                            */
/* реализованы операции сложения и умножения вычетов по материалам статьи                          */
/* C. Koc, T.Acar, B. Kaliski Analyzing and Comparing Montgomery Multiplication Algorithms         */
/*                                                             IEEE Micro, 16(3):26-33, June 1996. */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция складывает два вычета x и y по модулю p, после чего приводит полученную сумму
    по модулю p, то есть вычисляет значение сравнения \f$ z \equiv x + y \pmod{p}\f$.
    Результат помещается в переменную z. Указатель на z может совпадать с одним из указателей на
    слагаемые.

    @param z Указатель на вычет, в который помещается результат
    @param x Левый аргумент операции сложения
    @param y Правый аргумент операции сложения
    @param p Модуль, по которому производяится операция сложения
    @param size Размер модуля в словах (значение константы ak_mpzn256_size или ak_mpzn512_size )   */
/* ----------------------------------------------------------------------------------------------- */
 inline void ak_mpzn_add_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y,
                                                                ak_uint64 *p, const size_t size )
{
  size_t i = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;
  ak_mpznmax t = ak_mpznmax_zero;

 // сначала складываем: (x + y) -> t
  for( i = 0; i < size; i++, x++, y++ ) {
     av = *x; bv = *y;
     bv += cy;
     cy = bv < cy;
     bv += av;
     cy += bv < av;
     t[i] = bv;
  }
  t[size] = cy; cy = 0;
 // потом вычитаем: (t - p) -> z
  for( i = 0; i < size; i++, p++ ) {
     av = t[i];
     bv = av - cy;
     cy = bv > av;
     av = bv - *p;
     cy += av > bv;
     z[i] = av;
  }
  if( t[size] != cy ) memcpy( z, t, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция умножает вычет x на 2, после чего приводит полученную сумму
    по модулю p, то есть вычисляет значение сравнения \f$ z \equiv 2x \pmod{p}\f$.
    Умножение производится путем сдвига вычета x на 1 разряд влево и последующего вычитания модуля p.

    Результат помещается в переменную z. Указатель на z может совпадать с одним из других аргументов
    функции.

    @param z Вычет, в который помещается результат
    @param x Вычет, который умножается на 2
    @param p Модуль, по которому производится операция сложения
    @param size Размер модуля в словах
    (значение константы \ref ak_mpzn256_size или \ref ak_mpzn512_size ).                           */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_lshift_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *p, const size_t size )
{
  size_t i;
  ak_uint64 av = 0, bv = 0, cy = 0;
  ak_mpznmax t = ak_mpznmax_zero;

  t[size] = 0;
  for( i = 0; i < size; i++, p++ ) {
    t[i+1] =  (( x[i]&0x8000000000000000LL ) > 0 );
    t[i] |= x[i] << 1; // сначала сдвигаем на один разряд влево
    av = t[i];         // потом вычитаем модуль
    bv = av - cy;
    cy = bv > av;
    av = bv - *p;
    cy += av > bv;
    z[i] = av;
   }
   if( t[size] != cy ) memcpy( z, t, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция умножает два вычета x и y в представлении Монтгомери, после чего приводит полученное
    произведение по модулю p, то есть для \f$ x \equiv x_0r \pmod{p} \f$ и
    \f$ y \equiv y_0r \pmod{p} \f$ функция вычисляет значение,
    удовлетворяющее сравнению \f$ z \equiv x_0y_0r \pmod{p}\f$.
    Результат помещается в переменную z. Указатель на z может совпадать с одним из указателей на
    перемножаемые вычеты.

    @param z Указатель на вычет, в который помещается результат
    @param x Левый аргумент опреации сложения
    @param y Правый аргумент операции сложения
    @param p Модуль, по которому производятся вычисления
    @param n0 Константа, используемая в вычислениях. Представляет собой младшее слово
    числа n, удовлетворяющего равенству \f$ rs - np = 1\f$.
    @param size Размер модуля в словах (значение константы \ref ak_mpzn256_size или
                                                                          \ref ak_mpzn512_size).   */
/* ----------------------------------------------------------------------------------------------- */
 inline void ak_mpzn_mul_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y,
                                               ak_uint64 *p, ak_uint64 n0, const size_t size )
{
  size_t i = 0, j = 0, ij = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;
  ak_mpznmax t = ak_mpznmax_zero;

  // ak_mpzn_mul( t, x, y, size );
  for( i = 0; i < size; i++ ) {
     ak_uint64 c = 0, m = x[i];
     for( j = 0, ij = i; j < size; j++ , ij++ ) {
        ak_uint64 w1, w0, cy;
        umul_ppmm( w1, w0, m, y[j] );
        t[ij] += c;
        cy = t[ij] < c;

        t[ij] += w0;
        cy += t[ij] < w0;
        c = w1 + cy;
     }
     t[ij] = c;
  }

  //  ak_mpzn_mul( u, t, n, size );
  //  ak_mpzn_mul( u, u, p, size );
  //  ak_mpzn_add( u, u, t, (size<<1));
  for( i = 0; i < size; i++ ) {
     ak_uint64 c = 0, m = t[i]*n0;
     for( j = 0, ij = i; j < size; j++ , ij++ ) {
        ak_uint64 w1, w0, cy;
        umul_ppmm( w1, w0, m, p[j] );
        t[ij] += c;
        cy = t[ij] < c;

        t[ij] += w0;
        cy += t[ij] < w0;
        c = w1;
        c += cy;
     }
     do {
         t[ij] += c;
         c = t[ij] < c;
         ij++;
     } while( c != 0 );
  }

  // вычитаем из результата модуль p
  for( i = 0, j = size; i < size; i++, j++ ) {
     av = t[j];
     bv = av - cy;
     cy = bv > av;
     av = bv - p[i];
     cy += av > bv;
     z[i] = av;
  }
  //if( cy == 1 ) memcpy( z, t+size, size*sizeof( ak_uint64 )); <--- это ошибочный вариант !!!
  if( cy != t[2*size] ) memcpy( z, t+size, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для вычета \f$ x \f$, заданного в представлении Монтгомери в виде \f$ xr \f$, где \f$ r \f$
    заданная степень двойки, вычисляется вычет \f$ z \f$,
    удовлетворяющий сравнению \f$z \equiv (x^k)r \pmod{p}\f$.
    Результат \f$ z \f$  является значением вычета \f$ x^k \pmod{p}\f$ в представлении Монтгомери.
    Величины \f$ k \f$  и \f$ p \f$ задаются как обычные вычеты и \f$ p \f$  отлично от нуля.

    @param z Вычет, в который помещается результат
    @param x Вычет, который возводится в степень \f$ k \f$
    @param k Степень, в которую возводится вычет \f$ x \f$
    @param p Модуль, по которому производятся вычисления
    @param n0 Константа, используемая в вычислениях. Представляет собой младшее слово числа n,
    удовлетворяющего равенству \f$ rs - np = 1\f$.
    @param size Размер модуля в словах (значение константы \ref ak_mpzn256_size
    или \ref ak_mpzn512_size )                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_modpow_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *k,
                                                   ak_uint64 *p, ak_uint64 n0, const size_t size )
{
  ak_uint64 uk = 0;
  size_t s = size-1;
  long long int i, j;
  ak_mpznmax res = ak_mpznmax_zero; // это константа r (mod p) = r-p
  if( ak_mpzn_sub( res, res, p, size ) == 0 ) {
    ak_error_message( ak_error_undefined_value,
                                          "using an unexpected value of prime modulo", __func__ );
    return;
  }
  while( k[s] == 0 ) {
     if( s > 0 ) --s;
      else {
             ak_mpzn_set( z, res, size );
             return;
           }
  }
  for( i = s; i >= 0; i-- ) {
     uk = k[i];
     for( j = 0; j < 64; j++ ) {
        ak_mpzn_mul_montgomery( res, res, res, p, n0, size );
        if( uk&0x8000000000000000LL ) ak_mpzn_mul_montgomery( res, res, x, p, n0, size );
        uk <<= 1;
     }
  }
  memcpy( z, res, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_GMP_H
/* преобразование "туда и обратно" */
 void ak_mpzn_to_mpz( const ak_uint64 *x, const size_t size, mpz_t xm )
{
 mpz_import( xm, size, -1, sizeof( ak_uint64 ), 0, 0, x );
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_mpz_to_mpzn( const mpz_t xm, ak_uint64 *x, const size_t size )
{
 memcpy( x, xm->_mp_d, size*sizeof( ak_uint64 ));
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_mpzn.c  */
/* ----------------------------------------------------------------------------------------------- */
