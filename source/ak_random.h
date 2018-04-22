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
/*   ak_random.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_RANDOM_H__
#define    __AK_RANDOM_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 struct random;
/*! \brief Указатель на класс генератора псевдо-случайных чисел. */
 typedef struct random *ak_random;

/* ----------------------------------------------------------------------------------------------- */
 typedef int ( ak_function_random )( ak_random );
 typedef int ( ak_function_random_ptr_const )( ak_random, const ak_pointer, const size_t );
 typedef ak_handle ( ak_function_random_new ) ( void );
/*! \brief Функция создания контекста генератора псевдо случайных последовательностей. */
 typedef int ( ak_function_random_create ) ( ak_random );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий произвольный генератор псевдо-случайных чисел.                       */
/* ----------------------------------------------------------------------------------------------- */
 struct random {
   /*! \brief указатель на внутренние структуры данных */
   ak_pointer data;

   /*! \brief указатель на функцию выработки следующего внутреннего состояния */
   ak_function_random *next;
   /*! \brief указатель на функцию инициализации генератора заданным массивом значений */
   ak_function_random_ptr_const *randomize_ptr;
   /*! \brief указатель на функцию выработки последователности псевдо-случайных байт */
   ak_function_random_ptr_const *random;
   /*! \brief указатель на функцию освобождения памяти внутренней структуры данных */
   ak_function_free *free;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация генератора псевдо-случайных чисел. */
 int ak_random_create( ak_random );
/*! \brief Уничтожение данных, хранящихся в полях структуры struct random. */
 int ak_random_destroy( ak_random );
/*! \brief Уничтожение генератора псевдо-случайных чисел. */
 ak_pointer ak_random_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание генератора BBS псевдо-случайных чисел. */
 int ak_random_create_bbs( ak_random );
/*! \brief Создание линейного конгруэнтного генератора псевдо-случайных чисел. */
 int ak_random_create_lcg( ak_random );
/*! \brief Cоздание генератора, считывающего случайные значения из заданного файла. */
 int ak_random_create_file( ak_random , const char * );
#if defined(__unix__) || defined(__APPLE__)
/*! \brief Cоздание генератора, считывающего случайные значения из /dev/random. */
 int ak_random_create_random( ak_random );
/*! \brief Cоздание генератора, считывающего случайные значения из /dev/urandom. */
 int ak_random_create_urandom( ak_random );
#endif
#ifdef _WIN32
/*! \brief Интерфейс доступа к генератору псевдо-случайных чисел, предоставляемому ОС Windows. */
 int ak_random_create_winrtl( ak_random );
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция генерации случайного 64-х битного целого числа. */
 ak_uint64 ak_random_value( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_random.h  */
/* ----------------------------------------------------------------------------------------------- */
