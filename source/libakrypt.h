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
/*   libakrypt.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_H__
#define    __LIBAKRYPT_H__

/* ----------------------------------------------------------------------------------------------- */
#ifdef DLL_EXPORT
 #define building_dll
#endif
#ifdef _MSC_VER
 #define building_dll
#endif
/* ----------------------------------------------------------------------------------------------- */
/* Обрабатываем вариант библиотеки для работы под Windows (Win32)                                  */
#ifdef building_dll
 #define dll_export __declspec (dllexport)
#else
/* ----------------------------------------------------------------------------------------------- */
/* Для остальных операционных систем символ теряет свой смысл ;)                                   */
 #define dll_export
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #pragma warning (disable : 4711)
 #pragma warning (disable : 4820)
 #pragma warning (disable : 4996)
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <pthread.h>
 #include <sys/types.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDALIGN
 #include <stdalign.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 #include <emmintrin.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <windows.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #include <io.h>
 #include <conio.h>
 #include <process.h>
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef __MINGW32__
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef MSYS
 typedef int32_t ak_int32;
 typedef u_int32_t ak_uint32;
 typedef int64_t ak_int64;
 typedef u_int64_t ak_uint64;
 int snprintf(char *str, size_t size, const char *format, ... );
#endif
#if defined(__unix__) || defined(__APPLE__)
 typedef signed int ak_int32;
 typedef unsigned int ak_uint32;
 typedef signed long long int ak_int64;
 typedef unsigned long long int ak_uint64;
#endif


/* ----------------------------------------------------------------------------------------------- */
 typedef signed char ak_int8;
 typedef unsigned char ak_uint8;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для обработки 128-ми битных значений. */
 typedef union {
    ak_uint8 b[16];
    ak_uint64 q[2];
 } ak_uint128;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение булева типа, принимающего значения либо истина, либо ложь. */
 typedef enum { ak_false, ak_true } ak_bool;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef void *ak_pointer;
/*! \brief Дескриптор произвольного объекта библиотеки. */
 typedef ak_int64 ak_handle;
/*! \brief Стандартная для языка С функция выделения памяти. */
 typedef ak_pointer ( ak_function_alloc )( size_t );
/*! \brief Стандартная для языка С функция освобождения памяти. */
 typedef void ( ak_function_free )( ak_pointer );
/*! \brief Функция, возвращающая NULL после освобождения памяти. */
 typedef ak_pointer ( ak_function_free_object )( ak_pointer );
/*! \brief Стандартная для языка С функция перераспределения памяти. */
 typedef ak_pointer ( ak_function_realloc )( ak_pointer , size_t );
/*! \brief Пользовательская функция аудита. */
 typedef int ( ak_function_log )( const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Результат, говорящий об отсутствии ошибки. */
 #define ak_error_ok                            (0)
/*! \brief Ошибка выделения оперативной памяти. */
 #define ak_error_out_of_memory                (-1)
/*! \brief Ошибка, возникающая при доступе или передаче в качестве аргумента функции null указателя. */
 #define ak_error_null_pointer                 (-2)
/*! \brief Ошибка, возникащая при передаче аргументов функции или выделении памяти нулевой длины. */
 #define ak_error_zero_length                  (-3)
/*! \brief Ошибка, возникающая при обработке данных ошибочной длины. */
 #define ak_error_wrong_length                 (-4)
/*! \brief Использование неопределенного значения. */
 #define ak_error_undefined_value              (-5)
/*! \brief Использование неопределенного указателя на функцию (вызов null указателя). */
 #define ak_error_undefined_function           (-6)
/*! \brief Попытка доступа к неопределенной опции библиотеки. */
 #define ak_error_wrong_option                 (-7)
/*! \brief Ошибка создания файла. */
 #define ak_error_create_file                  (-9)
/*! \brief Ошибка доступа к файлу (устройству). */
 #define ak_error_access_file                 (-10)
/*! \brief Ошибка открытия файла (устройства). */
 #define ak_error_open_file                   (-11)
/*! \brief Ошибка закрытия файла (устройства). */
 #define ak_error_close_file                  (-12)
/*! \brief Ошибка чтения из файла (устройства). */
 #define ak_error_read_data                   (-13)
/*! \brief Ошибка записи в файл (устройство). */
 #define ak_error_write_data                  (-14)
/*! \brief Ошибка записи в файл - файл существует */
 #define ak_error_file_exists                 (-15)
/*! \brief Неверное значение дескриптора объекта. */
 #define ak_error_wrong_handle                (-16)
/*! \brief Ошибка, возникающая в случае неправильного значения размера структуры хранения контекстов. */
 #define ak_error_context_manager_size        (-17)
/*! \brief Ошибка, возникающая при превышении числа возможных элементов структуры хранения контекстов. */
 #define ak_error_context_manager_max_size    (-18)

/*! \brief Неверный тип криптографического механизма. */
 #define ak_error_oid_engine                  (-19)
/*! \brief Неверный режим использования криптографического механизма. */
 #define ak_error_oid_mode                    (-20)
/*! \brief Ошибочное или не определенное имя криптографического механизма. */
 #define ak_error_oid_name                    (-21)
/*! \brief Ошибочный или неопределенный идентификатор криптографического механизма. */
 #define ak_error_oid_id                      (-22)
/*! \brief Ошибочный индекс идентификатора криптографического механизма. */
 #define ak_error_oid_index                   (-23)
/*! \brief Ошибка с обращением к oid. */
 #define ak_error_wrong_oid                   (-24)

/*! \brief Ошибка при сравнении двух массивов данных. */
 #define ak_error_not_equal_data              (-25)
/*! \brief Ошибка выполнения библиотеки на неверной архитектуре. */
 #define ak_error_wrong_endian                (-26)
/*! \brief Ошибка чтения из терминала. */
 #define ak_error_terminal                    (-27)
/*! \brief Ошибка исчерпания количества возможных использований ключа. */
 #define ak_error_resource_counter            (-28)
/*! \brief Ошибка, возникающая при использовании ключа, значение которого не определено. */
 #define ak_error_key_value                   (-29)
/*! \brief Ошибка, возникающая при зашифровании/расшифровании данных, длина которых не кратна длине блока. */
 #define ak_error_wrong_block_cipher_length   (-30)
/*! \brief Ошибка, возникающая при неверном значении кода целостности ключа. */
 #define ak_error_wrong_key_icode             (-31)
/*! \brief Ошибка, возникающая при недостаточном ресурсе ключа. */
 #define ak_error_low_key_resource            (-32)
/*! \brief Ошибка, возникающая при использовании синхропосылки (инициализационного вектора) неверной длины. */
 #define ak_error_wrong_iv_length             (-33)
/*! \brief Ошибка, возникающая при неправильном использовании функций зашифрования/расшифрования данных. */
 #define ak_error_wrong_block_cipher_function (-34)
/*! \brief Ошибка, возникающая если заданная точка не принадлежит заданной кривой. */
 #define ak_error_curve_point                 (-40)
/*! \brief Ошибка, возникающая когда порядок точки неверен. */
 #define ak_error_curve_point_order           (-41)
/*! \brief Ошибка, возникающая если дискриминант кривой равен нулю (уравнение не задает кривую). */
 #define ak_error_curve_discriminant          (-42)
/*! \brief Ошибка, возникающая когда неверно определены вспомогательные параметры эллиптической кривой. */
 #define ak_error_curve_order_parameters      (-43)
/*! \brief Ошибка, возникающая когда простой модуль кривой задан неверно. */
 #define ak_error_curve_prime_size            (-44)

/*! \brief Ошибка, возникающая при кодировании ASN1 структуры (перевод в DER-кодировку). */
 #define ak_error_wrong_asn1_encode           (-50)
/*! \brief Ошибка, возникающая при декодировании ASN1 структуры (перевод из DER-кодировки в ASN1 структуру). */
 #define ak_error_wrong_asn1_decode           (-51)

/* ----------------------------------------------------------------------------------------------- */
 #define ak_null_string                  ("(null)")

/*! \brief Минимальный уровень аудита */
 #define ak_log_none                            (0)
/*! \brief Стандартный уровень аудита */
 #define ak_log_standard                        (1)
/*! \brief Максимальный уровень аудита */
 #define ak_log_maximum                         (2)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип криптографического механизма. */
 typedef enum {
   /*! \brief неопределенный механизм, может возвращаться как ошибка */
     undefined_engine,
   /*! \brief идентификатор */
     identifier,
   /*! \brief симметричный шифр (блочный алгоритм)  */
     block_cipher,
   /*! \brief симметричный шифр (поточный алгоритм)  */
     stream_cipher,
   /*! \brief схема гибридного шифрования */
     hybrid_cipher,
   /*! \brief функция хеширования */
     hash_function,
   /*! \brief ключевая функция хеширования (функция вычисления имитовставки) */
     mac_function,
   /*! \brief функция выработки электронной подписи (секретный ключ электронной подписи) */
     sign_function,
   /*! \brief функция проверки электронной подписи (ключ проверки электронной подписи) */
     verify_function,
   /*! \brief генератор случайных и псевдо-случайных последовательностей */
     random_generator,
   /*! \brief механизм итерационного вычисления сжимающих отображений */
     update_engine,
   /*! \brief механизм идентификаторов криптографических алгоритмов */
     oid_engine
} ak_oid_engine;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режим и параметры использования криптографического механизма. */
 typedef enum {
   /*! \brief неопределенный режим, может возвращаться в как ошибка */
     undefined_mode,
   /*! \brief собственно криптографический механизм (алгоритм) */
     algorithm,
   /*! \brief данные */
     parameter,
   /*! \brief набор параметров эллиптической кривой в форме Вейерштрасса */
     wcurve_params,
   /*! \brief набор параметров эллиптической кривой в форме Эдвардса */
     ecurve_params,
   /*! \brief набор перестановок */
     kbox_params,
   /*! \brief режим простой замены блочного шифра (ГОСТ Р 34.13-2015, раздел 5.1) */
     ecb,
   /*! \brief режим гаммирования для блочного шифра (ГОСТ Р 34.13-2015, раздел 5.2) */
     counter,
   /*! \brief режим гаммирования для блочного шифра согласно ГОСТ 28147-89 */
     counter_gost,
   /*! \brief режим гаммирования c обратной связью по выходу (ГОСТ Р 34.13-2015, раздел 5.3) */
     ofb,
   /*! \brief режим простой замены с зацеплением (ГОСТ Р 34.13-2015, раздел 5.4) */
     cbc,
   /*! \brief режим гаммирования c обратной связью по шифртексту (ГОСТ Р 34.13-2015, раздел 5.5) */
     cfb,
   /*! \brief режим шифрования XTS для блочного шифра */
     xts,
   /*! \brief шифрование с аутентификацией сообщений */
     xts_mac,
   /*! \brief режим гаммирования поточного шифра (сложение по модулю 2) */
     xcrypt,
   /*! \brief гаммирование по модулю \f$ 2^8 \f$ поточного шифра */
     a8,
   /*! \brief вычисление электронной подписи */
     signify,
   /*! \brief проверка электронной подписи */
     verify
} ak_oid_mode;

/* ----------------------------------------------------------------------------------------------- */
 struct buffer;
/*! \brief Контекст буффера. */
 typedef struct buffer *ak_buffer;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает уровень аудита библиотеки. */
 dll_export int ak_log_get_level( void );
/*! \brief Прямой вывод сообщения аудита. */
 dll_export int ak_log_set_message( const char * );
/*! \brief Явное задание функции аудита. */
 dll_export int ak_log_set_function( ak_function_log * );
#ifdef LIBAKRYPT_HAVE_SYSLOG_H
 /*! \brief Функиция вывода сообщения об ошибке с помощью демона операционной системы. */
 int ak_function_log_syslog( const char * );
#endif
/*! \brief Функция вывода сообщения об ошибке в стандартный канал вывода ошибок. */
 dll_export int ak_function_log_stderr( const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message( const int, const char *, const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message_fmt( const int , const char *, const char *, ... );
/*! \brief Функция устанавливает значение переменной, хранящей ошибку выполнения программы. */
 dll_export int ak_error_set_value( const int );
/*! \brief Функция возвращает код последней ошибки выполнения программы. */
 dll_export int ak_error_get_value( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает константный указатель NULL-строку с текущей версией библиотеки. */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция инициализации и тестирования криптографических механизмов библиотеки. */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция остановки поддержки криптографических механизмов. */
 dll_export int ak_libakrypt_destroy( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение общего количества опций библиотеки */
 dll_export const size_t ak_libakrypt_options_count( void );
/*! \brief Получение имени опции по ее номеру. */
 dll_export const char *ak_libakrypt_get_option_name( const size_t index );
/*! \brief Получение значения опции по ее номеру. */
 dll_export int ak_libakrypt_get_option_value( const size_t index );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение точного количества типов криптографических механизмов. */
 dll_export const size_t ak_libakrypt_engines_count( void );
/*! \brief Получение константного символьного описания типа криптографического механизма. */
 dll_export const char *ak_libakrypt_get_engine_str( ak_oid_engine );
/*! \brief Получение типа криптографического механизма по его символьному описанию. */
 dll_export ak_oid_engine ak_libakrypt_get_engine( const char * );
/*! \brief Получения символьного описания режима применения криптографического механизма. */
 dll_export const char *ak_libakrypt_get_mode_str( ak_oid_mode );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение количества доступных OID библиотеки. */
 dll_export const size_t ak_libakrypt_oids_count( void );
/*! \brief Поиск OID по типу криптографического механизма. */
 dll_export ak_handle ak_libakrypt_find_oid_by_engine( ak_oid_engine );
/*! \brief Продолжение поиска OID по типу криптографического механизма. */
 dll_export ak_handle ak_libakrypt_findnext_oid_by_engine( ak_handle, ak_oid_engine );
/*! \brief Поиск OID его имени. */
 dll_export ak_handle ak_libakrypt_find_oid_by_name( const char * );
/*! \brief Поиск OID по его идентификатору (строке цифр, разделенных точками). */
 dll_export ak_handle ak_libakrypt_find_oid_by_id( const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение читаемого имени OID. */
 dll_export const char *ak_libakrypt_oid_get_name( ak_handle );
/*! \brief Получение значения OID - последовательности чисел, разделенных точками. */
 dll_export const char *ak_libakrypt_oid_get_id( ak_handle );
/*! \brief Получение типа криптографического механизма. */
 dll_export const ak_oid_engine ak_libakrypt_oid_get_engine( ak_handle );
/*! \brief Получение словесного описания для типа криптографического механизма. */
 dll_export const char *ak_libakrypt_oid_get_engine_str( ak_handle );
/*! \brief Получение режима использования криптографического механизма. */
 dll_export const ak_oid_mode ak_libakrypt_oid_get_mode( ak_handle );
/*! \brief Получение словесного описания режима использования криптографического механизма. */
 dll_export const char *ak_libakrypt_oid_get_mode_str( ak_handle );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение типа криптографического механизма для существующего дескриптора. */
 dll_export ak_oid_engine ak_handle_get_engine( ak_handle );
/*! \brief Получение символьного описания (null-строки) типа криптографического механизма. */
 dll_export const char *ak_handle_get_engine_str( ak_handle handle );
/*! \brief Удаление дескриптора объекта. */
 dll_export int ak_handle_delete( ak_handle );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание буффера заданного размера. */
 dll_export ak_buffer ak_buffer_new_size( const size_t );
/*! \brief Создание буффера с данными. */
 dll_export ak_buffer ak_buffer_new_ptr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Создание буффера с данными, записанными в шестнадцатеричном виде. */
 dll_export ak_buffer ak_buffer_new_hexstr( const char * );
/*! \brief Создание буффера заданной длины с данными, записанными в шестнадцатеричном виде. */
 dll_export ak_buffer ak_buffer_new_hexstr_size( const char * , const size_t , const ak_bool );
/*! \brief Создание буффера, содержащего строку символов, оканчивающуюся нулем. */
 dll_export ak_buffer ak_buffer_new_str( const char * );
/*! \brief Уничтожение буффера. */
 dll_export ak_pointer ak_buffer_delete( ak_pointer );
/*! \brief Пощемение двоичных данных в буффер. */
 dll_export int ak_buffer_set_ptr( ak_buffer , const ak_pointer , const size_t , const ak_bool );
/*! \brief Пощемение в буффер данных, заданных строкой в  шестнадцатеричном представлении. */
 dll_export int ak_buffer_set_hexstr( ak_buffer, const char * );
/*! \brief Помещение в буффер строки, оканчивающейся нулем. */
 dll_export int ak_buffer_set_str( ak_buffer, const char * );
/*! \brief Получение указателя на данные (как на строку символов). */
 dll_export const char *ak_buffer_get_str( ak_buffer );
/*! \brief Получение указателя на данные. */
 dll_export ak_pointer ak_buffer_get_ptr( ak_buffer );
/*! \brief Получение размера буффера. */
 dll_export const size_t ak_buffer_get_size( ak_buffer );
/*! \brief Получение строки символов с шестнадцатеричным значением буффера. */
 dll_export char *ak_buffer_to_hexstr( const ak_buffer );
/*! \brief Сравнение двух буфферов. */
 dll_export ak_bool ak_buffer_is_equal( const ak_buffer, const ak_buffer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание строки символов, содержащей значение заданной области памяти. */
 dll_export char *ak_ptr_to_hexstr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Преобразование области памяти в символьное представление. */
 dll_export int ak_ptr_to_hexstr_static( const ak_pointer , const size_t , ak_pointer ,
                                                                     const size_t , const ak_bool );
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных. */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const ak_bool );
/*! \brief Сравнение двух областей памяти. */
 dll_export ak_bool ak_ptr_is_equal( const ak_pointer, const ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание дескриптора линейного конгруэнтного генератора. */
 dll_export ak_handle ak_random_new_lcg( void  );
/*! \brief Создание дескриптора генератора, предоставляющего доступ к заданному файлу с данными. */
 dll_export ak_handle ak_random_new_file( const char * );
#if defined(__unix__) || defined(__APPLE__)
/*! \brief Создание дескриптора генератора, предоставляющего доступ к символьному устройству `/dev/random`. */
 dll_export ak_handle ak_random_new_dev_random( void );
/*! \brief Создание дескриптора генератора, предоставляющего доступ к символьному устройству `/dev/urandom`. */
 dll_export ak_handle ak_random_new_dev_urandom( void );
#endif
#ifdef _WIN32
/*! \brief Создание дескриптора системного генератора ОС Windows. */
 dll_export ak_handle ak_random_new_winrtl( void );
#endif
/*! \brief Создание дескриптора генератора по его OID. */
 dll_export ak_handle ak_random_new_oid( ak_handle );
/*! \brief Создание дескриптора генератора с использованием хэш-функции. */
 dll_export ak_handle ak_random_new_tc26(const char * hash_function_name);
/*! \brief Заполнение заданного массива случайными данными. */
 dll_export int ak_random_ptr( ak_handle, const ak_pointer, const size_t );
/*! \brief Создание буффера заданного размера со случайными данными. */
 dll_export ak_buffer ak_random_buffer( ak_handle, const size_t );
/*! \brief Выработка одного псевдо-случайного байта. */
 dll_export ak_uint8 ak_random_uint8( ak_handle );
/*! \brief Выработка одного псевдо-случайного слова размером 8 байт (64 бита). */
 dll_export ak_uint64 ak_random_uint64( ak_handle );
/*! \brief Инициализация генератора данными, содержащимися в заданной области памяти. */
 dll_export int ak_random_randomize( ak_handle, const ak_pointer, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание дескриптора функции хеширования ГОСТ Р 34.11-2012 (Стрибог256). */
 dll_export ak_handle ak_hash_new_streebog256( void );
/*! \brief Создание дескриптора функции хеширования ГОСТ Р 34.11-2012 (Стрибог512). */
 dll_export ak_handle ak_hash_new_streebog512( void );
/*! \brief Создание дескриптора функции хеширования ГОСТ Р 34.11-94 с заданными таблицами замен. */
 dll_export ak_handle ak_hash_new_gosthash94( ak_handle );
/*! \brief Создание дескриптора функции хеширования ГОСТ Р 34.11-94 с таблицами замен из CSP. */
 dll_export ak_handle ak_hash_new_gosthash94_csp( void );
/*! \brief Создание дескриптора функции хеширования по ее OID. */
 dll_export ak_handle ak_hash_new_oid( ak_handle );
/*! \brief Получение длины хешкода для заданной функции хеширования (в байтах). */
 dll_export size_t ak_hash_get_icode_size( ak_handle );
/*! \brief Хеширование заданной области памяти. */
 dll_export ak_buffer ak_hash_ptr( ak_handle , const ak_pointer , const size_t , ak_pointer );
/*! \brief Хеширование заданного файла. */
 dll_export ak_buffer ak_hash_file( ak_handle , const char* , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Чтение пароля из консоли. */
 dll_export int ak_password_read( char *, const size_t );
/*! \brief Чтение пароля из консоли в буффер. */
 dll_export int ak_password_read_buffer( ak_buffer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обобщенная реализация функции snprintf для различных компиляторов. */
 dll_export int ak_snprintf( char *str, size_t size, const char *format, ... );

/* ----------------------------------------------------------------------------------------------- */
#ifndef __STDC_VERSION__
  #define inline
  int snprintf(char *str, size_t size, const char *format, ... );
#endif
#ifdef _MSC_VER
 #define __func__  __FUNCTION__
#endif
#ifndef _WIN32
 #ifndef O_BINARY
   #define O_BINARY  ( 0x0 )
 #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
#define ak_max(x,y) ((x) > (y) ? (x) : (y))
#define ak_min(x,y) ((x) < (y) ? (x) : (y))

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */
