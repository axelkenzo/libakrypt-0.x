/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 by Mikhail Lavrinovich, mikhail.lavrinovich@netcracker.com                  */
/*  Copyright (c) 2018 by Petr Mikhalitsyn, myprettycapybara@gmail.com                             */
/*  Copyright (c) 2019 by Diffractee                                                               */
/*  Copyright (c) 2019 by kirlit26                                                                 */
/*  Copyright (c) 2019 by Anton Sakharov                                                           */
/*                                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*  Файл libakrypt.h                                                                               */
/*                                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_H__
#define    __LIBAKRYPT_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_GMP_H
 #define LIBAKRYPT_HAVE_GMP_H
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Попытка доступа к неопределенной опции библиотеки. */
 #define ak_error_wrong_option                (-100)
/*! \brief Ошибка использования неправильного (неожидаемого) значения. */
 #define ak_error_invalid_value               (-101)

/*! \brief Неверный тип криптографического механизма. */
 #define ak_error_oid_engine                  (-110)
/*! \brief Неверный режим использования криптографического механизма. */
 #define ak_error_oid_mode                    (-111)
/*! \brief Ошибочное или не определенное имя криптографического механизма. */
 #define ak_error_oid_name                    (-112)
/*! \brief Ошибочный или неопределенный идентификатор криптографического механизма. */
 #define ak_error_oid_id                      (-113)
/*! \brief Ошибочный индекс идентификатора криптографического механизма. */
 #define ak_error_oid_index                   (-114)
/*! \brief Ошибка с обращением к oid. */
 #define ak_error_wrong_oid                   (-115)

/*! \brief Ошибка, возникающая когда параметры кривой не соответствуют алгоритму, в котором они используются. */
 #define ak_error_curve_not_supported         (-120)
/*! \brief Ошибка, возникающая если точка не принадлежит заданной кривой. */
 #define ak_error_curve_point                 (-121)
/*! \brief Ошибка, возникающая когда порядок точки неверен. */
 #define ak_error_curve_point_order           (-122)
/*! \brief Ошибка, возникающая если дискриминант кривой равен нулю (уравнение не задает кривую). */
 #define ak_error_curve_discriminant          (-123)
/*! \brief Ошибка, возникающая когда неверно определены вспомогательные параметры эллиптической кривой. */
 #define ak_error_curve_order_parameters      (-124)
/*! \brief Ошибка, возникающая когда простой модуль кривой задан неверно. */
 #define ak_error_curve_prime_modulo          (-125)

/*! \brief Ошибка, возникающая при использовании ключа, значение которого не определено. */
 #define ak_error_key_value                   (-130)
/*! \brief Ошибка, возникающая при использовании ключа для бесключевых функций. */
 #define ak_error_key_usage                   (-131)
/*! \brief Ошибка, возникающая при неверном заполнении полей структуры bckey. */
 #define ak_error_wrong_block_cipher          (-132)
/*! \brief Ошибка, возникающая при зашифровании/расшифровании данных, длина которых не кратна длине блока. */
 #define ak_error_wrong_block_cipher_length   (-133)
/*! \brief Ошибка, возникающая при неверном значении кода целостности ключа. */
 #define ak_error_wrong_key_icode             (-134)
/*! \brief Ошибка, возникающая при неверном значении длины ключа. */
 #define ak_error_wrong_key_length            (-135)
/*! \brief Ошибка, возникающая при использовании неверного типа ключа. */
 #define ak_error_wrong_key_type              (-136)
/*! \brief Ошибка, возникающая при недостаточном ресурсе ключа. */
 #define ak_error_low_key_resource            (-137)
/*! \brief Ошибка, возникающая при использовании синхропосылки (инициализационного вектора) неверной длины. */
 #define ak_error_wrong_iv_length             (-138)
/*! \brief Ошибка, возникающая при неправильном использовании функций зашифрования/расшифрования данных. */
 #define ak_error_wrong_block_cipher_function (-139)
/*! \brief Ошибка согласования данных. */
 #define ak_error_linked_data                 (-140)

/*! \brief Использование неверного значения поля, определяющего тип данных */
 #define ak_error_invalid_asn1_tag            (-150)
/*! \brief Использование неверного значения длины данных, размещаемых в узле ASN1 дерева */
 #define ak_error_invalid_asn1_length         (-151)
/*! \brief Использование неверной функции для чтения отрицательных данных, размещаемых в узле ASN1 дерева */
 #define ak_error_invalid_asn1_significance   (-152)
/*! \brief Полученные ASN.1 данные содержат неверный или неожидаемый контент */
 #define ak_error_invalid_asn1_content        (-153)
/*! \brief Полученные ASN.1 данные содержат неверное количество элементов */
 #define ak_error_invalid_asn1_count          (-154)
/*! \brief Ошибка, возникающая при кодировании ASN1 структуры (перевод в DER-кодировку). */
 #define ak_error_wrong_asn1_encode           (-155)
/*! \brief Ошибка, возникающая при декодировании ASN1 структуры (перевод из DER-кодировки в ASN1 структуру). */
 #define ak_error_wrong_asn1_decode           (-156)

/*! \brief Ошибка использования для проверки сертификата неопределенного открытого ключа (null указатель) */
 #define ak_error_certificate_verify_key      (-160)
/*! \brief Ошибка использования для проверки сертификата открытого ключа
  с некорректным или не поддерживаемым алгоритмом электронной подписи. */
 #define ak_error_certificate_verify_engine   (-161)
/*! \brief Ошибка использования для проверки сертификата открытого ключа,
  расширенное имя владельца которого не совпадает с именем эмитента в проверяемом сертификате. */
 #define ak_error_certificate_verify_names    (-162)
/*! \brief Ошибка при импорте сертификата:
  срок действия сертификата не актуален (истек или еще не начался) */
 #define ak_error_certificate_validity        (-165)
/*! \brief Ошибка при импорте сертификата:
    сертификат не является сертификатом центра сертификации. */
 #define ak_error_certificate_ca              (-166)
/*! \brief Ошибка при импорте сертификата:
    сертификат не содержит установленный бит в расширении keyUsage. */
 #define ak_error_certificate_key_usage       (-167)
/*! \brief Ошибка при импорте сертификата:
    сертификат предназначен для некорректного или неподдерживаемого алгоритма электронной подписи. */
 #define ak_error_certificate_engine          (-168)
/*! \brief Ошибка при импорте сертификата: электроннная подпись под сертификатом не верна. */
 #define ak_error_certificate_signature       (-169)

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup options-doc Инициализация и настройка параметров библиотеки
 @{ */
/*! \brief Функция инициализации библиотеки. */
 dll_export bool_t ak_libakrypt_create( ak_function_log * );
/*! \brief Функция завершает работу с библиотекой. */
 dll_export int ak_libakrypt_destroy( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает номер версии бибилиотеки libakrypt. */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция возвращает общее количества опций библиотеки. */
 dll_export size_t ak_libakrypt_options_count( void );
/*! \brief Функция возвращает имя функции по ее индексу. */
 dll_export char *ak_libakrypt_get_option_name( const size_t );
/*! \brief Функция возвращает значение опции по ее имени. */
 dll_export ak_int64 ak_libakrypt_get_option_by_name( const char * );
/*! \brief Функция возвращает значение опции по ее индексу. */
 dll_export ak_int64 ak_libakrypt_get_option_by_index( const size_t );
/*! \brief Функция устанавливает значение заданной опции. */
 dll_export int ak_libakrypt_set_option( const char * , const ak_int64 );
/*! \brief Функция считывает значения опций библиотеки из файла. */
 dll_export bool_t ak_libakrypt_load_options( void );
/*! \brief Функция выводит текущие значения всех опций библиотеки. */
 dll_export void ak_libakrypt_log_options( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает режим совместимости криптографических преобразований с библиотекой openssl. */
 dll_export int ak_libakrypt_set_openssl_compability( bool_t );
/*! \brief Функция получает домашний каталог библиотеки. */
 dll_export int ak_libakrypt_get_home_path( char * , const size_t );
/*! \brief Функция создает полное имя файла в домашем каталоге библиотеки. */
 dll_export int ak_libakrypt_create_home_filename( char * , const size_t , char * , const int );
/*! \brief Функция выводит в заданный файл параметры эллиптической кривой. */
 dll_export int ak_libakrypt_print_curve( FILE * , const char * );
/** \addtogroup tests-doc Тестирование криптографических механизмов
 @{ */
/*! \brief Функция выполняет динамическое тестирование работоспособности криптографических преобразований. */
 dll_export bool_t ak_libakrypt_dynamic_control_test( void );
/*! \brief Функция тестирования корректности реализации операций умножения в полях характеристики два. */
 dll_export bool_t ak_libakrypt_test_gfn_multiplication( void );
 /*! \brief Функция тестирует все определяемые библиотекой параметры эллиптических кривых,
    заданных в короткой форме Вейерштрасса. */
 dll_export bool_t ak_libakrypt_test_wcurves( void );
/*! \brief Функция проверяет корректность реализации асимметричных криптографических алгоритмов. */
 dll_export bool_t ak_libakrypt_test_asymmetric_functions( void );
/*! \brief Проверка корректной работы функции хеширования Стрибог-256 */
 dll_export bool_t ak_libakrypt_test_streebog256( void );
/*! \brief Проверка корректной работы функции хеширования Стрибог-512 */
 dll_export bool_t ak_libakrypt_test_streebog512( void );
/*! \brief Функция проверяет корректность реализации алгоритмов хэширования. */
 dll_export bool_t ak_libakrypt_test_hash_functions( void );
/*! \brief Функция проверяет корректность реализации алгоритмов выработки имитовставки. */
 dll_export bool_t ak_libakrypt_test_mac_functions( void );
/*! \brief Тестирование алгоритмов выработки имитовставки HMAC с отечественными
    функциями хеширования семейства Стрибог (ГОСТ Р 34.11-2012). */
 dll_export bool_t ak_libakrypt_test_hmac_streebog( void );
/*! \brief Тестирование алгоритма PBKDF2, регламентируемого Р 50.1.113-2016. */
 dll_export bool_t ak_libakrypt_test_pbkdf2( void );
/*! \brief Функция тестирует корректность реализации блочных шифрова и режимов их использования. */
 dll_export bool_t ak_libakrypt_test_block_ciphers( void ); 
/*! \brief Тестирование корректной работы алгоритма блочного шифрования Магма (ГОСТ Р 34.12-2015). */
 dll_export bool_t ak_libakrypt_test_magma( void );
/*! \brief Тестирование корректной работы алгоритма блочного шифрования Кузнечик (ГОСТ Р 34.12-2015). */
 dll_export bool_t ak_libakrypt_test_kuznechik( void );
/*! \brief Функция тестирует корректность реаличных реализаций алгоритма cmac. */
 dll_export bool_t ak_libakrypt_test_cmac( void );
/*! \brief Тестирование корректной работы режима блочного шифрования с одновременной
    выработкой имитовставки. */
 dll_export bool_t ak_libakrypt_test_mgm( void );
/*! \brief Тестирование корректной работы режима шифрования `ACPKM`, регламентируемого Р 1323565.1.017—2018. */
 dll_export bool_t ak_libakrypt_test_acpkm( void );
/*! \brief Выполнение тестовых примеров для алгоритмов выработки и проверки электронной подписи */
 dll_export bool_t ak_libakrypt_test_sign( void );

/** @}*//** @}*/

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на класс генератора псевдо-случайных чисел. */
 typedef struct random *ak_random;

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup oid-doc Идентификаторы криптографических механизмов
 @{ */
/*! \brief Указатель на идентификатор криптографического механизма */
 typedef struct oid *ak_oid;
/*! \brief Функция, возвращающая код ошибки после инициализации объекта (конструктор). */
 typedef int ( ak_function_create_object ) ( ak_pointer );
/*! \brief Функция, возвращающая код ошибки после разрушения объекта (деструктор). */
 typedef int ( ak_function_destroy_object ) ( ak_pointer );
/*! \brief Функция, выполняющая криптографическое преобразование. */
 typedef int ( ak_function_run_object ) ( ak_pointer, ... );
/*! \brief Функция, выполняющая присвоение фиксированного ключа. */
 typedef int ( ak_function_set_key_object ) ( ak_pointer, const ak_pointer , const size_t );
/*! \brief Функция, выполняющая выработку нового случайного ключа. */
 typedef int ( ak_function_set_key_random_object ) ( ak_pointer, ak_random );
/*! \brief Функция, выполняющая выработку ключа из пароля. */
 typedef int ( ak_function_set_key_from_password_object ) ( ak_pointer,
                               const ak_pointer , const size_t , const ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, контролирующая функционирование криптографических объектов библиотеки. */
/*! \details Структура представляет из себя описатель класса, позволяющий создавать и уничтожать
 объекты данного класса, а также вызывать базовые функции чтения и сохранения объектов.            */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct object {
 /*! \brief Размер области памяти для первого объекта. */
  size_t size;
 /*! \brief Конструктор первого объекта. */
  ak_function_create_object *create;
 /*! \brief Деструктор первого объекта. */
  ak_function_destroy_object *destroy;
 /*! \brief Функция, выполняющая присвоение фиксированного ключа. */
  ak_function_set_key_object *set_key;
 /*! \brief Функция, выполняющая выработку нового случайного ключа. */
  ak_function_set_key_random_object *set_key_random;
 /*! \brief Функция, выполняющая выработку ключа из пароля. */
  ak_function_set_key_from_password_object *set_key_from_password;
 } *ak_object;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, контролирующая функциональные возможности алгоритма. */
/*! \details Обеспечивает доступ к объектам (секретным ключам),
   а также криптографическим преобразованиям. */
 typedef struct functional_objects {
 /*! \brief Управляющий объект криптографического алгоритма */
  struct object first;
 /*! \brief Второй объект, в ряде алгоритмов - второй ключ криптографического алгоритма */
  struct object second;
 /*! \brief Функция выполняющая прямое преобразование.
     \details В качестве такого преобразования может выступать, например, режим зашифрования
     для блочного шифра или алгоритм выработки имитовставки. */
  ak_function_run_object *direct;
 /*! \brief Функция выполняющая обратное преобразование.
     \details В качестве такого преобразования может выступать, например, режим расшифрования
     для блочного шифра. */
  ak_function_run_object *invert;
} *ak_functional_objects;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип криптографического механизма. */
 typedef enum {
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
   /*! \brief семейство ключевых функций хеширования HMAC */
     hmac_function,
   /*! \brief семейство функций выработки имитовставки согласно ГОСТ Р 34.13-2015. */
     cmac_function,
   /*! \brief семейство функций выработки имитовставки MGM. */
     mgm_function,
   /*! \brief класс всех ключевых функций хеширования (функций вычисления имитовставки) */
     mac_function,
   /*! \brief функция выработки электронной подписи (секретный ключ электронной подписи) */
     sign_function,
   /*! \brief функция проверки электронной подписи (ключ проверки электронной подписи) */
     verify_function,
   /*! \brief генератор случайных и псевдо-случайных последовательностей */
     random_generator,
   /*! \brief механизм идентификаторов криптографических алгоритмов */
     oid_engine,
   /*! \brief алгоритм выработки мастер ключа для схемы Блома распределения симметричных ключей */
     blom_master,
   /*! \brief алгоритм выработки ключа абонента для схемы Блома распределения симметричных ключей */
     blom_subscriber,
   /*! \brief алгоритм выработки ключа парной связи */
    blom_pairwise,
   /*! \brief неопределенный механизм, может возвращаться как ошибка */
     undefined_engine
} oid_engines_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режим и параметры использования криптографического механизма. */
 typedef enum {
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
   /*!  \brief базовый режим шифрования */
     encrypt_mode,
   /*!  \brief режим шифрования с двумя ключами */
     encrypt2k_mode,
   /*! \brief режим шифрования с указанием длины обрабатываемого блока */
     acpkm,
   /*! \brief режим выработки имитовставки */
     mac,
   /*! \brief режим аутентифицирующего шифрования */
     aead,
   /*! \brief режим гаммирования поточного шифра (сложение по модулю 2) */
     xcrypt,
   /*! \brief описатель для типов данных, помещаемых в asn1 дерево */
     descriptor,
   /*! \brief неопределенный режим, может возвращаться как ошибка */
     undefined_mode
} oid_modes_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения идентификаторов объектов (криптографических механизмов) и их данных. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct oid {
  /*! \brief Тип криптографического механизма. */
   oid_engines_t engine;
  /*! \brief Режим применения криптографического механизма. */
   oid_modes_t mode;
  /*! \brief Перечень идентификаторов криптографического механизма. */
   const char **id;
  /*! \brief Перечень доступных имен криптографического механизма. */
   const char **name;
  /*! \brief Указатель на данные. */
   ak_pointer data;
  /*! \brief Структура, контролирующая поведение объектов криптографического механизма. */
   struct functional_objects func;
} *ak_oid;

/* ----------------------------------------------------------------------------------------------- */
 #define ak_object_undefined { 0, NULL, NULL, NULL, NULL, NULL }
 #define ak_functional_objects_undefined { ak_object_undefined, ak_object_undefined, NULL, NULL }
 #define ak_oid_undefined { undefined_engine, undefined_mode, \
                                              NULL, NULL, NULL, ak_functional_objects_undefined }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение человекочитаемого имени для заданного типа криптографического механизма. */
 dll_export const char *ak_libakrypt_get_engine_name( const oid_engines_t );
/*! \brief Получение человекочитаемого имени режима или параметров криптографического механизма. */
 dll_export const char *ak_libakrypt_get_mode_name( const oid_modes_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание объекта в оперативной памяти (куче) */
 dll_export ak_pointer ak_oid_new_object( ak_oid );
/*! \brief Удаление объекта из кучи */
 dll_export ak_pointer ak_oid_delete_object( ak_oid , ak_pointer );
/*! \brief Создание второго объекта в оперативной памяти (куче) */
 dll_export ak_pointer ak_oid_new_second_object( ak_oid );
/*! \brief Удаление второго объекта из кучи */
 dll_export ak_pointer ak_oid_delete_second_object( ak_oid , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает количество идентификаторов библиотеки. */
 dll_export size_t ak_libakrypt_oids_count( void );
/*! \brief Получение OID по его внутреннему индексу. */
 dll_export ak_oid ak_oid_find_by_index( const size_t );
/*! \brief Поиск OID его имени. */
 dll_export ak_oid ak_oid_find_by_name( const char * );
/*! \brief Поиск OID по его идентификатору (строке цифр, разделенных точками). */
 dll_export ak_oid ak_oid_find_by_id( const char * );
/*! \brief Поиск OID по его имени или идентификатору. */
 dll_export ak_oid ak_oid_find_by_ni( const char * );
/*! \brief Поиск OID по указателю на даные */
 dll_export ak_oid ak_oid_find_by_data( ak_const_pointer  );
/*! \brief Поиск OID по типу криптографического механизма. */
 dll_export ak_oid ak_oid_find_by_engine( const oid_engines_t );
/*! \brief Продолжение поиска OID по типу криптографического механизма. */
 dll_export ak_oid ak_oid_findnext_by_engine( const ak_oid, const oid_engines_t );
/*! \brief Поиск OID по режиму работы криптографического механизма. */
 dll_export ak_oid ak_oid_find_by_mode( const oid_modes_t );
/*! \brief Продолжение поиска OID по режиму работы криптографического механизма. */
 dll_export ak_oid ak_oid_findnext_by_mode( const ak_oid, const oid_modes_t );
/*! \brief Проверка соответствия заданного адреса корректному oid. */
 dll_export bool_t ak_oid_check( const ak_pointer );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup random-doc Генераторы псевдо-случайных чисел
 @{ */
/*! \brief Функция, принимающая в качестве аргумента указатель на структуру struct random. */
 typedef int ( ak_function_random )( ak_random );
/*! \brief Функция обработки данных заданного размера. */
 typedef int ( ak_function_random_ptr_const )( ak_random , const ak_pointer, const ssize_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий произвольный генератор псевдо-случайных чисел. */
/* ----------------------------------------------------------------------------------------------- */
 struct random {
  /*! \brief OID генератора псевдо-случайных чисел. */
   ak_oid oid;
  /*! \brief Указатель на функцию выработки следующего внутреннего состояния */
   ak_function_random *next;
  /*! \brief Указатель на функцию инициализации генератора заданным массивом значений */
   ak_function_random_ptr_const *randomize_ptr;
  /*! \brief Указатель на функцию выработки последователности псевдо-случайных байт */
   ak_function_random_ptr_const *random;
  /*! \brief Указатель на функцию освобождения внутреннего состояния */
   ak_function_random *free;
  /*! \brief Объединение, определяющее внутренние данные генератора */
   union {
     /*! \brief Внутреннее состояние линейного конгруэнтного генератора */
       ak_uint64 val;
     /*! \brief Внутреннее состояние xorshift32 генератора */
       ak_uint32 value;
     /*! \brief Файловый дескриптор */
       int fd;
    #ifdef AK_HAVE_WINDOWS_H
     /*! \brief Дескриптор крипто-провайдера */
      HCRYPTPROV handle;
    #endif
     /*! \brief Указатель на произвольную структуру данных. */
       ak_pointer ctx;
   } data;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста линейного конгруэнтного генератора псевдо-случайных чисел. */
 dll_export int ak_random_create_lcg( ak_random );
 /*! \brief Инициализация контекста генератора, считывающего случайные значения из заданного файла. */
 dll_export int ak_random_create_file( ak_random , const char * );
#if defined(__unix__) || defined(__APPLE__)
/*! \brief Инициализация контекста генератора, считывающего случайные значения из /dev/random. */
 dll_export int ak_random_create_random( ak_random );
/*! \brief Инициализация контекста генератора, считывающего случайные значения из /dev/urandom. */
 dll_export int ak_random_create_urandom( ak_random );
#endif
#ifdef _WIN32
/*! \brief Инициализация контекста, реализующего интерфейс доступа к генератору псевдо-случайных чисел, предоставляемому ОС Windows. */
 dll_export int ak_random_create_winrtl( ak_random );
#endif
/*! \brief Инициализация контекста генератора по заданному OID алгоритма генерации псевдо-случайных чисел. */
 dll_export int ak_random_create_oid( ak_random, ak_oid );
/*! \brief Установка внутреннего состояния генератора псевдо-случайных чисел. */
 dll_export int ak_random_randomize( ak_random , const ak_pointer , const ssize_t );
/*! \brief Выработка псевдо-случайных данных. */
 dll_export int ak_random_ptr( ak_random , const ak_pointer , const ssize_t );
/*! \brief Некриптографическая функция генерации случайного 64-х битного целого числа. */
 dll_export ak_uint64 ak_random_value( void );
/*! \brief Уничтожение данных, хранящихся в полях структуры struct random. */
 int ak_random_destroy( ak_random );
/*! \brief Функция очистки памяти. */
 int ak_ptr_wipe( ak_pointer , size_t , ak_random );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-doc Секретные ключи криптографических механизмов
 @{ */
/*! \brief Указатель на структуру секретного ключа. */
 typedef struct skey *ak_skey;
/*! \brief Однопараметрическая функция для проведения действий с секретным ключом, возвращает код ошибки. */
 typedef int ( ak_function_skey )( ak_skey );
/*! \brief Однопараметрическая функция для проведения действий с секретным ключом, возвращает истину или ложь. */
 typedef bool_t ( ak_function_skey_check )( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перечисление, определяющее флаги хранения и обработки секретных ключей. */
 typedef ak_uint64 key_flags_t;

/* константные битовые маски, используемые как флаги */
/*! \brief Неопределенное значение */
 #define ak_key_flag_undefined          (0x0000000000000000ULL)

/*! \brief Младший (нулевой) бит отвечает за установку значения ключа:
             0 - ключ не установлен, 1 установлен. */
 #define ak_key_flag_set_key            (0x0000000000000001ULL)

/*! \brief Первый бит отвечает за установку маски:
             0 - маска не установлена, 1 - маска установлена. */
 #define ak_key_flag_set_mask           (0x0000000000000002ULL)

/*! \brief Второй бит отвечает за установку контрольной суммы ключа:
             0 - контрольная сумма не установлена не установлена, 1 - контрольная сумма установлена. */
 #define ak_key_flag_set_icode          (0x0000000000000004ULL)

/*! \brief Третий бит отвечает за то, кто из классов skey или его наследники уничтожают внутреннюю
 память. Если флаг установлен, то класс skey очистку не производит и возлагает это на методы
 классов-наследников: 0 - очистка производится, 1 - очистка памяти не производится */
 #define ak_key_flag_data_not_free      (0x0000000000000008ULL)

/*! \brief Флаг, который запрещает использование функции ctr без указания синхропосылки. */
 #define ak_key_flag_not_ctr            (0x0000000000000100ULL)

/*! \brief Флаг, который определяет, можно ли использовать значение внутреннего буффера в режиме omac. */
 #define ak_key_flag_omac_buffer_used   (0x0000000000000200ULL)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Способ выделения памяти для хранения секретной информации. */
 typedef enum {
  /*! \brief Механизм выделения памяти не определен. */
   undefined_policy,
  /*! \brief Выделение памяти через стандартный malloc */
   malloc_policy

} memory_allocation_policy_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип ключа шифрования контента. */
 typedef enum {
  /*! \brief Ключ шифрования контента, вырабатываемый из пароля пользователя */
   password_based_encryption_key,
} kek_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Место хранения зашифрованной информации. */
 typedef enum {
  /*! \brief Данные отсутствуют. */
   data_not_present_storage,
  /*! \brief Данные находятся в наличии. */
   data_present_storage,
  /*! \brief Данные находятся в заданном файле. */
   external_file_storage
} data_storage_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перечисление определяет возможные типы счетчиков ресурса секретного ключа. */
 typedef enum {
  /*! \brief Счетчик числа использованных блоков. */
    block_counter_resource,
  /*! \brief Счетчик числа использований ключа, например,
     количество подписанных сообщений или число производных ключей. */
    key_using_resource,
} counter_resource_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип и значение счетчика ресурса ключа. */
 typedef struct key_resource_counter {
  /*! \brief Тип ресурса */
    counter_resource_t type;
  /*! \brief Дополнение */
    ak_uint8 padding[4];
  /*! \brief Cчетчик числа использований, например, зашифрованных/расшифрованных блоков. */
    ssize_t counter;
} *ak_key_resoure_counter;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Временной интервал действия ключа. */
 typedef struct time_interval {
  /*! \brief Время, до которого ключ недействителен. */
   time_t not_before;
  /*! \brief Время, после которого ключ недействителен. */
   time_t not_after;
} *ak_time_intermal;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Ресурс ключа. */
 typedef struct resource {
  /*! \brief Счетчик числа использований ключа. */
   struct key_resource_counter value;
  /*! \brief Временной интервал использования ключа. */
   struct time_interval time;
 } *ak_resource;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Абстрактный секретный ключ, содержит базовый набор данных и методов контроля. */
 struct skey {
  /*! \brief ключ */
#ifdef AK_HAVE_STDALIGN_H
   alignas(32)
#endif
   ak_uint8 *key;
  /*! \brief размер ключа (в октетах) */
   size_t key_size;
  /*! \brief OID алгоритма для которого предназначен секретный ключ */
   ak_oid oid;
  /*! \brief уникальный номер ключа */
   ak_uint8 number[32];
  /*! \brief контрольная сумма ключа */
   ak_uint32 icode;
  /*! \brief генератор случайных масок ключа */
   struct random generator;
  /*! \brief ресурс использования ключа */
   struct resource resource;
  /*! \brief указатель на внутренние данные ключа */
   ak_pointer data;
  /*! \brief пользовательская метка ключа */
   char *label;
  /*! \brief Флаги текущего состояния ключа */
   key_flags_t flags;
  /*! \brief Способ выделения памяти. */
   memory_allocation_policy_t policy;
  /*! \brief указатель на функцию маскирования ключа */
   ak_function_skey *set_mask;
  /*! \brief указатель на функцию демаскирования ключа */
   ak_function_skey *unmask;
  /*! \brief указатель на функцию выработки контрольной суммы от значения ключа */
   ak_function_skey *set_icode;
  /*! \brief указатель на функцию проверки контрольной суммы от значения ключа */
   ak_function_skey_check *check_icode;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Генерация случайного уникального вектора, рассматриваемого как номер ключа. */
 dll_export int ak_libakrypt_generate_unique_number( ak_pointer , const size_t );
/*! \brief Получение человекочитаемого имени для типа ключевого ресурса. */
 dll_export const char *ak_libakrypt_get_counter_resource_name( const counter_resource_t );
/*! \brief Функция выделения памяти для ключевой информации. */
 dll_export int ak_skey_alloc_memory( ak_skey , size_t , memory_allocation_policy_t );
/*! \brief Функция освобождения выделенной ранее памяти. */
 dll_export int ak_skey_free_memory( ak_skey );
/*! \brief Инициализация структуры секретного ключа. */
 dll_export int ak_skey_create( ak_skey , size_t );
/*! \brief Очистка структуры секретного ключа. */
 dll_export int ak_skey_destroy( ak_skey );
/*! \brief Присвоение секретному ключу уникального номера. */
 dll_export int ak_skey_set_unique_number( ak_skey );
/*! \brief Присвоение секретному ключу заданного номера. */
 dll_export int ak_skey_set_number( ak_skey , ak_pointer , size_t );
/*! \brief Присвоение секретному ключу константного значения. */
 dll_export int ak_skey_set_key( ak_skey , const ak_pointer , const size_t );
/*! \brief Присвоение секретному ключу случайного значения. */
 dll_export int ak_skey_set_key_random( ak_skey , ak_random );
/*! \brief Присвоение секретному ключу значения, выработанного из пароля */
 dll_export int ak_skey_set_key_from_password( ak_skey , const ak_pointer , const size_t ,
                                                                 const ak_pointer , const size_t );
/*! \brief Наложение или смена маски путем сложения по модулю два
    случайной последовательности с ключом. */
 dll_export int ak_skey_set_mask_xor( ak_skey );
/*! \brief Снятие маски с ключа. */
 dll_export int ak_skey_unmask_xor( ak_skey );
/*! \brief Вычисление значения контрольной суммы ключа. */
 dll_export int ak_skey_set_icode_xor( ak_skey );
/*! \brief Проверка значения контрольной суммы ключа. */
 dll_export bool_t ak_skey_check_icode_xor( ak_skey );
/*! \brief Функция устанавливает ресурс ключа. */
 dll_export int ak_skey_set_resource( ak_skey , ak_resource );
/*! \brief Функция устанавливает временной интервал действия ключа. */
 dll_export int ak_skey_set_validity( ak_skey , time_t , time_t );
/*! \brief Функция устанавливает ресурс и временной итервал действия ключа. */
 dll_export int ak_skey_set_resource_values( ak_skey , counter_resource_t ,
                                                                  const char * , time_t , time_t );
/*! \brief Фукция присваивает пользовательскую метку ключу. */
 dll_export int ak_skey_set_label( ak_skey, const char * , const size_t );

#ifdef LIBAKRYPT_HAVE_DEBUG_FUNCTIONS
/*! \brief Функция выводит информацию о контексте секретного ключа в заданный файл. */
 int ak_skey_print_to_file( ak_skey , FILE *fp );
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на структуру ключа блочного алгоритма шифрования. */
 typedef struct bckey *ak_bckey;
/*! \brief Функция создания ключа блочного алгоритма шифрования. */
 typedef int ( ak_function_bckey_create ) ( ak_bckey );
/*! \brief Функция зашифрования/расширования одного блока информации. */
 typedef void ( ak_function_bckey )( ak_skey, ak_pointer, ak_pointer );
/*! \brief Функция, предназначенная для зашифрования/расшифрования области памяти заданного размера */
 typedef int ( ak_function_bckey_encrypt )( ak_bckey, ak_pointer, ak_pointer, size_t,
                                                                                ak_pointer, size_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ блочного алгоритма шифрования. */
 struct bckey {
  /*! \brief Указатель на секретный ключ. */
   struct skey key;
  /*! \brief Размер блока обрабатываемых данных (в байтах). */
   size_t bsize;
  /*! \brief Буффер, для хранения текущего значения синхропосылки.
      \details Максимальное количество блоков, помещающихся в буффер,
      равно 8 для Магмы и 4 для Кузнечика. */
   ak_uint8 ivector[64];
  /*! \brief Текущий размер вектора синхропосылки (в октетах) */
   size_t ivector_size;
  /*! \brief Функция заширования одного блока информации. */
   ak_function_bckey *encrypt;
  /*! \brief Функция расширования одного блока информации. */
   ak_function_bckey *decrypt;
  /*! \brief Функция развертки ключа. */
   ak_function_skey *schedule_keys;
  /*! \brief Функция уничтожения развернутых ключей. */
   ak_function_skey *delete_keys;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация секретного ключа алгоритма блочного шифрования Магма. */
 dll_export int ak_bckey_create_magma( ak_bckey );
/*! \brief Инициализация секретного ключа алгоритма блочного шифрования Кузнечик. */
 dll_export int ak_bckey_create_kuznechik( ak_bckey );
/*! \brief Инициализация секретного ключа алгоритма блочного шифрования по его OID. */
 dll_export int ak_bckey_create_oid( ak_bckey , ak_oid );
/*! \brief Очистка ключа алгоритма блочного шифрования. */
 dll_export int ak_bckey_destroy( ak_bckey );
/*! \brief Присвоение ключу алгоритма блочного шифрования константного значения. */
 dll_export int ak_bckey_set_key( ak_bckey, const ak_pointer , const size_t );
/*! \brief Присвоение ключу алгоритма блочного шифрования случайного значения. */
 dll_export int ak_bckey_set_key_random( ak_bckey , ak_random );
/*! \brief Присвоение ключу алгоритма блочного шифрования значения, выработанного из пароля. */
 dll_export int ak_bckey_set_key_from_password( ak_bckey ,
                                const ak_pointer , const size_t , const ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает пару ключей алгоритма блочного шифрования из заданного
   пользователем пароля. */
 int ak_bckey_create_key_pair_from_password( ak_bckey , ak_bckey , ak_oid ,
                            const char * , const size_t , ak_uint8 *, const size_t, const size_t );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup enc-doc Шифрование данных
 @{ */
/*! \brief Нелинейная перестановка для алгоритмов хеширования и блочного шифрования */
 typedef ak_uint8 sbox[256];
/*! \brief Набор таблиц замен для блочного шифра Магма. */
 typedef sbox magma[4];
/*! \brief Матрица линейного преобразования */
 typedef ak_uint8 linear_matrix[16][16];
/*! \brief Линейный регистр сдвига */
 typedef ak_uint8 linear_register[16];
/*! \brief Таблица, используемая для эффективной реализации алгоритма шифрования Кузнечик. */
 typedef ak_uint64 expanded_table[16][256][2];
/*! \brief Структура, содержащая параметры алгоритма блочного шифрования Кузнечик. */
 typedef struct kuznechik_params {
  /*! \brief Линейный регистр сдвига */
   linear_register reg;
  /*! \brief 16я степень сопровождающей матрицы линейного регистра сдвига */
   linear_matrix L;
  /*! \brief Нелинейная перестановка */
   sbox pi;
  /*! \brief Развернутые таблицы, используемые для эффективного зашифрования */
   expanded_table enc;
  /*! \brief Обратная матрица, к 16й степени сопровождающей матрицы линейного регистра сдвига. */
   linear_matrix Linv;
  /*! \brief Обратная нелинейная перестановка. */
   sbox pinv;
  /*! \brief Развернутые таблицы, используемые для эффективного расшифрования */
   expanded_table dec;
 } *ak_kuznechik_params;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Зашифрование данных в режиме простой замены (electronic codebook, ecb). */
 dll_export int ak_bckey_encrypt_ecb( ak_bckey , ak_pointer , ak_pointer , size_t );
/*! \brief Расшифрование данных в режиме простой замены (electronic codebook, ecb). */
 dll_export int ak_bckey_decrypt_ecb( ak_bckey , ak_pointer , ak_pointer , size_t );
 /*! \brief Зашифрование данных в режиме простой замены с зацеплением из ГОСТ Р 34.13-2015
    (cipher block chaining, cbc). */
 dll_export int ak_bckey_encrypt_cbc( ak_bckey , ak_pointer , ak_pointer , size_t ,
                                                                            ak_pointer , size_t );
 /*! \brief Расшифрование данных в режиме простой замены с зацеплением из ГОСТ Р 34.13-2015
    (cipher block chaining, cbc). */
 dll_export int ak_bckey_decrypt_cbc( ak_bckey , ak_pointer , ak_pointer , size_t ,
                                                                            ak_pointer , size_t );
/*! \brief Шифрование данных в режиме гаммирования из ГОСТ Р 34.13-2015
   (counter mode, ctr). */
 dll_export int ak_bckey_ctr( ak_bckey , ak_pointer , ak_pointer , size_t , ak_pointer , size_t );
/*! \brief Шифрование данных в режиме гаммирования с обратной связью по выходу
   (output feedback, ofb). */
 dll_export int ak_bckey_ofb( ak_bckey , ak_pointer , ak_pointer , size_t , ak_pointer , size_t );
/*! \brief Зашифрование данных в режиме гаммирования с обратной связью по шифртексту
   из ГОСТ Р 34.13-2015 (cipher feedback, cfb). */
 dll_export int ak_bckey_encrypt_cfb( ak_bckey , ak_pointer , ak_pointer , size_t ,
                                                                             ak_pointer , size_t );
/*! \brief Расшифрование данных в режиме гаммирования с обратной связью по шифртексту
   из ГОСТ Р 34.13-2015 (cipher feedback, cfb). */
 dll_export int ak_bckey_decrypt_cfb( ak_bckey , ak_pointer , ak_pointer , size_t ,
                                                                             ak_pointer , size_t );
/*! \brief Шифрование данных в режиме `CTR-ACPKM` из Р 1323565.1.017—2018. */
 dll_export int ak_bckey_ctr_acpkm( ak_bckey , ak_pointer , ak_pointer , size_t , size_t ,
                                                                             ak_pointer , size_t );
/*! \brief Зашифрование данных в режиме `XTS`. */
 dll_export int ak_bckey_encrypt_xts( ak_bckey ,  ak_bckey , ak_pointer , ak_pointer , size_t ,
                                                                             ak_pointer , size_t );
/*! \brief Расшифрование данных в режиме `XTS`. */
 dll_export int ak_bckey_decrypt_xts( ak_bckey ,  ak_bckey , ak_pointer , ak_pointer , size_t ,
                                                                             ak_pointer , size_t );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac-doc Вычисление кодов целостности (хеширование и имитозащита)
 @{ */ 
/*! \brief Вычисление имитовставки согласно ГОСТ Р 34.13-2015. */
 dll_export int ak_bckey_cmac( ak_bckey , ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Очистка внутреннего состояния секретного ключа. */
 dll_export int ak_bckey_cmac_clean( ak_bckey );
/*! \brief Обновление внутреннего состояния секретного ключа при вычислении имитовставки
    согласно ГОСТ Р 34.13-2015. */
 dll_export int ak_bckey_cmac_update( ak_bckey , const ak_pointer , const size_t );
/*! \brief Завершение вычисления имитовставки согласно ГОСТ Р 34.13-2015. */
 dll_export int ak_bckey_cmac_finalize( ak_bckey , const ak_pointer , const size_t ,
                                                                       ak_pointer , const size_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция очистки контекста хеширования. */
 typedef int ( ak_function_clean )( ak_pointer );
/*! \brief Однораундовая функция сжатия, применяемая к одному или нескольким входным блокам. */
 typedef int ( ak_function_update )( ak_pointer, const ak_pointer , const size_t );
/*! \brief Функция завершения вычислений и получения конечного результата. */
 typedef int ( ak_function_finalize )( ak_pointer,
                                     const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Функция создания контекста хеширования. */
 typedef int ( ak_function_hash_create )( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Максимальный размер блока входных данных в октетах (байтах). */
 #define ak_mac_max_buffer_size (64)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст алгоритма итерационного сжатия. */
/*! Класс предоставляет интерфейс для реализации процедруры сжатия данных фрагментами произвольной длины.
    Данная процедура может применяться в алгоритмах хеширования, выработки имитовставки и т.п.*/
/* ----------------------------------------------------------------------------------------------- */
 typedef struct mac {
  /*! \brief Размер входного блока данных (в октетах) */
   size_t bsize;
  /*! \brief Текущее количество данных во внутреннем буффере. */
   size_t length;
  /*! \brief Внутренний буффер для хранения входных данных. */
   ak_uint8 data[ ak_mac_max_buffer_size ];
  /*! \brief Указатель на контекст, содержащий внутреннее состояние алгоритма сжатия. */
   ak_pointer ctx;
  /*! \brief Функция очистки контекста ctx */
   ak_function_clean *clean;
  /*! \brief Функция обновления состояния контекста ctx  */
   ak_function_update *update;
  /*! \brief Функция завершения вычислений и получения конечного результата */
   ak_function_finalize *finalize;
 } *ak_mac;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных функций хеширования семейства Стрибог. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct streebog {
 /*! \brief Вектор h - временный */
  ak_uint64 h[8];
 /*! \brief Вектор n - временный */
  ak_uint64 n[8];
 /*! \brief Вектор  \f$ \Sigma \f$ - контрольная сумма */
  ak_uint64 sigma[8];
 /*! \brief Размер блока выходных данных (хеш-кода)*/
  size_t hsize;
} *ak_streebog;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст бесключевой функции хеширования. */
/*! \details Класс предоставляет интерфейс для реализации бесключевых функций хеширования, построенных
    с использованием итеративных сжимающих отображений. В настоящее время
    с использованием класса \ref hash реализованы следующие отечественные алгоритмы хеширования
     - Стрибог256,
     - Стрибог512.

  Перед началом работы контекст функции хэширования должен быть инициализирован
  вызовом одной из функций инициализации, например, функции ak_hash_create_streebog256()
  или функции ak_hash_create_streebog512().
  После завершения вычислений контекст должен быть освобожден с помощью функции
  ak_hash_destroy().                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct hash {
  /*! \brief OID алгоритма хеширования */
   ak_oid oid;
  /*! \brief Контекст итерационного сжатия. */
   struct mac mctx;
  /*! \brief Внутренние данные контекста */
   union {
   /*! \brief Структура алгоритмов семейства Стрибог. */
    struct streebog sctx;
   } data;
 } *ak_hash;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста функции бесключевого хеширования ГОСТ Р 34.11-2012 (Стрибог256). */
 dll_export int ak_hash_create_streebog256( ak_hash );
/*! \brief Инициализация контекста функции бесключевого хеширования ГОСТ Р 34.11-2012 (Стрибог512). */
 dll_export int ak_hash_create_streebog512( ak_hash );
/*! \brief Инициализация контекста функции бесключевого хеширования по заданному OID алгоритма. */
 dll_export int ak_hash_create_oid( ak_hash, ak_oid );
/*! \brief Уничтожение контекста функции хеширования. */
 dll_export int ak_hash_destroy( ak_hash );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает размер вырабатываемого хеш-кода (в октетах). */
 dll_export size_t ak_hash_get_tag_size( ak_hash );
/*! \brief Функция возвращает размер блока входных данных, обрабатываемого функцией хеширования (в октетах). */
 dll_export size_t ak_hash_get_block_size( ak_hash );
/*! \brief Очистка контекста алгоритма хеширования. */
 dll_export int ak_hash_clean( ak_hash );
/*! \brief Обновление состояния контекста хеширования. */
 dll_export int ak_hash_update( ak_hash , const ak_pointer , const size_t );
/*! \brief Обновление состояния и вычисление результата применения алгоритма хеширования. */
 dll_export int ak_hash_finalize( ak_hash , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Хеширование заданной области памяти. */
 dll_export int ak_hash_ptr( ak_hash , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Хеширование заданного файла. */
 dll_export int ak_hash_file( ak_hash , const char*, ak_pointer , const size_t );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-doc Cекретные ключи криптографических механизмов
 @{ */
/*! \brief Секретный ключ алгоритма выработки имитовставки HMAC. */
/*!  Алгоритм выработки имитовставки HMAC основан на двукратном применении бесключевой функции
     хеширования. Алгоритм описывается рекомендациями IETF RFC 2104 (см. также RFC 7836) и
     стандартизован отечественными рекомендациями по стандартизации Р 50.1.113-2016.
     Алгоритм предназначен, в основном, для выработки имитовставки и преобразования ключевой
     информации.

     В нашей реализации алгоритм может быть использован совместно с любой функцией хеширования,
     реализованной в библиотеке. Отметим, что согласно Р 50.1.113-2016 алгоритм рекомендуется
     использовать только совместно с функцией хеширования Стрибог
     (с длиной хеш кода как 256 бит, так и 512 бит).

     \note Использование ключей, чья длина превышает размер блока бесключевой функции
     хеширования, реализовано в соответствии с RFC 2104.                                           */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct hmac {
  /*! \brief Контекст секретного ключа */
   struct skey key;
  /*! \brief Контекст итерационного сжатия. */
   struct mac mctx;
  /*! \brief Контекст функции хеширования */
   struct hash ctx;
} *ak_hmac;

/*! \brief Создание секретного ключа алгоритма выработки имитовставки HMAC на основе функции Стрибог256. */
 dll_export int ak_hmac_create_streebog256( ak_hmac );
/*! \brief Создание секретного ключа алгоритма выработки имитовставки HMAC на основе функции Стрибог512. */
 dll_export int ak_hmac_create_streebog512( ak_hmac );
/*! \brief Создание секретного ключа алгоритма выработки имитовставки HMAC c помощью заданного oid. */
 dll_export int ak_hmac_create_oid( ak_hmac , ak_oid );
/*! \brief Уничтожение секретного ключа. */
 dll_export int ak_hmac_destroy( ak_hmac );
/*! \brief Присвоение секретному ключу константного значения. */
 dll_export int ak_hmac_set_key( ak_hmac , const ak_pointer , const size_t );
/*! \brief Присвоение секретному ключу случайного значения. */
 dll_export int ak_hmac_set_key_random( ak_hmac , ak_random );
/*! \brief Присвоение секретному ключу значения, выработанного из пароля */
 dll_export int ak_hmac_set_key_from_password( ak_hmac , const ak_pointer , const size_t ,
                                                                 const ak_pointer , const size_t );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac-doc Вычисление кодов целостности (хеширование и имитозащита)
 @{ */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает размер вырабатываемой имитовставки. */
 dll_export size_t ak_hmac_get_tag_size( ak_hmac );
/*! \brief Функция возвращает размер блока входных данных, обрабатываемого функцией выработки имитовставки. */
 dll_export size_t ak_hmac_get_block_size( ak_hmac );
/*! \brief Очистка контекста секретного ключа алгоритма выработки имитовставки HMAC, а также
    проверка ресурса ключа. */
 dll_export int ak_hmac_clean( ak_hmac );
/*! \brief Обновление текущего состояния контекста алгоритма выработки имитовставки HMAC. */
 dll_export int ak_hmac_update( ak_hmac , const ak_pointer , const size_t );
/*! \brief Завершение алгоритма выработки имитовставки HMAC. */
 dll_export int ak_hmac_finalize( ak_hmac , const ak_pointer , const size_t ,
                                                                       ak_pointer , const size_t );
/*! \brief Вычисление имитовставки для заданной области памяти. */
 dll_export int ak_hmac_ptr( ak_hmac , const ak_pointer , const size_t ,
                                                                       ak_pointer , const size_t );
/*! \brief Вычисление имитовставки для заданного файла. */
 dll_export int ak_hmac_file( ak_hmac , const char* , ak_pointer , const size_t );
/*! \brief Развертка ключевого вектора из пароля (согласно Р 50.1.111-2016, раздел 4) */
 dll_export int ak_hmac_pbkdf2_streebog512( const ak_pointer , const size_t ,
                   const ak_pointer , const size_t, const size_t , const size_t , ak_pointer );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup aead-doc Аутентифицированное шифрование данных
 @{ */
/*! \brief Функция аутентифицированного шифрования. */
 typedef int ( ak_function_aead )( ak_pointer, ak_pointer, const ak_pointer , const size_t ,
                   const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                         ak_pointer , const size_t );

/*! \brief Зашифрование данных в режиме `mgm` с одновременной выработкой имитовставки
    согласно Р 1323565.1.026-2019. */
 dll_export int ak_bckey_encrypt_mgm( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                         ak_pointer , const size_t );
/*! \brief Расшифрование данных в режиме `mgm` с одновременной проверкой имитовставки
    согласно Р 1323565.1.026-2019. */
 dll_export int ak_bckey_decrypt_mgm( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                          ak_pointer, const size_t );
/*! \brief Зашифрование данных в режиме `xtsmac` с одновременной выработкой имитовставки. */
 dll_export int ak_bckey_encrypt_xtsmac( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                         ak_pointer , const size_t );
/*! \brief Расшифрование данных в режиме `xtsmac` с одновременной проверкой имитовставки. */
 dll_export int ak_bckey_decrypt_xtsmac( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                          ak_pointer, const size_t );

/*! \brief Зашифрование данных с одновременной выработкой имитовставки согласно ГОСТ Р 34.13-2015. */
 dll_export int ak_bckey_encrypt_ctr_cmac( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                         ak_pointer , const size_t );
/*! \brief Расшифрование данных с одновременной проверкой имитовставки согласно ГОСТ Р 34.13-2015. */
 dll_export int ak_bckey_decrypt_ctr_cmac( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                          ak_pointer, const size_t );
/*! \brief Зашифрование данных в режиме гаммирования с одновременной выработкой имитовставки
   согласно Р 50.1.113-2016. */
 dll_export int ak_bckey_encrypt_ctr_hmac( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                         ak_pointer , const size_t );
/*! \brief Расшифрование данных в режиме гаммирования с одновременной проверкой имитовставки
   согласно Р 50.1.113-2016. */
 dll_export int ak_bckey_decrypt_ctr_hmac( ak_pointer , ak_pointer , const ak_pointer ,
    const size_t , const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                          ak_pointer, const size_t );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup math-doc Математические функции
 @{ */
/** \addtogroup mpzn-doc Арифметика больших чисел
 @{ */
#ifdef LIBAKRYPT_HAVE_GMP_H
 #include <gmp.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define ak_mpzn128_size     (2)
 #define ak_mpzn256_size     (4)
 #define ak_mpzn512_size     (8)
 #define ak_mpznmax_size    (18)

 #define ak_mpzn128_zero  { 0, 0 }
 #define ak_mpzn128_one   { 1, 0 }
 #define ak_mpzn256_zero  { 0, 0, 0, 0 }
 #define ak_mpzn256_one   { 1, 0, 0, 0 }
 #define ak_mpzn512_zero  { 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpzn512_one   { 1, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_zero  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_one   { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Элемент кольца вычетов по модулю \f$2^{128}\f$. */
 typedef ak_uint64 ak_mpzn128[ ak_mpzn128_size ];
/*! \brief Элемент кольца вычетов по модулю \f$2^{256}\f$. */
 typedef ak_uint64 ak_mpzn256[ ak_mpzn256_size ];
/*! \brief Элемент кольца вычетов по модулю \f$2^{512}\f$. */
 typedef ak_uint64 ak_mpzn512[ ak_mpzn512_size ];
/*! \brief Тип данных для хранения максимально возможного большого числа. */
 typedef ak_uint64 ak_mpznmax[ ak_mpznmax_size ];

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Присвоение вычету другого вычета. */
 dll_export void ak_mpzn_set( ak_uint64 *, ak_uint64 * , const size_t );
/*! \brief Присвоение вычету беззнакового целого значения. */
 dll_export void ak_mpzn_set_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Присвоение вычету случайного значения. */
 dll_export int ak_mpzn_set_random( ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету случайного значения по фиксированному модулю. */
 dll_export int ak_mpzn_set_random_modulo( ak_uint64 *, ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету значения, записанного строкой шестнадцатеричных символов. */
 dll_export int ak_mpzn_set_hexstr( ak_uint64 *, const size_t , const char * );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов. */
 dll_export const char *ak_mpzn_to_hexstr( const ak_uint64 *, const size_t );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов с выделением памяти. */
 dll_export char *ak_mpzn_to_hexstr_alloc( ak_uint64 *, const size_t );
/*! \brief Сериализация вычета в последовательность октетов. */
 dll_export int ak_mpzn_to_little_endian( ak_uint64 * , const size_t ,
                                                             ak_pointer , const size_t , bool_t );
/*! \brief Присвоение вычету сериализованного значения. */
 dll_export int ak_mpzn_set_little_endian( ak_uint64 * , const size_t ,
                                                       const ak_pointer , const size_t , bool_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов */
 dll_export ak_uint64 ak_mpzn_add( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычитание двух вычетов */
 dll_export ak_uint64 ak_mpzn_sub( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение двух вычетов */
 dll_export int ak_mpzn_cmp( ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение вычета с беззнаковым целым числом (типа ak_uint64) */
 dll_export bool_t ak_mpzn_cmp_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Умножение вычета на беззнаковое целое */
 dll_export ak_uint64 ak_mpzn_mul_ui( ak_uint64 *, ak_uint64 *, const size_t, const ak_uint64 );
/*! \brief Умножение двух вычетов как целых чисел */
 dll_export void ak_mpzn_mul( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычисление остатка от деления одного вычета на другой */
 dll_export void ak_mpzn_rem( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычисление остатка от деления вычета на одноразрядное число */
 dll_export ak_uint32 ak_mpzn_rem_uint32( ak_uint64 *, const size_t , ak_uint32 );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов в представлении Монтгомери. */
 dll_export void ak_mpzn_add_montgomery( ak_uint64 *, ak_uint64 *,
                                                         ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Удвоение на двойку в представлении Монтгомери. */
 dll_export void ak_mpzn_lshift_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Умножение двух вычетов в представлении Монтгомери. */
 dll_export void ak_mpzn_mul_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                           ak_uint64 *, ak_uint64, const size_t );
/*! \brief Модульное возведение в степень в представлении Монтгомери. */
 dll_export void ak_mpzn_modpow_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                           ak_uint64 *, ak_uint64, const size_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка на равенство двух 128-битных чисел. */
 dll_export int ak_128_equal( const ak_uint64 *x, const ak_uint64 *y );
/*! \brief Сравнение 128-битного числа с нулем. */
 dll_export int ak_128_is_zero( const ak_uint64 *x );
/*! \brief Сравнение 128-битного числа с единицей. */
 dll_export int ak_128_is_one( const ak_uint64 *x );
/*! \brief Присвоение нуля 128-битному числу. */
 dll_export void ak_128_set_zero( ak_uint64 *x );
/*! \brief Присвоение единицы 128-битному числу. */
 dll_export void ak_128_set_one( ak_uint64 *x );
/*! \brief Сложение двух 128-битных чисел с возвратом знака переноса. */
 dll_export ak_uint64 ak_128_add( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y );
/*! \brief Сложение двух 128-битных вычетов по заданному 128-битному модулю. */
 dll_export void ak_128_add_mod( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y, const ak_uint64 *p );
/*! \brief Вычитание двух 128-битных чисел с возвратом знака переноса. */
 dll_export ak_uint64 ak_128_sub( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y );
/*! \brief Вычитание двух 128-битных вычетов по заданному 128-битному модулю. */
 dll_export void ak_128_sub_mod( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y, const ak_uint64 *p );
/*! \brief Умножение двух 128-битных чисел. */
 dll_export void ak_128_mul( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y );
/*! \brief Умножение двух 128-битных вычетов по заданному 128-битному модулю. */
 dll_export void ak_128_mul_mod( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y, const ak_uint64 *p );
/*! \brief Получение остатка от деления 256-битного числа на заданный 128-битный модуль. */
 dll_export void ak_128_rem( ak_uint64 *r, const ak_uint64 *u, const ak_uint64 *p );
/*! \brief Получение частного и остатка от деления 256-битного числа на заданный 128-битный модуль. */
 dll_export ak_uint64 ak_128_div( ak_uint64 *q, ak_uint64 *r, const ak_uint64 *u, const ak_uint64 *p );
/*! \brief Получение обратного вычета по заданному 128-битному модулю. */
 dll_export void ak_128_inverse( ak_uint64 *o, const ak_uint64 *x, const ak_uint64 *p );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, предназначенный для хранения данных, необходимых для операций Монтгомери */
/* ----------------------------------------------------------------------------------------------- */
 struct ak_montgomery_context_128
{
/*! \brief Модуль, по которому производятся вычисления */
 ak_uint64 p[ak_mpzn128_size];
/*! \brief Значение 2^128 по модулю p */
 ak_uint64 r[ak_mpzn128_size];
/*! \brief Значение 2^256 по модулю p */
 ak_uint64 r2[ak_mpzn128_size];
/*! \brief Число, удовлетворяющее соотношению ru − pv = 1, где r = 2^128 */
 ak_uint64 v[ak_mpzn128_size];
};
 typedef struct ak_montgomery_context_128 ak_montgomery_context_128;

/*! \brief Инициализация данных, необходимых для операций Монтгомери. */
 dll_export void ak_128_montgomery_init( ak_montgomery_context_128 *ctx );
/*! \brief Сложение двух вычетов в представлении Монтгомери. */
 dll_export void ak_128_montgomery_add( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y, const ak_montgomery_context_128 *ctx );
/*! \brief Умножение двух вычетов в представлении Монтгомери. */
 dll_export void ak_128_montgomery_mul( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *y, const ak_montgomery_context_128 *ctx );
/*! \brief Поиск вычета, обратного данному в представлении Монтгомери. */
 dll_export void ak_128_montgomery_inverse( ak_uint64 *z, const ak_uint64 *x, const ak_montgomery_context_128 *ctx );
/*! \brief Возведение одного вычета в степень другого в представлении Монтгомери. */
 dll_export void ak_128_montgomery_modpow( ak_uint64 *z, const ak_uint64 *x, const ak_uint64 *k, const ak_montgomery_context_128 *ctx );
/*! \brief Приведение вычета из прямого представления к форме Монтгомери. */
 dll_export void ak_128_to_montgomery( ak_uint64 *z, const ak_uint64 *x, const ak_montgomery_context_128 *ctx );
/*! \brief Приведение вычета из формы Монтгомери к прямому представлению */
 dll_export void ak_128_from_montgomery( ak_uint64 *z, const ak_uint64 *x, const ak_montgomery_context_128 *ctx );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий точку эллиптической кривой с 128-битными афинными координатами. */
/* ----------------------------------------------------------------------------------------------- */
 struct point128
{
/*! \brief x-координата точки эллиптической кривой */
 ak_uint64 x[ak_mpzn128_size];
/*! \brief y-координата точки эллиптической кривой */
 ak_uint64 y[ak_mpzn128_size];
};
 typedef struct point128 *ak_point128;


/*! \brief Сложение двух точек на эллиптической кривой по заданному 128-битному модулю. */
 dll_export void ak_128_point_add( ak_point128 c, const ak_point128 a, const ak_point128 b, const ak_uint64 *p );

#ifdef AK_HAVE_GMP_H
/*! \brief Преобразование ak_mpznxxx в mpz_t. */
 dll_export void ak_mpzn_to_mpz( const ak_uint64 *, const size_t , mpz_t );
/*! \brief Преобразование mpz_t в ak_mpznxxx. */
 dll_export void ak_mpz_to_mpzn( const mpz_t , ak_uint64 *, const size_t );
#endif
/** @} */
/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup curves-doc Эллиптические кривые
 @{ */
 struct wcurve;
/*! \brief Контекст эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 typedef struct wcurve *ak_wcurve;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий точку эллиптической кривой.

    Класс представляет собой точку \f$ P \f$ эллиптической кривой, заданной в короткой форме Вейерштрасса,
    в проективных координатах, т.е. точка представляется в виде вектора \f$ P=(x:y:z) \f$,
    удовлетворяющего сравнению \f$ y^2z \equiv x^3 + axz^2 + bz^3 \pmod{p} \f$.
    В дальнейшем, при проведении вычислений, для координат точки используется
    представление Монтгомери.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 struct wpoint
{
/*! \brief x-координата точки эллиптической кривой */
 ak_uint64 x[ak_mpzn512_size];
/*! \brief y-координата точки эллиптической кривой */
 ak_uint64 y[ak_mpzn512_size];
/*! \brief z-координата точки эллиптической кривой */
 ak_uint64 z[ak_mpzn512_size];
};
/*! \brief Контекст точки эллиптической кривой в короткой форме Вейерштрасса */
 typedef struct wpoint *ak_wpoint;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация и присвоение контексту значения образующей точки эллиптической кривой. */
 dll_export int ak_wpoint_set( ak_wpoint, ak_wcurve );
/*! \brief Инициализация и присвоение контексту значения бесконечно удаленной точки эллиптической кривой. */
 dll_export int ak_wpoint_set_as_unit( ak_wpoint , ak_wcurve );
/*! \brief Инициализация и присвоение контексту значения заданной точки эллиптической кривой. */
 dll_export int ak_wpoint_set_wpoint( ak_wpoint , ak_wpoint , ak_wcurve );

/*! \brief Проверка принадлежности точки заданной кривой. */
 dll_export bool_t ak_wpoint_is_ok( ak_wpoint , ak_wcurve );
/*! \brief Проверка порядка заданной точки. */
 dll_export bool_t ak_wpoint_check_order( ak_wpoint , ak_wcurve );

/*! \brief Удвоение точки эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 dll_export void ak_wpoint_double( ak_wpoint , ak_wcurve );
/*! \brief Прибавление к одной точке эллиптической кривой значения другой точки. */
 dll_export void ak_wpoint_add( ak_wpoint , ak_wpoint , ak_wcurve );
/*! \brief Приведение проективной точки к аффинному виду. */
 dll_export void ak_wpoint_reduce( ak_wpoint , ak_wcurve );
/*! \brief Вычисление кратной точки эллиптической кривой. */
 dll_export void ak_wpoint_pow( ak_wpoint , ak_wpoint , ak_uint64 *, size_t , ak_wcurve );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий эллиптическую кривую, заданную в короткой форме Вейерштрасса

    Класс определяет эллиптическую кривую, заданную сравнением
    \f$ y^2 \equiv x^3 + ax + b \pmod{p} \f$, а также образующую точку \f$P=(x_P, y_P)\f$
    на этой кривой с заданным порядком \f$ q \f$.

    Порядок \f$ m \f$ всей группы точек эллиптической кривой может быть определен
    из равенства \f$ m = dq \f$, где величину \f$ d \f$ называют кофактором.

    Параметры \f$ n, n_q, r_2\f$ вводятся для оптимизации вычислений. Определим \f$ r = 2^{256}\f$
    или \f$ r=2^{512}\f$, тогда \f$ n \equiv n_0 \pmod{2^{64}}\f$,
    где \f$ n_0 \equiv -p^{-1} \pmod{r}\f$.

    Величина \f$ r_2 \f$ удовлетворяет сравнению \f$ r_2 \equiv r^2 \pmod{p}\f$.                   */
/* ----------------------------------------------------------------------------------------------- */
 struct wcurve
{
 /*! \brief Размер параметров эллиптической кривой, исчисляемый количеством 64-х битных блоков. */
  ak_uint32 size;
 /*! \brief Кофактор эллиптической кривой - делитель порядка группы точек. */
  ak_uint32 cofactor;
 /*! \brief Коэффициент \f$ a \f$ эллиптической кривой (в представлении Монтгомери) */
  ak_uint64 a[ak_mpzn512_size];
 /*! \brief Коэффициент \f$ b \f$ эллиптической кривой (в представлении Монтгомери). */
  ak_uint64 b[ak_mpzn512_size];
 /*! \brief Модуль \f$ p \f$ эллиптической кривой. */
  ak_uint64 p[ak_mpzn512_size];
 /*! \brief Величина \f$ r^2\f$, взятая по модулю \f$ p \f$ и используемая в арифметике Монтгомери. */
  ak_uint64 r2[ak_mpzn512_size];
 /*! \brief Порядок \f$ q \f$ подгруппы, порождаемой образующей точкой \f$ P \f$. */
  ak_uint64 q[ak_mpzn512_size];
 /*! \brief Величина \f$ r^2\f$, взятая по модулю \f$ q \f$ и используемая в арифметике Монтгомери. */
  ak_uint64 r2q[ak_mpzn512_size];
 /*! \brief Точка \f$ P \f$ эллиптической кривой, порождающая подгруппу порядка \f$ q \f$. */
  struct wpoint point;
 /*! \brief Константа \f$ n \f$, используемая в арифметике Монтгомери по модулю \f$ p \f$. */
  ak_uint64 n;
 /*! \brief Константа \f$ n_q \f$, используемая в арифметике Монтгомери по модулю \f$ q\f$. */
  ak_uint64 nq;
 /*! \brief Строка, содержащая символьную запись модуля \f$ p \f$.
     \details Используется для проверки корректного хранения параметров кривой в памяти. */
  const char *pchar;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление дискриминанта эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 dll_export void ak_mpzn_set_wcurve_discriminant( ak_uint64 *, ak_wcurve );
/*! \brief Проверка корректности дискриминанта эллиптической кривой, заданной в форме Вейерштрасса. */
 dll_export int ak_wcurve_discriminant_is_ok( ak_wcurve );
/*! \brief Проверка корректности параметров, необходимых для вычисления по модулю q. */
 dll_export int ak_wcurve_check_order_parameters( ak_wcurve );
/*! \brief Проверка набора параметров эллиптической кривой, заданной в форме Вейерштрасса. */
 dll_export int ak_wcurve_is_ok( ak_wcurve );

/* ----------------------------------------------------------------------------------------------- */
/*                         параметры 256-ти битных эллиптических кривых                            */
/* ----------------------------------------------------------------------------------------------- */
 extern const struct wcurve id_tc26_gost_3410_2012_256_paramSetTest;
 extern const struct wcurve id_tc26_gost_3410_2012_256_paramSetA;
 extern const struct wcurve id_rfc4357_gost_3410_2001_paramSetA;
 extern const struct wcurve id_rfc4357_gost_3410_2001_paramSetB;
 extern const struct wcurve id_rfc4357_gost_3410_2001_paramSetC;

/*! \brief Параметры кривой A из RFC 4357, включенные в состав рекомендаций Р 1323565.0.024-2019 */
 #define id_tc26_gost_3410_2012_256_paramSetB ( id_rfc4357_gost_3410_2001_paramSetA )
/*! \brief Параметры кривой B из RFC 4357, включенные в состав рекомендаций Р 1323565.0.024-2019 */
 #define id_tc26_gost_3410_2012_256_paramSetC ( id_rfc4357_gost_3410_2001_paramSetB )
/*! \brief Параметры кривой C из RFC 4357, включенные в состав рекомендаций Р 1323565.0.024-2019 */
 #define id_tc26_gost_3410_2012_256_paramSetD ( id_rfc4357_gost_3410_2001_paramSetC )

 extern const struct wcurve id_axel_gost_3410_2012_256_paramSet_N0;

/* ----------------------------------------------------------------------------------------------- */
/*                         параметры 512-ти битных эллиптических кривых                            */
/* ----------------------------------------------------------------------------------------------- */
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetTest;
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetA;
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetB;
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetC;
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup gf2n-doc Конечные поля характеристики два
 @{ */
/*! \brief Умножение элемента поля на примитивный элемент.
    \details Макрос реализует умножение произвольного элемента поля \f$ \mathbb F_{2^{128}} \f$ на
    примитивный элемент поля. `s1` задает старшие 64 бита элемента, `s0` - младшие 64 бита.
    Степень расширения поля равняется 128, а многочлен,
    порождающий поле равен \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$.           */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_gf128_mul_theta(s1,s0) {\
   ak_uint64 n = s1&0x8000000000000000LL;\
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;\
   if( n ) s0 ^= 0x87;\
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$. */
 dll_export void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$. */
 dll_export void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{256}}\f$. */
 dll_export void ak_gf256_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{512}}\f$. */
 dll_export void ak_gf512_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$. */
 dll_export void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$. */
 dll_export void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{256}}\f$. */
 dll_export void ak_gf256_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{512}}\f$. */
 dll_export void ak_gf512_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );

 #define ak_gf64_mul ak_gf64_mul_pcmulqdq
 #define ak_gf128_mul ak_gf128_mul_pcmulqdq
 #define ak_gf256_mul ak_gf256_mul_pcmulqdq
 #define ak_gf512_mul ak_gf512_mul_pcmulqdq
#else

 #define ak_gf64_mul ak_gf64_mul_uint64
 #define ak_gf128_mul ak_gf128_mul_uint64
 #define ak_gf256_mul ak_gf256_mul_uint64
 #define ak_gf512_mul ak_gf512_mul_uint64
#endif

/* Размеры конечных полей (в октетах) */
 #define ak_galois64_size               (8)
 #define ak_galois128_size             (16)
 #define ak_galois256_size             (32)
 #define ak_galois512_size             (64)
/** @} *//** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup asn1-doc Функции кодирования и декодирования ASN.1 нотации
 @{ */
/* Флаги, определяющие класс данных ASN.1. */
 #define UNIVERSAL           0x00u
 #define APPLICATION         0x40u
 #define CONTEXT_SPECIFIC    0x80u
 #define PRIVATE             0xC0u

/* ----------------------------------------------------------------------------------------------- */
/* Флаг, определяющий структуру блока данных ASN.1. */
 #define PRIMITIVE           0x00u
 #define CONSTRUCTED         0x20u

/* ----------------------------------------------------------------------------------------------- */
/* Номера стандартных тегов ASN.1. */
 #define TEOC                0x00u
 #define TBOOLEAN            0x01u
 #define TINTEGER            0x02u
 #define TBIT_STRING         0x03u
 #define TOCTET_STRING       0x04u
 #define TNULL               0x05u
 #define TOBJECT_IDENTIFIER  0x06u
 #define TOBJECT_DESCRIPTOR  0x07u
 #define TEXTERNAL           0x08u
 #define TREAL               0x09u
 #define TENUMERATED         0x0Au
 #define TUTF8_STRING        0x0Cu
 #define TSEQUENCE           0x10u
 #define TSET                0x11u
 #define TNUMERIC_STRING     0x12u
 #define TPRINTABLE_STRING   0x13u
 #define TT61_STRING         0x14u
 #define TVIDEOTEX_STRING    0x15u
 #define TIA5_STRING         0x16u
 #define TUTCTIME            0x17u
 #define TGENERALIZED_TIME   0x18u
 #define TGRAPHIC_STRING     0x19u
 #define TVISIBLE_STRING     0x1Au
 #define TGENERAL_STRING     0x1Bu
 #define TUNIVERSAL_STRING   0x1Cu
 #define TCHARACTER_STRING   0x1Du
 #define TBMP_STRING         0x1Eu

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Биты, определяющие класс данных */
 #define DATA_CLASS(x)     ((x) & 0xC0)
/*! \brief Бит, определяющий структуру данных */
 #define DATA_STRUCTURE(x) ((x) & 0x20)
/*! \brief Биты, определяющие номер тега */
 #define TAG_NUMBER(x)     ((x) & 0x1F)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Длина тега (текущая реализация поддерживает кодирование
 *         и декодирование тегов, представленных одним байтом) */
 #define TAG_LEN 1

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на примитивный элемент дерева ASN1 нотации */
 typedef struct tlv *ak_tlv;
/*! \brief Указатель на один уровень дерева ASN1 нотации */
 typedef struct asn1 *ak_asn1;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий один уровень дерева ASN1 нотации.
    \details Фактически, класс asn1 является двусвязным списком узлов, расположенных на одном
    уровне ASN1 дерева. Каждый узел, реализуемый при помощи структуры \ref tlv,
    представляет собой примитивный элемент, либо низлежащий уровень -- двусвязный список,
    также реализуемый при помощи класса asn1.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct asn1 {
   /*! \brief указатель на текущий узел списка */
    ak_tlv current;
   /*! \brief количество содержащихся узлов в списке (одного уровня) */
    size_t count;
 } *ak_asn1;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, определяющая элемент дерева ASN1 нотации
    \details ASN1 дерево представляется в памяти двусвязным списком узлов (tlv структур), образующих
    один уровень. При этом, каждый узел может быть:
     - примитивным, содержащим данные, для которых определены стандартные процедуры кодирования и
       декодирования,
     - составным, представляющим собой двусвязный список узлов следующего уровня;
       составные узлы позволяют образовывать произвольные типы данных, отличные от примитивных;
       процедуры кодирования/декодирования составных узлов сводятся к последовательному применению
       процедур для примитивных типов.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 struct tlv
{
 /*! \brief объединение, определяющее способ представления данных (примитивный или составной элемент),
     а также сами данные. */
  union {
   /*! \brief указатель на примитивные, закодированые по правилам ASN.1 данные */
    ak_uint8* primitive;
   /*! \brief указатель на составные данные, представляющие собой двусвязный список следующего уровня */
    ak_asn1 constructed;
  } data;
 /*! \brief тег, идентифицирующий данные. */
  ak_uint8 tag;
 /*! \brief длинна данных. */
  ak_uint32 len;
 /*! \brief флаг, определяющий, должен ли объект освобождать память из под данных, которыми управляет */
  bool_t free;

 /*! \brief указатель на предыдущий элемент списка. */
  ak_tlv prev;
 /*! \brief указатель на следующий элемент списка. */
  ak_tlv next;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, используемая для передачи информации о битовых строках. */
 typedef struct bit_string {
  /*! \brief массив, содержащий данные (в шестнадцатеричном виде) */
   ak_uint8 *value;
  /*! \brief размер массива с данными (в октетах) */
   ak_uint32 len;
  /*! \brief кол-во неиспользуемых битов в последнем байте
     (допустимые значения: от 0 до 7 включительно). */
   ak_uint8 unused;
 } *ak_bit_string;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Формат хранения asn1 дерева в файле */
 typedef enum {
  /*! \brief хранение asn1 дерева в виде der-последовательности. */
   asn1_der_format,
  /*! \brief хранение asn1 дерева в виде der-последовательнсти, закодированной в base64. */
   asn1_pem_format,
} export_format_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип контента, помещаемого в контейнер. */
 typedef enum {
  /*! \brief Не заданный или не определенный контент. */
   undefined_content = 0x0,
  /*! \brief Секретный ключ симметричного криптографического алгоритма. */
   symmetric_key_content = 0x1,
  /*! \brief Секретный ключ асимметричного криптографического алгоритма. */
   secret_key_content = 0x2,
  /*! \brief Открытый ключ асимметричного криптографического алгоритма. */
   public_key_certificate_content = 0x3,
  /*! \brief Запрос на получение открытого ключа асимметричного криптографического алгоритма. */
   public_key_request_content = 0x4,
  /*! \brief Зашифрованные, не ключевые данные. */
   encrypted_content = 0x5,
  /*! \brief Незашифрованные, не ключевые данные. */
   plain_content = 0x06
} crypto_content_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение количества байт, необходимых для кодирования длины элемента ASN1 дерева. */
 dll_export size_t ak_asn1_get_length_size( const size_t );
/*! \brief Определение количества байт, необходимых для кодирования идентификатора объекта. */
 dll_export size_t ak_asn1_get_length_oid( const char * );
/*! \brief Получение символьного (человекочитаемого) описания типа примитивного элемента ASN1 дерева. */
 dll_export const char* ak_asn1_get_tag_description( ak_uint8 );
/*! \brief Получение из DER-последовательности тега для текущего узла ASN1 дерева. */
 dll_export int ak_asn1_get_tag_from_der( ak_uint8** , ak_uint8 * );
/*! \brief Получение из DER-последовательности длины текущего узла ASN1 дерева. */
 dll_export int ak_asn1_get_length_from_der( ak_uint8** , size_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание примитивного узла ASN1 дерева. */
 dll_export int ak_tlv_create_primitive( ak_tlv , ak_uint8 , size_t , ak_pointer , bool_t );
/*! \brief Создание примитивного узла ASN1 дерева. */
 dll_export ak_tlv ak_tlv_new_primitive( ak_uint8 , size_t , ak_pointer , bool_t );
/*! \brief Создание составного узла ASN1 дерева. */
 dll_export int ak_tlv_create_constructed( ak_tlv , ak_uint8 , ak_asn1 );
/*! \brief Создание составного узла ASN1 дерева. */
 dll_export ak_tlv ak_tlv_new_constructed( ak_uint8 , ak_asn1 );
/*! \brief Создание составного узла ASN1 дерева, содержащего пустую последовательность */
 dll_export ak_tlv ak_tlv_new_sequence( void );
/*! \brief Уничтожение примитивного узла ASN1 дерева. */
 dll_export int ak_tlv_destroy( ak_tlv );
/*! \brief Уничтожение примитивного узла ASN1 дерева и освобождение памяти. */
 dll_export ak_pointer ak_tlv_delete( ak_pointer );
/*! \brief Вывод информации о заданном узле ASN1 дерева. */
 dll_export int ak_tlv_print( ak_tlv , FILE * );
/*! \brief Вывод информации о примитивном узле ASN1 дерева. */
 dll_export int ak_tlv_print_primitive( ak_tlv, FILE * );
/*! \brief Функция вычисляет размер, занимаемый данным уровнем ASN.1 дерева */
 dll_export int ak_tlv_evaluate_length( ak_tlv , size_t * );
/*! \brief Кодирование одного узла ASN1 дерева в DER-последовательность октетов. */
 dll_export int ak_tlv_encode( ak_tlv , ak_pointer , size_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение булевого значения, хранящегося в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_bool( ak_tlv , bool_t * );
/*! \brief Получение беззнакового, 32-х битного значения, хранящегося в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_uint32( ak_tlv , ak_uint32 * );
/*! \brief Получение указателя на последовательность октетов, хранящуюся в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_octet_string( ak_tlv , ak_pointer *, size_t * );
/*! \brief Получение указателя на utf8 последовательность символов, хранящуюся в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_utf8_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на ia5 строку, хранящуюся в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_ia5_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на строку, содержащую только символы английского алфавита (см. стандарт ITU-T X.690 ). */
 dll_export int ak_tlv_get_printable_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на строку, содержащую только арабские цифры и пробел. */
 dll_export int ak_tlv_get_numeric_string( ak_tlv , ak_pointer * );
/*! \brief Получение указателя на битовую строку. */
 dll_export int ak_tlv_get_bit_string( ak_tlv , ak_bit_string );
/*! \brief Получение указателя на символьную запись идентификатора объекта (OID),
    хранящуюся в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_oid( ak_tlv , ak_pointer * );
/*! \brief Получение универсального времни, хранящегося в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_utc_time( ak_tlv , time_t * );
/*! \brief Получение указателя на строку, содержащую значение локального времени (UTC),
    хранящегося в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_utc_time_string( ak_tlv , ak_pointer * );
/*! \brief Получение времни, хранящегося в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_generalized_time( ak_tlv , time_t * );
/*! \brief Получение указателя на строку, содержащую значение локального времени (GeneralizedTime),
    хранящегося в заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_generalized_time_string( ak_tlv , ak_pointer * );
/*! \brief Получение временного интервала в структуру данных TimeValidity, хранящуюся в
   заданном узле ASN1 дерева. */
 dll_export int ak_tlv_get_validity( ak_tlv , time_t * , time_t * );
/*! \brief Получение структуры, содержащей ресурс (структуру struct resource). */
 dll_export int ak_tlv_get_resource( ak_tlv , ak_resource );
/*! \brief Получение идентификаторов криптографического алгоритма. */
 dll_export int ak_tlv_get_algorithm_identifier( ak_tlv, ak_oid * , ak_oid * );
/*! \brief Добавление типизированной строки в последовательность обобщенных имен,
    которой владеет текущий узел. */
 dll_export int ak_tlv_add_string_to_global_name( ak_tlv , const char * , const char * );
/*! \brief Функция создает новую последовательность обобщенных имен и копирует в нее типизированные
    строки из заданной последовательности. */
 dll_export ak_tlv ak_tlv_duplicate_global_name( ak_tlv );
/*! \brief Функция сравнивает две последовательности обобщенных имен. */
 dll_export int ak_tlv_compare_global_names( ak_tlv , ak_tlv );
/*! \brief Вывод информации о расширенном имени в заданный файл. */
 dll_export int ak_tlv_print_global_name( ak_tlv , FILE * );
/*! \brief Вывод информации о расширенном имени в заданную строку. */
 dll_export int ak_tlv_snprintf_global_name( ak_tlv , char * , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Выделение памяти и создание одного уровня ASN1 дерева. */
 dll_export ak_asn1 ak_asn1_new( void );
/*! \brief Создание одного уровня ASN1 дерева. */
 dll_export int ak_asn1_create( ak_asn1 );
/*! \brief Перемещение к следующему узлу текущего уровня ASN1 дерева. */
 dll_export bool_t ak_asn1_next( ak_asn1 );
/*! \brief Перемещение к предыдущему узлу текущего уровня ASN1 дерева. */
 dll_export bool_t ak_asn1_prev( ak_asn1 );
/*! \brief Перемещение к последнему узлу текущего уровня ASN1 дерева. */
 dll_export bool_t ak_asn1_last( ak_asn1 );
/*! \brief Перемещение к первому узлу текущего уровня ASN1 дерева. */
 dll_export bool_t ak_asn1_first( ak_asn1 );
/*! \brief Изъятие текущего узла из ASN1 дерева. */
 dll_export ak_tlv ak_asn1_exclude( ak_asn1 asn1 );
/*! \brief Уничтожение текущего узла с текущего уровня ASN1 дерева. */
 dll_export bool_t ak_asn1_remove( ak_asn1 );
/*! \brief Уничтожение текущего уровня ASN1 дерева. */
 dll_export int ak_asn1_destroy( ak_asn1 );
/*! \brief Уничтожение текущего уровня ASN1 дерева и освобождение памяти. */
 dll_export ak_pointer ak_asn1_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Добавление нового узла к текущему уровню ASN1 дерева. */
 dll_export int ak_asn1_add_tlv( ak_asn1 , ak_tlv );
/*! \brief Добавление к текущему уровню ASN1 дерева булева значения. */
 dll_export int ak_asn1_add_bool( ak_asn1 , const bool_t );
/*! \brief Добавление к текущему уровню ASN1 дерева целого числа, представимого в виде
    беззнакового 32-х битного значения. */
 dll_export int ak_asn1_add_uint32( ak_asn1 , const ak_uint32 );
/*! \brief Добавление к текущему уровню ASN1 дерева большого целого числа, представимого
    в виде объекта класса \ref ak_mpzn */
 dll_export int ak_asn1_add_mpzn( ak_asn1 , ak_uint8 tag, ak_uint64 * , const size_t );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную
    последовательность октетов */
 dll_export int ak_asn1_add_octet_string( ak_asn1 , const ak_pointer , const size_t );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную строку
    в кодировке utf-8. */
 dll_export int ak_asn1_add_utf8_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную ia5-строку. */
 dll_export int ak_asn1_add_ia5_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную
    printable-строку. */
 dll_export int ak_asn1_add_printable_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего произвольную
    последовательность арабских цифр. */
 dll_export int ak_asn1_add_numeric_string( ak_asn1 , const char * );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего двоичную строку. */
 dll_export int ak_asn1_add_bit_string( ak_asn1 , ak_bit_string );
/*! \brief Добавление к текущему уровню ASN1 дерева узла, содержащего идентификатор объекта */
 dll_export int ak_asn1_add_oid( ak_asn1 , const char * );
/*!  \brief Добавление универсального времени к текущему уровню ASN1 дерева узла*/
 dll_export int ak_asn1_add_utc_time( ak_asn1 , time_t );
/*! \brief Добавление к текущему уровню ASN1 дерева низлежащего уровня */
 dll_export int ak_asn1_add_asn1( ak_asn1 , ak_uint8 , ak_asn1 );
/*! \brief Добавление к текущему уровню ASN1 дерева низлежащего уровня,
    представленного в виде der-последовательности октетов */
 dll_export int ak_asn1_add_asn1_as_octet_string( ak_asn1 , ak_asn1 );
/*! \brief Добавление к текущему уровню ASN1 дерева низлежащего уровня, содержащего временной интервал */
 dll_export int ak_asn1_add_validity( ak_asn1 , time_t , time_t );
/*! \brief Функция добавляет в ASN.1 структуру, содержащую ресурс (структуру struct resource). */
 dll_export int ak_asn1_add_resource( ak_asn1 root, ak_resource );
/*! \brief Функция добавляет в ASN.1 структуру, содержащую идентификатор алгоритма. */
 dll_export int ak_asn1_add_algorithm_identifier( ak_asn1 , ak_oid , ak_oid );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вывод информации о текущем уровне ASN1 дерева. */
 dll_export int ak_asn1_print( ak_asn1 , FILE * );
/*! \brief Функция вычисляет размер, занимаемый данным уровнем ASN.1 дерева */
 dll_export int ak_asn1_evaluate_length( ak_asn1 , size_t * );
/*! \brief Кодирование ASN1 дерева в DER-последовательность октетов. */
 dll_export int ak_asn1_encode( ak_asn1 , ak_pointer , size_t * );
/*! \brief Декодирование ASN1 дерева из заданной DER-последовательности октетов. */
 dll_export int ak_asn1_decode( ak_asn1 , const ak_pointer , const size_t , bool_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт ASN.1 дерева в файл в виде der-последовательности. */
 dll_export int ak_asn1_export_to_derfile( ak_asn1 , const char * );
/*! \brief Экспорт ASN.1 дерева в файл в виде der-последовательности, закодированной в base64. */
 dll_export int ak_asn1_export_to_pemfile( ak_asn1 , const char * , crypto_content_t );
/*! \brief Экспорт ASN.1 дерева в файл. */
 dll_export int ak_asn1_export_to_file( ak_asn1 , const char * , export_format_t , crypto_content_t );
/*! \brief Импорт ASN.1 дерева из файла, содержащего der-последовательность. */
 dll_export int ak_asn1_import_from_file( ak_asn1 , const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выводит в заданный файл закодированное ASN.1 дерево. */
 dll_export int ak_libakrypt_print_asn1( const char * , FILE *);
/*! \brief Конвертирование asn1 дерева из der формата в pem и обратно. */
 dll_export int ak_libakrypt_convert_asn1( const char * , const char * ,
                                                              export_format_t , crypto_content_t );
/*! \brief Разбиение asn1 дерева на поддеревья первого уровня. */
 dll_export int ak_libakrypt_split_asn1( const char * , export_format_t , crypto_content_t );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-doc Ключи криптографических механизмов
 @{ *//*! \brief Секретный ключ алгоритма выработки электронной подписи ГОСТ Р 34.10-2012.

   Ключ может рассматриваться в качестве секретного ключа как для действующего стандарта
   ГОСТ Р 34.10-2012, так и для предыдущей редакции 2001 года. Кроме того, данный контекст
   секретного ключа может быть применим для любого асимметричного криптографического механизма,
   использующего вычисления с эллиптическими кривыми в короткой форме Вейерштрасса, либо
   в искривленной форме Эдвардса. Кривые указанных форм поддерживаются отечественными
   рекомендациями Р 1323565.024-2019.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct signkey {
 /*! \brief контекст секретного ключа */
  struct skey key;
 /*! \brief контекст функции хеширования */
  struct hash ctx;
 /*! \brief номер открытого ключа, выработанного из данного секретного ключа. */
  ak_uint8 verifykey_number[32];
} *ak_signkey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создания контекста секретного ключа электронной подписи. */
 typedef int ( ak_function_signkey_create ) ( ak_signkey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012. */
 dll_export int ak_signkey_create( ak_signkey , const ak_wcurve );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012. */
 dll_export int ak_signkey_create_str( ak_signkey , const char * );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012
   с параметрами эллиптической кривой по-умолчанию. */
 dll_export int ak_signkey_create_streebog256( ak_signkey );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012
   с параметрами эллиптической кривой по-умолчанию. */
 dll_export int ak_signkey_create_streebog512( ak_signkey );
/*! \brief Инициализация контекста секретного ключа алгоритма выработки электронной подписи
    по заданному идентификатору алгоритма. */
 dll_export int ak_signkey_create_oid( ak_signkey , ak_oid );
/*! \brief Присвоение контексту секретного ключа указателя на эллиптическую кривую. */
 dll_export int ak_signkey_set_curve( ak_signkey , const ak_wcurve );
/*! \brief Присвоение контексту секретного ключа указателя на эллиптическую кривую. */
 dll_export int ak_signkey_set_curve_str( ak_signkey sctx, const char * );
/*! \brief Функция устанавливает временной интервал действия секретного ключа. */
 dll_export int ak_signkey_set_validity( ak_signkey , time_t , time_t );
/*! \brief Функция устанавливает ресурс и временной итервал действия ключа. */
 dll_export int ak_signkey_set_resource_values( ak_signkey , counter_resource_t ,
                                                                  const char * , time_t , time_t );
/*! \brief Уничтожение контекста секретного ключа. */
 dll_export int ak_signkey_destroy( ak_signkey );
/*! \brief Размер области памяти, которую занимает электронная подпись. */
 dll_export size_t ak_signkey_get_tag_size( ak_signkey );
/*! \brief Присвоение секретному ключу электронной подписи константного значения. */
 dll_export int ak_signkey_set_key( ak_signkey , const ak_pointer , const size_t );
/*! \brief Присвоение секретному ключу электронной подписи случайного значения. */
 dll_export int ak_signkey_set_key_random( ak_signkey , ak_random );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup sign-doc Электронная подпись
 @{ *//** \addtogroup cert-doc Открытые ключи асимметричных алгоритмов и их сертификаты
 @{ */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Открытый ключ алгоритма проверки электронной подписи ГОСТ Р 34.10-2012.

   Ключ представляет собой объединение точки эллиптической кривой, а также ряда параметров (номера
   ключа, обобщенного имени владельца, времени действия ключа и т.п.),
   используемых при помещении ключа в контейнер или сертификат.

   Ключ может рассматриваться в качестве открытого ключа как для действующего стандарта
   ГОСТ Р 34.10-2012, так и для предыдущей редакции 2001 года. Кроме того, данный контекст
   открытого ключа может быть применим для любого асимметричного криптографического механизма,
   использующего вычисления с эллиптическими кривыми в короткой форме Вейерштрасса, либо
   в искривленной форме Эдвардса. Кривые указанных форм поддерживаются отечественными
   рекомендациями Р 1323565.024-2019.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct verifykey {
 /*! \brief контекст функции хеширования */
  struct hash ctx;
 /*! \brief уникальный номер открытого ключа */
  ak_uint8 number[32];
 /*! \brief контекст эллиптической кривой */
  ak_wcurve wc;
 /*! \brief OID алгоритма, для которого используется ключ;
    в случае электронной подписи используется идентификтор алгоритма проверки подписи */
  ak_oid oid;
 /*! \brief точка кривой, являющаяся открытым ключом электронной подписи */
  struct wpoint qpoint;
 /*! \brief временной интервал использования ключа  */
  struct time_interval time;
 /*! \brief ASN.1 дерево, содержащее в себе последовательность расширенных имен
    владельца ключа (согласно ITU-T X.509) */
  ak_tlv name;
 /*! \brief флаги состояния ключа */
  ak_uint64 flags;
} *ak_verifykey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Бит `digitalSignature` расширения `keyUsage`. */
 #define bit_digitalSignature   (256)
/*! \brief Бит `contentCommitment` расширения `keyUsage`. */
 #define bit_contentCommitment  (128)
/*! \brief Бит `keyEncipherment` расширения `keyUsage`. */
 #define bit_keyEncipherment     (64)
/*! \brief Бит `dataEncipherment` расширения `keyUsage`. */
 #define bit_dataEncipherment    (32)
/*! \brief Бит `keyAgreement` расширения `keyUsage`. */
 #define bit_keyAgreement        (16)
/*! \brief Бит `keyCertSign` расширения `keyUsage`. */
 #define bit_keyCertSign          (8)
/*! \brief Бит `cRLSign` расширения `keyUsage`. */
 #define bit_cRLSign              (4)
/*! \brief Бит `encipherOnly` расширения `keyUsage`. */
 #define bit_encipherOnly         (2)
/*! \brief Бит `decipherOnly` расширения `keyUsage`. */
 #define bit_decipherOnly         (1)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, в которой хранятся параметры сертификата открытого ключа.
    \details Указанные параметры используются при создании сертификата, а также при проверке
    его валидности. В структуру включены параметры, которые не входят в struct verifykey           */
/* ----------------------------------------------------------------------------------------------- */
  typedef struct certificate_opts
{
 /*! \brief расширение `Basic Constraints` */
  struct {
    /*! \brief определено ли данное расширение */
     bool_t is_present;
    /*! \brief разрешено ли порождать цепочки сертификации */
     bool_t value;
    /*! \brief количество промежуточных сертификатов в цепочке сертификации. */
     ak_uint32 pathlenConstraint;
  } ca;

 /*! \brief расширение `keyUsage`. */
  struct {
    /*! \brief определено ли данное расширение */
     bool_t is_present;
    /*! \brief набор бит, описывающих область применения открытого ключа */
     ak_uint32 bits;
  } key_usage;

 /*! \brief расширение Subject Key Identifier */
  struct {
    /*! \brief определено ли данное расширение */
     bool_t is_present;
    /*! \brief длина идентификатора ключа (в октетах) */
     size_t length;
  } subjkey;

 /*! \brief расширение Authority Key Identifier */
  struct {
    /*! \brief определено ли данное расширение */
     bool_t is_present;
    /*! \brief надо ли включать расширенное имя эмитента в сертификат */
     bool_t include_name;
  } authoritykey;

 /*! \brief Версия сертификата (по-умолчанию, мы всегда работаем с v3) */
  ak_uint32 version;
 /*! \brief Флаг того, создан ли сертификат, используется только при импорте сертификатов */
  bool_t created;
 /*! \brief длина серийного номера */
  size_t serialnumlen;
 /*! \brief собственно серийный номер сертификата */
 /*! \details при экспорте данное значение вырабатывается в процессе выработки сертификата,
     при импорте - считывается из asn1 дерева */
  ak_uint8 serialnum[32];

} *ak_certificate_opts;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция присваивает значения по-умолчанию для опций сертификата. */
 dll_export int ak_certificate_opts_create( ak_certificate_opts );
/*! \brief Функция уничтожает динамически размещенные данные, полученные в ходе импорта сертификата. */
 dll_export int ak_certificate_opts_destroy( ak_certificate_opts );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста открытого ключа асимметричного криптографического алгоритма,
    в частности, алгоритма ГОСТ Р 34.10-2012. */
 dll_export int ak_verifykey_create( ak_verifykey , const ak_wcurve );
 /*! \brief Инициализация контекста открытого ключа асимметричного криптографического алгоритма,
    c фиксированной кривой размера 256 бит. */
 dll_export int ak_verifykey_create_streebog256( ak_verifykey );
 /*! \brief Инициализация контекста открытого ключа асимметричного криптографического алгоритма,
    c фиксированной кривой размера 512 бит. */
 dll_export int ak_verifykey_create_streebog512( ak_verifykey );
/*! \brief Инициализация контекста открытого ключа асимметричного криптографического алгоритма,
    в частности, алгоритма ГОСТ Р 34.10-2012. */
 dll_export int ak_verifykey_create_from_signkey( ak_verifykey , ak_signkey );
/*! \brief Функция устанавливает временной интервал действия открытого ключа. */
 dll_export int ak_verifykey_set_validity( ak_verifykey , time_t , time_t );
/*! \brief Функция вырабатывает номер открытого ключа. */
 dll_export int ak_verifykey_set_number( ak_verifykey );
/*! \brief Функция добавляет к расширенному имени владельца ключа новую строку. */
 dll_export int ak_verifykey_add_name_string( ak_verifykey , const char * , const char * );
/*! \brief Уничтожение контекста открытого ключа. */
 dll_export int ak_verifykey_destroy( ak_verifykey );
/** \addtogroup cert-export-doc Функции экспорта и импорта открытых ключей
 @{ */
/*! \brief Функция экспортирует открытый ключ асиметричного криптографического алгоритма
    в запрос на получение сертификата окрытого ключа. */
 dll_export int ak_verifykey_export_to_request( ak_verifykey , ak_signkey , ak_random ,
                                                         char * , const size_t , export_format_t );
/*! \brief Функция импортирует открытый ключ асимметричного преобразования из запроса
   на сертификат открытого ключа */
 dll_export int ak_verifykey_import_from_request( ak_verifykey , const char * ,
                                                                         ak_function_file_output );
/*! \brief Функция вырабатывает серийный номер сертификата. */
 dll_export int ak_verifykey_generate_certificate_serial_number( ak_verifykey ,
                                                                         ak_signkey , ak_mpzn256 );
/*! \brief Функция экспортирует открытый ключ асиметричного криптографического алгоритма
    в сертификат открытого ключа. */
 dll_export int ak_verifykey_export_to_certificate( ak_verifykey , ak_signkey , ak_verifykey ,
                       ak_random , ak_certificate_opts , char * , const size_t , export_format_t );

/*! \brief Функция импортирует открытый ключ асимметричного преобразования из сертификата
   открытого ключа */
 dll_export int ak_verifykey_import_from_certificate( ak_verifykey , ak_verifykey ,
                                    const char * , ak_certificate_opts , ak_function_file_output );
/*! \brief Функция импортирует открытый ключ асимметричного преобразования из сертификата
   открытого ключа, расположенного в памяти */
 dll_export int ak_verifykey_import_from_ptr_as_certificate( ak_verifykey ,
  ak_verifykey , const ak_pointer , const size_t , ak_certificate_opts , ak_function_file_output );

/** @} *//** \addtogroup cert-tlv-doc Функции создания расширений сертификатов открытых ключей
 @{ */
/*! \brief Создание расширения, содержащего идентификатор открытого ключа
   (x509v3: SubjectKeyIdentifier ) */
 dll_export ak_tlv ak_tlv_new_subject_key_identifier( ak_pointer, const size_t );
/*! \brief Создание расширения, содержащего основные ограничения (x509v3: BasicConstraints ) */
 dll_export ak_tlv ak_tlv_new_basic_constraints( bool_t , const ak_uint32 );
/*! \brief Создание расширения, содержащего область применения сертификата (x509v3: keyUsage ) */
 dll_export ak_tlv ak_tlv_new_key_usage( const ak_uint32 );
/*! \brief Создание расширения, содержащего информацию о ключе проверки сертификата
   (x509v3: Authority Key Identifier) */
 dll_export ak_tlv ak_tlv_new_authority_key_identifier( ak_signkey , ak_verifykey , const bool_t );
/** @} */
/** @} *//** \addtogroup signalg-doc Алгоритмы выработки и проверки электроной подписи
 @{ */
/*! \brief Выработка электронной подписи для фиксированного значения случайного числа и вычисленного
    заранее значения хеш-функции. */
 dll_export void ak_signkey_sign_const_values( ak_signkey , ak_uint64 * ,
                                                                        ak_uint64 * , ak_pointer );
/*! \brief Выработка электронной подписи для вычисленного заранее значения хеш-функции. */
 dll_export int ak_signkey_sign_hash( ak_signkey , ak_random , ak_pointer , size_t ,
                                                                             ak_pointer , size_t );
/*! \brief Выработка электронной подписи для заданной области памяти. */
 dll_export int ak_signkey_sign_ptr( ak_signkey , ak_random , const ak_pointer ,
                                                              const size_t , ak_pointer , size_t );
/*! \brief Выработка электронной подписи для заданного файла. */
 dll_export int ak_signkey_sign_file( ak_signkey , ak_random ,
                                                              const char * , ak_pointer , size_t );
/*! \brief Проверка электронной подписи для вычисленного заранее значения хеш-функции. */
 dll_export bool_t ak_verifykey_verify_hash( ak_verifykey , const ak_pointer ,
                                                                       const size_t , ak_pointer );
/*! \brief Проверка электронной подписи для заданной области памяти. */
 dll_export bool_t ak_verifykey_verify_ptr( ak_verifykey , const ak_pointer ,
                                                                       const size_t , ak_pointer );
/*! \brief Проверка электронной подписи для заданного файла. */
 dll_export bool_t ak_verifykey_verify_file( ak_verifykey , const char * , ak_pointer );
/** @} *//** @} */

/* ----------------------------------------------------------------------------------------------- */
/*! \addtogroup skey-doc
 @{ */
/*! \brief Тип функции, предназначенной для считывания пароля.  */
 typedef ssize_t ( ak_function_password_read ) ( char *, const size_t );
/*! \brief Чтение пароля из консоли с выводом уведомления (устанавливается по-умолчанию) */
 dll_export ssize_t ak_password_read_from_terminal( char * , const size_t );
/*! \brief Функция устанавливает обработчик - функцию чтения пользовательского пароля. */
 dll_export int ak_libakrypt_set_password_read_function( ak_function_password_read * );
/*! \brief Функция экспортирует секретный ключ в указанный файл. */
 dll_export int ak_skey_export_to_file_with_password( ak_pointer ,
                            const char *, const size_t , char * , const size_t , export_format_t );
/*! \brief Функция инициализирует контекст секретного ключа и импортирует параметры ключа
    из указанного файла. */
 dll_export int ak_skey_create_from_file( ak_pointer , oid_engines_t , const char * );
/*! \brief Функция инициализирует контекст секретного ключа, импортирует параметры ключа
    из указанного файла, а также присваивает значение секретного ключа. */
 dll_export int ak_skey_import_from_file( ak_pointer , oid_engines_t , const char * );
/*! \brief Функция создает и инициализирует контекст секретного ключа, после чего импортирует параметры
    ключа из указанного файла. */
 dll_export ak_pointer ak_skey_new_from_file( const char * );
/*! \brief Функция создает и инициализирует контекст секретного ключа, после чего импортирует
    значение секретного ключа и его параметры из указанного файла. */
 dll_export ak_pointer ak_skey_load_from_file( const char *filename );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-doc Cекретные ключи криптографических механизмов
 @{ */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ для схемы Блома распределения ключевой информации. */
/*! Подробное описание механизмов выработки ключей содержится в разделе \ref skey-blom-doc. */
 typedef struct blomkey {
  /*! \brief количество октетов, образующих один элемент конечного поля. */
   ak_uint32 count;
  /*! \brief величина определяет размер матрицы в \f$ size\times size\f$ элементов */
   ak_uint32 size;
  /*! \brief указатель на ключевые данные */
   ak_uint8 *data;
  /*! \brief контрольная сумма (хэш-код ключевых данных) */
   ak_uint8 icode[32];
  /*! \brief контекст алгоритма выработки имитовставки */
   struct hash ctx;
  /*! \brief тип ключа */
   enum {
    /*! \brief мастер-ключ, из которого вырабатываются все производные ключи */
     blom_matrix_key,
    /*! \brief секретный ключ клиента, представляющий собой вектор-строку */
     blom_abonent_key
   } type;
 } *ak_blomkey;

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-blom-doc Реализация схемы Блома распределения ключевой информации
 @{ *//*! \brief Функция создает мастер-ключ для схемы Блома. */
 dll_export int ak_blomkey_create_matrix( ak_blomkey , const ak_uint32 ,
                                                                     const ak_uint32 , ak_random );
/*! \brief Функция создает ключ абонента для схемы Блома. */
 dll_export int ak_blomkey_create_abonent_key( ak_blomkey , ak_blomkey ,
                                                                       ak_pointer , const size_t );
/*! \brief Функция создает ключ парной связи (в виде последовательности октетов) */
 dll_export int ak_blomkey_create_pairwise_key_as_ptr( ak_blomkey ,
                                                 ak_pointer , const size_t , ak_pointer , size_t );
/*! \brief Функция создает ключ парной связи и помещает его в контекст секретного ключа */
 dll_export ak_pointer ak_blomkey_new_pairwise_key( ak_blomkey , ak_pointer ,
                                                                           const size_t , ak_oid );
/*! \brief Функция возвращает элемент ключа с заданным индексом */
 dll_export ak_uint8 *ak_blomkey_get_element_by_index( ak_blomkey ,
                                                               const ak_uint32 , const ak_uint32 );
/*! \brief Уничтожение ключа */
 dll_export int ak_blomkey_destroy( ak_blomkey );
/*! \brief Экспорт ключа в заданный файл */
 dll_export int ak_blomkey_export_to_file_with_password( ak_blomkey ,
                                             const char * , const size_t , char * , const size_t );
/*! \brief Импорт ключа из заданного файла */
 dll_export int ak_blomkey_import_from_file_with_password( ak_blomkey ,
                                                            const char * , const size_t , char * );
/** @} *//** @} */

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */

