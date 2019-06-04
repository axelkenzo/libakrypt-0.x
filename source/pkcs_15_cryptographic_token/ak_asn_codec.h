/* ----------------------------------------------------------------------------------------------- */
/*  Файл ak_asn_codec.h                                                                           */
/*  - содержит перечень стандартных типов ASN.1;                                                   */
/*  - содержит перечень описаний функций кодирования и декодирования стандартных типов ASN.1;      */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_ASN_H__
#define __AK_ASN_H__

#include "kc_includes.h"

#include <libakrypt.h>
#include <pkcs_15_cryptographic_token/ak_pointer_server.h>


/*! \brief флаги, определяющие класс данных ASN.1. */
#define UNIVERSAL           0x00u
#define APPLICATION         0x40u
#define CONTEXT_SPECIFIC    0x80u
#define PRIVATE             0xC0u

/*! \brief флаг, определяющий структуру блока данных ASN.1. */
#define PRIMITIVE           0x00u
#define CONSTRUCTED         0x20u

/*! \brief номера стандартных тегов ASN.1. */
#define TEOC                0x00u
#define TBOOLEAN            0x01u
#define TINTEGER            0x02u
#define TBIT_STRING         0x03u
#define TOCTET_STRING       0x04u
#define TNULL               0x05u
#define TOBJECT_IDENTIFIER  0x06u
#define TOBJECT DESCRIPTOR  0x07u
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

/*! \brief Струкртура, хранящая целочисленые значения в соответствии с ASN.1. */
struct s_asn_int_type {
    /*! \brief массив, содержащий значение в формате big-endian. */
    byte *mp_value;
    /*! \brief размер массива с данными. */
    size_t m_val_len;
    /*! \brief флаг, определяющий знак числа. */
    bool m_positive;
};

/*! \brief Струкртура, хранящая массив байтов в соответствии с ASN.1. */
struct s_asn_oct_str_type {
    /*! \brief массив, содержащий значение. */
    byte *mp_value;
    /*! \brief размер массива с данными. */
    size_t m_val_len;
};

/*! \brief Струкртура, хранящая "битовую строку" в соответствии с ASN.1. */
struct s_asn_bit_str_type {
    /*! \brief массив, содержащий значение. */
    byte *mp_value;
    /*! \brief размер массива с данными. */
    size_t m_val_len;
    /*! \brief кол-во неиспользуемых битов в последнем байте
               (возмжные значения от 0 до 7 включительно). */
    uint8_t m_unused;
};

typedef byte tag;

/*! \brief Псевдонимы базовых типов ASN.1 */
typedef bool boolean;
typedef byte *utf8_string;
typedef char *visible_string;
typedef char *generalized_time;
typedef char *object_identifier;
typedef struct s_asn_int_type integer;
typedef struct s_asn_bit_str_type bit_string;
typedef struct s_asn_oct_str_type octet_string;

/*! \brief Декодирование тега из DER последовательности. */
int asn_get_tag(byte *p_buff, tag *p_tag);

/*! \brief Декодирование длины данных из DER последовательности. */
int asn_get_len(byte *p_buff, size_t *p_len, uint8_t *p_len_byte_cnt);

/*! \brief Декодирование целого числа из DER последовательности. */
int asn_get_int(byte *p_buff, size_t len, integer *p_val);

/*! \brief Декодирование UTF-8 строки из DER последовательности. */
int asn_get_utf8string(byte *p_buff, size_t len, utf8_string *p_str);

/*! \brief Декодирование массива октетов из DER последовательности. */
int asn_get_octetstr(byte *p_buff, size_t len, octet_string *p_dst);

/*! \brief Декодирование строки из DER последовательности. */
int asn_get_vsblstr(byte *p_buff, size_t len, visible_string *p_str);

/*! \brief Декодирование идентификатора объекта из DER последовательности. */
int asn_get_objid(byte *p_buff, size_t len, object_identifier *p_objid);

/*! \brief Декодирование массива байтов, представляющих произвольные флаги, из DER последовательности. */
int asn_get_bitstr(byte *p_buff, size_t len, bit_string *p_dst);

/*! \brief Декодирование значения типа boolean из DER последовательности. */
int asn_get_bool(byte *p_buff, size_t len, boolean *p_value);

/*! \brief Декодирование времени, представленном в общепринятом формате, из DER последовательности. */
int asn_get_generalized_time(byte *p_buff, size_t len, generalized_time *p_time);

/*! \brief Добавление тега в DER последовательность. */
int asn_put_tag(tag tag, byte *p_buff);

/*! \brief Добавление длины данных в DER последовательность. */
int asn_put_len(size_t len, byte *p_buff);

/*! \brief Добавление целого числа в DER последовательность. */
int asn_put_int(integer val, byte *p_buff);

/*! \brief Добавление UTF-8 строки в DER последовательность. */
int asn_put_utf8string(utf8_string str, byte *p_buff);

/*! \brief Добавление массива октетов в DER последовательность. */
int asn_put_octetstr(octet_string src, byte *p_buff);

/*! \brief Добавление строки в DER последовательность. */
int asn_put_vsblstr(visible_string str, byte *p_buff);

/*! \brief Добавление идентификатора объекта в DER последовательность. */
int asn_put_objid(object_identifier obj_id, byte *p_buff);

/*! \brief Добавление массива байтов, представляющих произвольные флаги, в DER последовательность. */
int asn_put_bitstr(bit_string src, byte *p_buff);

/*! \brief Добавление значения типа boolean в DER последовательность. */
int asn_put_bool(boolean val, byte *p_buff);

/*! \brief Добавление времени, представленном в общепринятом формате, в DER последовательность. */
int asn_put_generalized_time(generalized_time time, byte *p_buff);


/* Tools */
/*! \brief Метод для добавления стандартных типов данных в DER последовательность. */
int asn_put_universal_tlv(uint8_t tag_number,
                          void *p_data,
                          size_t seq_or_set_len,
                          s_ptr_server *p_main_ps,
                          s_ptr_server *p_result);

/*! \brief Метод для декодированния типов данных из DER последовательности. */
int asn_get_expected_tlv(tag expected_tag, s_ptr_server *p_curr_ps, void *p_result);

/*! \brief Метод для определения кол-ва элементов в блоке данных DER последовательности. */
int asn_get_num_of_elems_in_constructed_obj(s_ptr_server *p_data, uint8_t *p_num_of_elems);

/*! \brief Метод для определения необходимого кол-ва памяти для хранения длины данных. */
ak_uint8 asn_get_len_byte_cnt(size_t len);

/*! \brief Метод для определения необходимого кол-ва памяти для хранения идентификатора объекта. */
ak_uint8 asn_get_oid_byte_cnt(object_identifier oid);

/*! \brief Метод для определения необходимого кол-ва памяти для хранения времени в общепринятом формате. */
ak_uint8 asn_get_gentime_byte_cnt(generalized_time time);

/*! \brief Освобождение памяти. */
void asn_free_int(integer *p_val);

void asn_free_utf8string(utf8_string *p_val);

void asn_free_octetstr(octet_string *p_val);

void asn_free_vsblstr(visible_string *p_val);

void asn_free_objid(object_identifier *p_val);

void asn_free_bitstr(bit_string *p_val);

void asn_free_generalized_time(generalized_time *p_val);

#endif /* __AK_ASN_H__ */
