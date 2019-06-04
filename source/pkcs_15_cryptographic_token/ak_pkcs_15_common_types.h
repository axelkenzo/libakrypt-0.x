/* ----------------------------------------------------------------------------------------------- */
/*  Файле ak_pkcs_15_common_types.h содержит перечень типов даных, описывающих         */
/*  блок памяти и перемещаться по ней.                                                             */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_PKCS_CMN_TYPES_H__
#define __AK_PKCS_CMN_TYPES_H__

#include <pkcs_15_cryptographic_token/ak_asn_codec.h>
#include <pkcs_15_cryptographic_token/ak_pointer_server.h>
#include <pkcs_15_cryptographic_token/ak_pkcs_15_algs_prms.h>

typedef s_ptr_server s_der_buffer;

/*! \brief Перечисление, определяющее флаги испоьзования ключа. */
typedef enum {
    ENCRYPT = 0x8000u,
    DECRYPT = 0x4000u,
    SIGN = 0x2000u,
    SIGN_RECOVER = 0x1000u,
    WRAP = 0x0800u,
    UNWRAP = 0x0400u,
    VERIFY = 0x0200u,
    VERIFY_RECOVER = 0x0100u,
    DERIVE = 0x0080u,
    NON_REPUDIATION = 0x0040u
} en_usage_bits;

typedef uint16_t key_usage_flags_t;

/*! \brief Структура, хранящая общие атрибуты объекта PKCS 15 Object. */
typedef struct {
    /*! \brief название ключа понятное человеку */
    utf8_string m_label;
    bit_string m_flags; // в данной реализации не испоьльзуется
} s_common_obj_attrs;

/*! \brief Структура, хранящая общие атрибуты объекта PKCS 15 Key object. */
typedef struct {
    /*! \brief уникальный идентификатор ключа */
    octet_string m_id;
    /*! \brief флаги, определяющие предназначения ключа */
    bit_string m_usage;
    /*! \brief флаг, определяющий возможность использования ключа для аппаратных вычислений */
    boolean m_native;
    bit_string m_access_flags; // в данной реализации не испоьльзуется
    integer m_key_reference; // в данной реализации не испоьльзуется
    /*! \brief начало периода действия ключа */
    generalized_time m_start_date;
    /*! \brief конец периода действия ключа */
    generalized_time m_end_date;
} s_common_key_attrs;

/*! \brief Структура, хранящая информацию о ключе шифрования CEK и алгоритме шифрования. */
typedef struct {
    /*! \brief версия (всегда равна 4) */
    integer m_version;              // always set to 4
    /*! \brief идентификатор ключа, который вырабатывается пароля */
    octet_string m_key_identifire;
    generalized_time m_date; // в данной реализации не испоьльзуется
    /*! \brief идентификатор алгоритма шифрования ключа CEK */
    object_identifier m_key_enc_alg_id;
    /*! \brief зашифрованное значение CEK, представленное в виде DER последовательности */
    octet_string m_encrypted_key;
    /*! \brief тип набора параметров (см. en_param_set_type)*/
    en_param_set_type m_prm_set_type;
    /*! \brief набор параметров для алгоритма шифрования ключа CEK */
    u_param_set m_prm_set;
} s_kekri;

/*
 * Содержит как вариант для password info
 * (используемый в key management info),
 * так и recipient info;
 * Значения соответствуют тегам из стандарта
 */
/*! \brief Перечисление, определяющее способ представления информации о ключе шифрования ключа CEK. */
typedef enum {
    PWD_INFO = 0u,
    KEKRI = 2u,
    PWRI = 3u
} en_pr_info;

/*! \brief Структура, хранящая информацию о получателе ключа. */
typedef union {
    s_kekri *mp_kekri;
    /*TODO: комментарий для Алексея Юрьевича: при необходимости, сюда следует добавить вариант Password Recipient Info.
            Его реализация, к сожалению, отсутствует.*/

} u_recipient_info;

/*! \brief Структура, хранящая информацию о получателе ключа и тип информации. */
typedef struct {
    /*! \brief вариант представления информации */
    en_pr_info m_type;
    /*! \brief информация о получателе ключа */
    u_recipient_info m_ri;
} s_recipient_info;

/*! \brief Структура, хранящая зашифрованное содержимое и информацию о шифровании. */
typedef struct {
    /*! \brief версия */
    integer m_version;
    /*! \brief массив указателей на данные о получателях ключа */
    s_recipient_info **mpp_recipient_infos;
    /*! \brief количество получателей ключа */
    uint8_t m_ri_size;
    /*! \brief идентификатор зашифрованного содержимого */
    object_identifier m_content_type;
    /*! \brief идентификатор алгоритма шифрования содержимого */
    object_identifier m_content_enc_alg_id;
    /*! \brief тип набора параметров (см. en_param_set_type)*/
    en_param_set_type m_prm_set_type;
    /*! \brief набора параметров для алгоритма шифрования содержимого */
    u_param_set m_prm_set;
    /*! \brief зашифрованное содержимое */
    octet_string m_encrypted_content;
} s_enveloped_data;

/* В данной версии не используется */
typedef struct {
    object_identifier m_parameters_id; //const "1.2.643.7.1.2.5.1.1"
    bit_string m_supported_operations; // 0
} s_key_info;

/** Методы добавления данных **/

/*! \brief Добавление зашифрованного объекта в DER последовательность. */
int pkcs_15_put_object_direct_protected(s_der_buffer *p_pkcs_15_token_der,
                                        s_enveloped_data *p_enveloped_data,
                                        s_der_buffer *p_enveloped_data_der);

/*! \brief Добавление общих атрибутов объектов в DER последовательность. */
int pkcs_15_put_common_object_attributes(s_der_buffer *p_pkcs_15_token_der,
                                         s_common_obj_attrs *p_obj_attrs,
                                         s_der_buffer *p_common_object_attributes_der);

/*! \brief Добавление общих атрибутов ключей в DER последовательность. */
int pkcs_15_put_common_key_attributes(s_der_buffer *p_pkcs_15_token_der,
                                      s_common_key_attrs *p_key_attrs,
                                      s_der_buffer *p_common_key_attributes_der);

/*! \brief Добавление информации о получателях данных в DER последовательность. */
int pkcs_15_put_recipient_infos(s_der_buffer *p_pkcs_15_token,
                                s_recipient_info **pp_recipient_infos,
                                uint8_t num_of_recipient_infos,
                                s_der_buffer *p_recipient_infos_der);

/*! \brief Добавление информации о конкретном получателе данных в DER последовательность. */
int pkcs_15_put_single_recipient_info(s_der_buffer *p_pkcs_15_token,
                                      s_recipient_info *p_sngl_recipient_info,
                                      s_der_buffer *p_sngl_recipient_info_der);

/*! \brief Добавление информации о шифровании ключа CEK в DER последовательность. */
int pkcs_15_put_kekri(s_der_buffer *p_pkcs_15_token, s_kekri *p_kekri, s_der_buffer *p_kekri_der);

/*! \brief Добавление информации об алгоритме шифрования ключа CEK в DER последовательность. */
int pkcs_15_put_key_encryption_algorithm(s_der_buffer *p_pkcs_15_token,
                                         s_kekri *p_kekri,
                                         s_der_buffer *p_key_encryption_algorithm_der);

/*! \brief Добавление информации о зашифрованных данных в DER последовательность. */
int pkcs_15_put_encrypted_content_info(s_der_buffer *p_pkcs_15_token,
                                       s_enveloped_data *p_enveloped_data,
                                       s_der_buffer *p_encrypted_content_info_der);

/*! \brief Добавление информации об алгоритме шифрования данных (контента) в DER последовательность. */
int pkcs_15_put_content_encryption_algorithm(s_der_buffer *p_pkcs_15_token,
                                             s_enveloped_data *p_enveloped_data,
                                             s_der_buffer *p_content_enc_alg_der);

/** Методы декодирования данных **/

/*! \brief Декодирование зашифрованного объекта из DER последовательности. */
int pkcs_15_get_object_direct_protected(s_der_buffer *p_object_der, s_enveloped_data *p_enveloped_data);

/*! \brief Декодирование общих атрибутов объектов из DER последовательности. */
int pkcs_15_get_common_object_attributes(s_der_buffer *p_object_der, s_common_obj_attrs *p_obj_attrs);

/*! \brief Декодирование общих атрибутов ключей из DER последовательности. */
int pkcs_15_get_common_key_attributes(s_der_buffer *p_object_der, s_common_key_attrs *p_key_attrs);

/*! \brief Декодирование информации о получателях данных из DER последовательности. */
int pkcs_15_get_recipient_infos(s_der_buffer *p_enveloped_data_der, s_enveloped_data *p_enveloped_data);

/*! \brief Декодирование информации о конкретном получателе данных из DER последовательности. */
int pkcs_15_get_sngl_recipient_info(s_der_buffer *p_recipient_infos_der, s_recipient_info *p_sngl_recipient_info);

/*! \brief Декодирование информации о шифровании ключа CEK из DER последовательности. */
int pkcs_15_get_kekri(s_der_buffer *p_recipient_infos_der, s_kekri *p_kekri);

/*! \brief Декодирование информации об алгоритме шифрования ключа CEK из DER последовательности. */
int pkcs_15_get_key_encryption_algorithm(s_der_buffer *p_kekri_der, s_kekri *p_kekri);

/*! \brief Декодирование информации о зашифрованных данных из DER последовательности. */
int pkcs_15_get_encrypted_content_info(s_der_buffer *p_enveloped_data_der, s_enveloped_data *p_enveloped_data);

/*! \brief Декодирование информации об алгоритме шифрования данных (контента) из DER последовательности. */
int pkcs_15_get_content_encryption_algorithm(s_der_buffer *p_encrypted_content_info_der,
                                             s_enveloped_data *p_enveloped_data);

/*! \brief Освобождение памяти. */
void pkcs_15_free_key_info(s_key_info *p_ki);

void pkcs_15_free_enveloped_data(s_enveloped_data *p_ed);

void pkcs_15_free_recipient_info(s_recipient_info *p_ri);

void pkcs_15_free_kekri(s_kekri *p_kekri);

void pkcs_15_free_common_key_attrs(s_common_key_attrs *p_cka);

void pkcs_15_free_common_obj_attrs(s_common_obj_attrs *p_coa);

#endif /* __AK_PKCS_CMN_TYPES_H__ */

