/* ----------------------------------------------------------------------------------------------- */
/*  Файле ak_pkcs_15_gost_secret_key.h содержит структуру, хранящую информацию о секретном ключе,  */
/*  а также методы по кодировани и декодированию данной информации.                                */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_PKCS_GOST_SEC_KEY_H__
#define __AK_PKCS_GOST_SEC_KEY_H__

#include "kc_includes.h"
#include <pkcs_15_cryptographic_token/ak_pkcs_15_common_types.h>
#include <pkcs_15_cryptographic_token/ak_pkcs_15_algs_prms.h>

/*! \brief Секретный ключ блочного алгоритма шифрования. */
typedef struct {
    /*! \brief Идентификатор алгоритмя, для которого предназначен ключ. */
    object_identifier m_key_type_gost;
    /*! \brief Общие атрибуты объекта PKCS 15. */
    s_common_obj_attrs m_obj_attrs;
    /*! \brief Общие атрибуты ключа. */
    s_common_key_attrs m_key_attrs;
    /*! \brief Размер ключа. */
    integer m_key_len;
    /*! \brief Структура, содержащая зашифрованное значение
               ключа и информацию о шифровании. */
    s_enveloped_data m_enveloped_data;
    /*! \brief Параметры алгоритма, в котором используется ключ. */
    /*
     * Поскольку предполагается хранение ключей для алгоритмов из ГОСТ 34.11-2015,
     * то данная структура закомментирована в реализации (параметры имеют фиксированное значение).
     * Методы по заполнению данной структуры также закомментированы.
    */
    //s_key_info m_key_info;
} s_gost_sec_key;

/** Методы добавления данных **/

/*! \brief Добавление секретного ключа в DER последовательность. */
int pkcs_15_put_gost_key(s_der_buffer *p_pkcs_15_token_der, s_gost_sec_key *p_key, s_der_buffer *p_gost_key_der);

/*! \brief Добавление всех атрибутов секретного ключа в DER последовательность. */
int pkcs_15_put_key_attr(s_der_buffer *p_pkcs_15_token_der, s_gost_sec_key *p_key, s_der_buffer *p_key_attr_der);

/*! \brief Добавление атрибутов объекта PKCS 15 (в данном случае секретного ключа) в DER последовательность. */
int pkcs_15_put_gost_secret_key_attributes(s_der_buffer *p_pkcs_15_token_der,
                                           s_gost_sec_key *p_key,
                                           s_der_buffer *p_gost_secret_key_attributes_der);

/*! \brief Добавление общего атрибута (размера) секретного ключа в DER последовательность. */
int pkcs_15_put_common_secret_key_attributes(s_der_buffer *p_pkcs_15_token_der,
                                             s_gost_sec_key *p_key,
                                             s_der_buffer *p_common_secret_key_attributes_der);

/*! \brief Добавление параметров алгоритма, в котором исползуется секретный ключ, в DER последовательность. */
int pkcs_15_put_key_info(s_der_buffer *p_pkcs_15_token_der, s_key_info *p_key_info, s_der_buffer *p_key_info_der);

/*! \brief Преобразование ключа, маски, счетчика ресурса в DER последовательность. (Используется во время заполнения структуры s_enveloped_data)*/
int pkcs_15_make_gost_key_value_mask(ak_buffer masked_key, ak_buffer mask, ssize_t counter, ak_buffer gost_kvm_der);

/*! \brief Преобразование ключа, маскив в DER последовательность. (Используется во время заполнения структуры s_recipient_info)*/
int pkcs_15_make_enc_key_plus_mac_seq(ak_buffer encrypted_cek, ak_buffer mac, ak_buffer encrypted_key_der);

/** Методы декодирования данных **/

/*! \brief Декодирование секретного ключа из DER последовательности. */
int pkcs_15_get_gost_key(s_der_buffer *p_object_der, s_gost_sec_key *p_key);

/*! \brief Декодирование всех атрибутов секретного ключа из DER последовательности. */
int pkcs_15_get_key_attr(s_der_buffer *p_key_der, s_gost_sec_key *p_key);

/*! \brief Декодирование атрибутов объекта PKCS 15 (в данном случае секретного ключа) из DER последовательности. */
int pkcs_15_get_common_secret_key_attributes(s_der_buffer *p_key_der, s_gost_sec_key *p_key);

/*! \brief Декодирование общего атрибута (размера) секретного ключа из DER последовательности. */
int pkcs_15_get_gost_secret_key_attributes(s_der_buffer *p_key_der, s_gost_sec_key *p_key);

/*! \brief Декодирование параметров алгоритма, в котором исползуется секретный ключ, из DER последовательности. */
int pkcs_15_get_key_info(s_der_buffer *p_key_der, s_key_info *p_key_info);

/*! \brief Декодирование ключа, маски, счетчика ресурса из DER последовательности. */
int pkcs_15_parse_gost_key_value_mask(ak_buffer gost_kvm_der, ak_buffer masked_key, ak_buffer mask, ssize_t *counter);

/*! \brief Декодирование ключа, маскив из DER последовательности. */
int pkcs_15_parse_enc_key_plus_mac_seq(octet_string encrypted_key_der, ak_buffer p_encrypted_cek, ak_buffer p_mac);

//todo: обдумать название метода (заменить gost28147_89)
int pkcs_15_put_gost28147_89_prms(s_der_buffer *p_pkcs_15_token_der, s_gost28147_89_prms *p_params,
                                  s_der_buffer *p_params_der);

void pcks_15_free_gost_sec_key(s_gost_sec_key *key);

#endif /* __AK_PKCS_GOST_SEC_KEY_H__ */
