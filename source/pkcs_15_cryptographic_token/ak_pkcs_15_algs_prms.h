/* ----------------------------------------------------------------------------------------------- */
/*  Файл ak_pkcs_15_algs_prms.h определяет набор структур, которые используются для                        */
/*  хранения параметров различных алгоритмов.                                                      */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_ALG_PRMS_H__
#define __AK_ALG_PRMS_H__

#include <pkcs_15_cryptographic_token/ak_pkcs_15_common_types.h>

/*! \brief Перечисление, определяющее тип используемого набора параметров. */
typedef enum {
    /*! \brief набор параметров, использующийся в алгоритме шифрования контента */
    GOST_CONTENT_ENC_SET = 1, // соответствует структуре s_gost28147_89_prms
    /*! \brief набор параметров, использующийся в алгоритме шифрования ключа */
    GOST_KEY_WRAP_SET = 2, // соответствует структуре s_gost28147_89_key_wrap_prms
} en_param_set_type;

/*! \brief Структура, хранящая парметры для алгоритма шифрования контента. */
typedef struct {
    /*! \brief вектор инициализации */
    octet_string m_iv;
    /*! \brief идентификатор набора параметров */
    object_identifier m_encryption_param_set;
} s_gost28147_89_prms;

/*! \brief Структура, хранящая парметры для алгоритма шифрования ключа. */
typedef struct {
    /*! \brief идентификатор набора параметров */
    object_identifier m_enc_prm_set;
    /*! \brief некоторый случайный вектор рамером 8 байт */
    octet_string m_ukm;
} s_gost28147_89_key_wrap_prms;

/*! \brief Структура для хранения конкретного набора параметров. */
typedef union {
    /*! \brief набор параметров, использующийся в алгоритме шифрования контента */
    s_gost28147_89_prms *p_content_enc_prm_set;
    /*! \brief набор параметров, использующийся в алгоритме шифрования ключа */
    s_gost28147_89_key_wrap_prms *p_key_wrap_set;
} u_param_set;

/* В данной версии не используется */
//typedef struct {
//    octet_string m_e_uz;
//    integer m_mode;
//    integer m_shift_bits;
//    s_algorithm_identifier* mp_key_meshing;
//} s_gost28147_89_param_set_parameters;

#endif //__AK_ALG_PRMS_H__
