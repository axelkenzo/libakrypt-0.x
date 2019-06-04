/* ----------------------------------------------------------------------------------------------- */
/*  Файле ak_pkcs_15_token.h содержит структуру, хранящую информацию о контейнере и объектах       */
/*  контейнера, а также методы по кодировани и декодированию данных.                               */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_TOKEN_H__
#define __AK_TOKEN_H__

#include "ak_pkcs_15_gost_secret_key.h"

/*! \brief Перечисление, определяющее тип ключа. */
typedef enum {
    /*! \brief приватный ключ */
            PRI_KEY = 0,
    /*! \brief публичный ключ */
            PUB_KEY = 1,
    /*! \brief секретный ключ */
            SEC_KEY = 3
} en_obj_type;

/*! \brief Структура, хранящая информацию о ключе. */
typedef union {
    /*! \brief указатель на секретный ключ */
    s_gost_sec_key *mp_sec_key;
    /*TODO: комментарий для Алексея Юрьевича: сюда необходимо добавить информацию
            о приватных и публичных ключах.*/
} u_pkcs_15_object;

/*! \brief Структура, хранящая указатель на объект ключа и тип ключа. */
typedef struct {
    /*! \brief тип ключа */
    en_obj_type m_type;
    /*! \brief ключ */
    u_pkcs_15_object m_obj;
} s_pkcs_15_object;

/*! \brief Структура, хранящая информацию об алгоритме выработки ключа из пароля. */
typedef struct {
    /*! \brief подсказка для пароля */
    utf8_string m_hint;
    /*! \brief идентификатор алгоритма диверсификации ключа (всегда используется алгоритм PBKDF2) */
    object_identifier m_algorithm;
    /*! \brief соль */
    octet_string m_salt;
    /*! \brief количество итерации */
    integer m_iteration_count;
    /*! \brief длина вырабатываемого ключа */
    integer m_key_len;
    /*! \brief идентификатор хеш функции, используемой в алгоритме */
    object_identifier m_prf_id;
} s_pwd_info;

/*! \brief Структура, хранящая информацию о способе получения ключа KEK. */
typedef union {
    /*! \brief информация для алгоритма выработки ключа из пароля */
    s_pwd_info *mp_pwd_info;
    /*! \brief информация о шифровании ключа CEK */
    s_kekri *mp_kekri;
    /*TODO: комментарий для Алексея Юрьевича: при необходимости, сюда следует добавить вариант Password Recipient Info.
            Его реализация, к сожалению, отсутствует.*/
} u_key_info_kmi;

/*! \brief Структура, хранящая информацию о способе получения ключа KEK и его идентификатор. */
typedef struct {
    /*! \brief уникальный идентификатор ключа */
    octet_string m_key_id;
    /*! \brief тип информации */
    en_pr_info m_type;
    /*! \brief информация о ключе KEK */
    u_key_info_kmi m_key_info;
} s_key_management_info;

/*! \brief Структура, представляющая контейнер. */
typedef struct {
    /*! \brief версия */
    integer m_version;
    /*! \brief массив указателей на информацию о выработке ключа KEK */
    s_key_management_info **mpp_key_infos;
    /*! \brief количество элементов в массиве mpp_key_infos */
    uint8_t m_info_size;
    /*! \brief массив указателей на объекты PKCS 15 Objects */
    s_pkcs_15_object **mpp_pkcs_15_objects;
    /*! \brief количество элементов в массиве mpp_pkcs_15_objects */
    uint8_t m_obj_size;
} s_pkcs_15_token;

/** Методы добавления данных **/

/*! \brief Метод по сбору контейнера в DER последовательность. */
int pkcs_15_generate_token(s_pkcs_15_token *p_pkcs_15_token, byte **pp_data, size_t *p_size);

/*! \brief Добавление объектов в DER последовательность. */
int pkcs_15_put_pkcs_objects(s_der_buffer *p_pkcs_15_token,
                             s_pkcs_15_object **pp_pkcs_15_objects,
                             int8_t size,
                             s_der_buffer *p_pkcs_15_object_der);

/*! \brief Добавление конкретного объекта в DER последовательность. */
int pkcs_15_put_obj(s_der_buffer *p_pkcs_15_token,
                    s_pkcs_15_object *p_pkcs_15_object,
                    s_der_buffer *p_added_pkcs_15_object_der);

/*! \brief Добавление объекта в открытом виде в DER последовательность. */
int pkcs_15_put_obj_direct(s_der_buffer *p_pkcs_15_token,
                           s_pkcs_15_object *p_pkcs_15_object,
                           s_der_buffer *p_direct_pkcs_15_object_der);

/*! \brief Добавление информации о выработке ключа KEK в DER последовательность. */
int pkcs_15_put_key_management_info(s_der_buffer *p_pkcs_15_token,
                                    s_key_management_info *p_key_management_info,
                                    s_der_buffer *p_key_management_info_der);

/*! \brief Добавление информации о выработке ключа KEK из пароля в DER последовательность. */
int pkcs_15_put_password_info(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_pwd_info_der);

/*! \brief Добавление информации об алгоритме выработки ключа из пароля в DER последовательность. */
int pkcs_15_put_alg_id(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_alg_id_der);

/*! \brief Добавление информации о параметрах алгоритма PBKDF2 в DER последовательность. */
int pkcs_15_put_params_pbkdf2(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_parameters_der);

/** Методы декодирования данных **/

/*! \brief Метод по разбору DER последовательности, представляющую контейнер ключевой информации. */
int pkcs_15_parse_token(byte *p_data, size_t size, s_pkcs_15_token *p_pkcs_15_token);

/*! \brief Декодирование объектов контейнера из DER последовательности. */
int pkcs_15_get_pkcs_objects(s_der_buffer *p_pkcs_15_token_der, s_pkcs_15_token *p_pkcs_15_token);

/*! \brief Декодирование конкретного объекта из DER последовательности. */
int pkcs_15_get_obj(s_der_buffer *p_pkcs_15_objects_der, s_pkcs_15_object *p_pkcs_15_object);

/*! \brief Декодирование объекта,представленного в открытом виде, из DER последовательности. */
int pkcs_15_get_direct_obj(s_der_buffer *p_pkcs_15_object_der, s_pkcs_15_object *p_pkcs_15_object);

/*! \brief Декодирование информации о выработке ключа KEK из DER последовательности. */
int pkcs_15_get_key_management_info(s_der_buffer *p_pkcs_15_token_der, s_pkcs_15_token *p_pkcs_15_token);

/*! \brief Декодирование информации о выработке ключа KEK из пароля из DER последовательности. */
int pkcs_15_get_sngl_kmi(s_der_buffer *p_key_management_info_der, s_pkcs_15_token *p_pkcs_15_token);

/*! \brief Декодирование информации о выработке ключа KEK из пароля из DER последовательности. */
int pkcs_15_get_password_info(s_der_buffer *p_sngl_kmi_der, s_pwd_info *p_pwd_info);

/*! \brief Декодирование информации об алгоритме выработки ключа из пароля из DER последовательности. */
int pkcs_15_get_alg_id(s_der_buffer *p_pwd_info_der, s_pwd_info *p_pwd_info);

/*! \brief Декодирование информации о параметрах алгоритма PBKDF2 из DER последовательности. */
int pkcs_15_get_params_pbkdf2(s_der_buffer *p_alg_id_der, s_pwd_info *p_pwd_info);

/*! \brief Освобождение памяти. */
void free_pkcs_15_token(s_pkcs_15_token *p_pkcs_15_token);

void free_key_management_info(s_key_management_info *p_kmi);

void free_pwd_info(s_pwd_info *p_pwd_info);

void free_pkcs_15_object(s_pkcs_15_object *p_object);

#endif //__AK_TOKEN_H__
