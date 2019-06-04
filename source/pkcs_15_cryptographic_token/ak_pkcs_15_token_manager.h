/* ----------------------------------------------------------------------------------------------- */
/*  Файл ak_pkcs_15_token_manager.h содержит описание структуры, представляющие расширенный объект */
/*  ключа, а так же методы по добавлению/извлечению ключей в/из контейнер/контейнера.              */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_TKN_MNG_H__
#define __AK_TKN_MNG_H__

#include <ak_bckey.h>
#include <ak_context_manager.h>
#include <pkcs_15_cryptographic_token/ak_pkcs_15_gost_secret_key.h>
#include <pkcs_15_cryptographic_token/ak_pkcs_15_token.h>

/*! \brief Тип, используемый для хранения даты и времени. */
typedef unsigned int date[6];

/*! \brief Струкртура, хранящая контекст ключа. */
union kc_key {
    /*! \brief контекст секретного ключа */
    ak_bckey sec_key;
    /*TODO: комментарий для Алексея Юрьевича: сюда необходимо добавить структуры,
            соответствующие приватным и публичным ключам. */
};

/*! \brief Струкртура, хранящая контекст ключа и дополнительные параметры. */
struct extended_key {

    /*TODO: комментарий для Алексея Юрьевича: на наш взгляд, имеет смысл перенести
            все дополнительные атрибуты в структуру skey. */

    /*! \brief объект ключа */
    union kc_key key;
    /*! \brief тип ключа */
    en_obj_type key_type; // enPrivKey = 0, enPubKey = 1, enSecKey = 3
    /*! \brief название ключа понятное человеку */
    ak_pointer label;
    /*! \brief начало периода действия ключа */
    date start_date;
    /*! \brief конец периода действия ключа */
    date end_date;
    /*! \brief флаги, определяющие предназначения ключа */
    key_usage_flags_t flags;
};

/*! \brief Метод для считывания ключей из контейнера. */
int read_keys_from_container(byte *password,
                             size_t pwd_size,
                             byte *inp_container,
                             size_t inp_container_size,
                             struct extended_key ***out_keys,
                             ak_uint8 *num_of_out_keys);

/*! \brief Метод для записи ключей в контейнер. */
int write_keys_to_container(struct extended_key **pp_inp_keys,
                            ak_uint8 num_of_inp_keys,
                            ak_pointer password,
                            size_t password_size,
                            byte **pp_out_container,
                            size_t *p_out_container_size);

/*! \brief Метод для преобразования флагов предназначения ключа в удобочитаемую строку. */
char *key_usage_flags_to_str(key_usage_flags_t flags);

#endif //__AK_TKN_MNG_H__



