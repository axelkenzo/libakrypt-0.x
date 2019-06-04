#include "ak_pkcs_15_token.h"

int pkcs_15_generate_token(s_pkcs_15_token *p_pkcs_15_token, byte **pp_data, size_t *p_size) {
    int error;
    s_der_buffer pkcs_token_der;
    s_der_buffer objects;
    s_der_buffer key_management_info;
    s_der_buffer token_ver;
    size_t token_len;

    memset(&pkcs_token_der, 0, sizeof(s_der_buffer));
    memset(&objects, 0, sizeof(s_der_buffer));
    memset(&key_management_info, 0, sizeof(s_der_buffer));
    memset(&token_ver, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !pp_data || !p_size)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    ps_alloc(&pkcs_token_der, 2000, PS_W_MODE);

    if (p_pkcs_15_token->mpp_pkcs_15_objects && p_pkcs_15_token->m_obj_size)
    {
        if ((error = pkcs_15_put_pkcs_objects(&pkcs_token_der,
                                              p_pkcs_15_token->mpp_pkcs_15_objects,
                                              p_pkcs_15_token->m_obj_size,
                                              &objects)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding objects");
    }
    else
        return ak_error_message(ak_error_invalid_value, __func__, "objects absent");


    if (p_pkcs_15_token->m_info_size != 0)
    {
        size_t key_management_info_len = 0;
        if (!p_pkcs_15_token->mpp_key_infos)
            return ak_error_message(ak_error_null_pointer, __func__, "key management info absent");

        for (uint8_t i = 0; i < p_pkcs_15_token->m_info_size; i++)
        {
            s_der_buffer sngl_key_management_info;
            memset(&sngl_key_management_info, 0, sizeof(s_der_buffer));
            if (!p_pkcs_15_token->mpp_key_infos[i])
                return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to key management info");

            if ((error = pkcs_15_put_key_management_info(&pkcs_token_der, p_pkcs_15_token->mpp_key_infos[i],
                                                         &sngl_key_management_info)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with adding key management info");

            key_management_info_len += ps_get_full_size(&sngl_key_management_info);
        }

        if (key_management_info_len)
        {
            if ((error = ps_move_cursor(&pkcs_token_der, asn_get_len_byte_cnt(key_management_info_len) + 1)) !=
                ak_error_ok)
                return ak_error_message(error, __func__, "problems with moving cursor");

            asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 0u, pkcs_token_der.mp_curr);

            if ((error = asn_put_len(key_management_info_len, pkcs_token_der.mp_curr + 1)) != ak_error_ok)
                return ak_error_message_fmt(error, __func__, "problem with adding key management info length");

            if ((error = ps_set(&key_management_info, pkcs_token_der.mp_curr, key_management_info_len
                                                                              +
                                                                              asn_get_len_byte_cnt(
                                                                                      key_management_info_len) +
                                                                              1, PS_U_MODE)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with making union of asn data");
        }
    }

    if ((error = asn_put_universal_tlv(TINTEGER, (void *) &p_pkcs_15_token->m_version, 0, &pkcs_token_der, &token_ver))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding token version");

    token_len = ps_get_full_size(&objects) +
                ps_get_full_size(&key_management_info) +
                ps_get_full_size(&token_ver);

    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, token_len, &pkcs_token_der, &token_ver)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    *p_size = (size_t) ps_get_curr_size(&pkcs_token_der);
    *pp_data = (byte *) calloc(*p_size, sizeof(byte));
    memcpy(*pp_data, pkcs_token_der.mp_curr, *p_size);

    free(pkcs_token_der.mp_begin);

    return error;
}

int pkcs_15_put_pkcs_objects(s_der_buffer *p_pkcs_15_token, s_pkcs_15_object **pp_pkcs_15_objects, int8_t size,
                             s_der_buffer *p_pkcs_15_object_der) {
    int error;
    size_t objects_len;

    if (!p_pkcs_15_token || !pp_pkcs_15_objects || !size || !p_pkcs_15_object_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    objects_len = 0;
    for (int8_t i = 0; i < size; i++)
    {
        s_der_buffer added_object;

        if (!pp_pkcs_15_objects[i])
            return ak_error_message(ak_error_null_pointer, __func__, "object absent");

        memset(&added_object, 0, sizeof(s_der_buffer));
        if ((error = pkcs_15_put_obj(p_pkcs_15_token, pp_pkcs_15_objects[i], &added_object)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding object");
        objects_len += ps_get_full_size(&added_object);
    }

    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, objects_len, p_pkcs_15_token, p_pkcs_15_object_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return ak_error_ok;
}

int pkcs_15_put_obj(s_der_buffer *p_pkcs_15_token,
                    s_pkcs_15_object *p_pkcs_15_object,
                    s_der_buffer *p_added_pkcs_15_object_der) {
    int error;
    s_der_buffer direct_object;
    size_t direct_object_len;

    memset(&direct_object, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_pkcs_15_object || !p_added_pkcs_15_object_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    if ((error = pkcs_15_put_obj_direct(p_pkcs_15_token, p_pkcs_15_object, &direct_object)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with adding object direct");

    direct_object_len = ps_get_full_size(&direct_object);
    if ((error = ps_move_cursor(p_pkcs_15_token, asn_get_len_byte_cnt(direct_object_len) + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    switch (p_pkcs_15_object->m_type)
    {
        case SEC_KEY:
            asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 3u, p_pkcs_15_token->mp_curr);
            break;
        case PRI_KEY:
            return ak_error_message(ak_error_invalid_value, __func__, "adding private keys does not realized yet");
        case PUB_KEY:
            return ak_error_message(ak_error_invalid_value, __func__, "adding public keys does not realized yet");
        default:
            return ak_error_message(ak_error_invalid_value, __func__, "unknown type of object");
    }

    if ((error = asn_put_len(direct_object_len, p_pkcs_15_token->mp_curr + 1)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "problem with adding object length");

    if ((error = ps_set(p_added_pkcs_15_object_der,
                        p_pkcs_15_token->mp_curr,
                        direct_object_len + asn_get_len_byte_cnt(direct_object_len) + 1,
                        PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return error;
}

int pkcs_15_put_obj_direct(s_der_buffer *p_pkcs_15_token,
                           s_pkcs_15_object *p_pkcs_15_object,
                           s_der_buffer *p_direct_pkcs_15_object_der) {
    int error;
    s_der_buffer gost_key;
    size_t gost_key_len;

    memset(&gost_key, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_pkcs_15_object || !p_direct_pkcs_15_object_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    switch (p_pkcs_15_object->m_type)
    {
        case SEC_KEY:
            if ((error = pkcs_15_put_gost_key(p_pkcs_15_token, p_pkcs_15_object->m_obj.mp_sec_key, &gost_key)) !=
                ak_error_ok)
                return ak_error_message(error, __func__, "problems with adding gost key");
            break;
        case PRI_KEY:
            return ak_error_message(ak_error_invalid_value, __func__, "adding private keys does not realized yet");
        case PUB_KEY:
            return ak_error_message(ak_error_invalid_value, __func__, "adding public keys does not realized yet");
        default:
            return ak_error_message(ak_error_invalid_value, __func__, "unknown type of object");
    }

    gost_key_len = (size_t) ps_get_full_size(&gost_key);

    if ((error = ps_move_cursor(p_pkcs_15_token, asn_get_len_byte_cnt(gost_key_len) + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 0u, p_pkcs_15_token->mp_curr);

    if ((error = asn_put_len(gost_key_len, p_pkcs_15_token->mp_curr + 1)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "problem with adding gost key length");

    if ((error = ps_set(p_direct_pkcs_15_object_der, p_pkcs_15_token->mp_curr,
                        gost_key_len + asn_get_len_byte_cnt(gost_key_len) + 1, PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return error;
}

int pkcs_15_put_key_management_info(s_der_buffer *p_pkcs_15_token, s_key_management_info *p_key_management_info,
                                    s_der_buffer *p_key_management_info_der) {
    int error = ak_error_ok;
    s_der_buffer key_info;
    s_der_buffer key_id;

    memset(&key_info, 0, sizeof(s_der_buffer));
    memset(&key_id, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_key_management_info || !p_key_management_info_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (p_key_management_info->m_key_id.m_val_len > 255)
        return ak_error_message(ak_error_wrong_length, __func__, "key id length can't be more than 255 bytes");


    switch (p_key_management_info->m_type)
    {
        case PWD_INFO:
            if ((error = pkcs_15_put_password_info(p_pkcs_15_token, p_key_management_info->m_key_info.mp_pwd_info,
                                                   &key_info))
                != ak_error_ok)
                return ak_error_message(error, __func__, "problems with adding password info");
            break;
        case KEKRI:
            return ak_error_message(ak_error_invalid_value,
                                    __func__,
                                    "adding kekri into key management info does not realized yet");
        case PWRI:
            return ak_error_message(ak_error_invalid_value,
                                    __func__,
                                    "adding pwri into key management info does not realized yet");
    }


    if ((error = asn_put_universal_tlv(TOCTET_STRING, (void *) &p_key_management_info->m_key_id, 0, p_pkcs_15_token,
                                       &key_id))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding key id");

    int key_management_info_len = ps_get_full_size(&key_info) + ps_get_full_size(&key_id);
    if ((error =
                 asn_put_universal_tlv(TSEQUENCE, NULL, key_management_info_len, p_pkcs_15_token,
                                       p_key_management_info_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

int pkcs_15_put_password_info(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_pwd_info_der) {
    int error;
    s_der_buffer alg_id;
    s_der_buffer hint;
    size_t password_info_len;

    memset(&alg_id, 0, sizeof(s_der_buffer));
    memset(&hint, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_pwd_info || !p_pwd_info_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    if ((error = pkcs_15_put_alg_id(p_pkcs_15_token, p_pwd_info, &alg_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with adding algorithm id");


    if (p_pwd_info->m_hint != NULL)
    {
        if ((error = asn_put_universal_tlv(TUTF8_STRING, (void *) &p_pwd_info->m_hint, 0, p_pkcs_15_token, &hint))
            != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding password hint");
    }

    password_info_len = ps_get_full_size(&alg_id) + ps_get_full_size(&hint);

    if ((error = ps_move_cursor(p_pkcs_15_token, asn_get_len_byte_cnt(password_info_len) + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 0u, p_pkcs_15_token->mp_curr);

    if ((error = asn_put_len(password_info_len, p_pkcs_15_token->mp_curr + 1)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "problem with adding gost key length");

    if ((error = ps_set(p_pwd_info_der,
                        p_pkcs_15_token->mp_curr,
                        password_info_len + asn_get_len_byte_cnt(password_info_len) + 1,
                        PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return error;
}

int pkcs_15_put_alg_id(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_alg_id_der) {
    int error;
    s_der_buffer params_pbkdf2;
    s_der_buffer algorithm;
    size_t alg_id_len;

    memset(&params_pbkdf2, 0, sizeof(s_der_buffer));
    memset(&algorithm, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_pwd_info || !p_alg_id_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (!p_pwd_info->m_algorithm)
        return ak_error_message(ak_error_null_pointer, __func__, "algorithm oid absent");


    if (p_pwd_info->m_salt.mp_value != NULL)
    {
        if ((error = pkcs_15_put_params_pbkdf2(p_pkcs_15_token, p_pwd_info, &params_pbkdf2)) != ak_error_ok)
        {
            return ak_error_message(error, __func__, "problems with adding algorithm id");
        }
    }

    /*
     * При выработке ключа из пароля всегда
     * используется схема PBKDF2
     */
    if (0 != strcmp(p_pwd_info->m_algorithm, "1.2.840.113549.1.5.12"))
        return ak_error_message_fmt(ak_error_wrong_oid,
                                    __func__,
                                    "algorithm (%s) is prohibited and must be other (%s)",
                                    p_pwd_info->m_prf_id,
                                    "1.2.840.113549.1.5.12");

    if ((error =
                 asn_put_universal_tlv(TOBJECT_IDENTIFIER, (void *) &p_pwd_info->m_algorithm, 0, p_pkcs_15_token,
                                       &algorithm))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding algorithm oid");

    alg_id_len = ps_get_full_size(&params_pbkdf2) + ps_get_full_size(&algorithm);
    if ((error = asn_put_universal_tlv(TSEQUENCE, 0, alg_id_len, p_pkcs_15_token, p_alg_id_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

int pkcs_15_put_params_pbkdf2(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_parameters_der) {
    int error = ak_error_ok;
    s_der_buffer prf;
    s_der_buffer key_length;
    s_der_buffer iteration_count;
    s_der_buffer salt;
    size_t parameters_len;

    memset(&prf, 0, sizeof(s_der_buffer));
    memset(&key_length, 0, sizeof(s_der_buffer));
    memset(&iteration_count, 0, sizeof(s_der_buffer));
    memset(&salt, 0, sizeof(s_der_buffer));


    if (!p_pkcs_15_token || !p_pwd_info || !p_parameters_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (p_pwd_info->m_salt.mp_value == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "salt absent");;

    if (p_pwd_info->m_iteration_count.mp_value == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "iteration count absent");;

    if (!p_pwd_info->m_prf_id)
        return ak_error_message(ak_error_null_pointer, __func__, "prf oid absent");

    /*
     * При выработке ключа по схеме PBKDF2
     * всегда должен использоваться алгоритм
     * HMAC на основе ГОСТ Р 34.11-2012 с ключом 512.
     * При этом поле prf.parameters = NULL.
     * (см. Р 50.1.111-2016 пункт 7.1)
     */
    if (0 != strcmp(p_pwd_info->m_prf_id, "1.2.643.7.1.1.4.2"))
        return ak_error_message_fmt(ak_error_wrong_oid,
                                    __func__,
                                    "algorithm (%s) is prohibited and must be other (%s)",
                                    p_pwd_info->m_prf_id,
                                    "1.2.643.7.1.1.4.2");
    else
    {
        s_der_buffer algorithm;
        memset(&algorithm, 0, sizeof(s_der_buffer));
        if ((error =
                     asn_put_universal_tlv(TOBJECT_IDENTIFIER, (void *) &p_pwd_info->m_prf_id, 0, p_pkcs_15_token,
                                           &algorithm))
            != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding algorithm oid");

        size_t prf_len = ps_get_full_size(&algorithm);
        if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, prf_len, p_pkcs_15_token, &prf)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    }


    if (p_pwd_info->m_key_len.mp_value != NULL)
    {
        if ((error = asn_put_universal_tlv(TINTEGER, (void *) &p_pwd_info->m_key_len, 0, p_pkcs_15_token, &key_length))
            != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key length");
    }


    if ((error = asn_put_universal_tlv(TINTEGER,
                                       (void *) &p_pwd_info->m_iteration_count,
                                       0,
                                       p_pkcs_15_token,
                                       &iteration_count)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding iteration count");

    /*
     * Значение соли всегда представляется
     * в виде строки октетов
     */

    if ((error = asn_put_universal_tlv(TOCTET_STRING, (void *) &p_pwd_info->m_salt, 0, p_pkcs_15_token, &salt))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding salt");

    parameters_len = ps_get_full_size(&prf) +
                     ps_get_full_size(&key_length) +
                     ps_get_full_size(&iteration_count) +
                     ps_get_full_size(&salt);

    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, parameters_len, p_pkcs_15_token, p_parameters_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    //TODO: Дописать реализацию;

    return 0;
}

/*            ------------- Parser -------------            */



int pkcs_15_parse_token(byte *p_data, size_t size, s_pkcs_15_token *p_pkcs_15_token) {
    int error;
    tag tag;
    size_t len;
    uint8_t len_byte_cnt;
    s_der_buffer token;

    tag = 0;
    len = 0;
    len_byte_cnt = 0;
    memset(&token, 0, sizeof(s_der_buffer));


    if (!p_data || !size || !p_pkcs_15_token)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    asn_get_tag(p_data, &tag);
    if (tag != (CONSTRUCTED | TSEQUENCE))
        return ak_error_invalid_token;

    if ((error = asn_get_len(p_data + 1, &len, &len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting data length");

    if ((error = ps_set(&token, p_data + 1 + len_byte_cnt, len, PS_R_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with setting pointer server");

    if ((error = asn_get_expected_tlv(TINTEGER, &token, (void *) &p_pkcs_15_token->m_version)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting token version");

    asn_get_tag(token.mp_curr, &tag);
    if (tag == (CONTEXT_SPECIFIC | CONSTRUCTED | 0u))
    {
        if ((error = pkcs_15_get_key_management_info(&token, p_pkcs_15_token)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting key management info");
    }

    if ((error = pkcs_15_get_pkcs_objects(&token, p_pkcs_15_token)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting pkcs 15 objects");

    if (ps_get_curr_size(&token) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_key_management_info(s_der_buffer *p_pkcs_15_token_der, s_pkcs_15_token *p_pkcs_15_token) {
    int error;
    uint8_t num_of_kmi_objs;
    s_der_buffer key_management_info;

    num_of_kmi_objs = 0;
    memset(&key_management_info, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token_der || !p_pkcs_15_token)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    if ((error = asn_get_expected_tlv((CONTEXT_SPECIFIC | CONSTRUCTED | 0u), p_pkcs_15_token_der,
                                      (void *) &key_management_info)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting token version");

    if ((error = asn_get_num_of_elems_in_constructed_obj(&key_management_info, &num_of_kmi_objs)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting num of elements in constructed data object");

    p_pkcs_15_token->m_info_size = 0;
    p_pkcs_15_token->mpp_key_infos = calloc(num_of_kmi_objs, sizeof(s_key_management_info *));
    if (!p_pkcs_15_token->mpp_key_infos)
        return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

    while (ps_get_curr_size(&key_management_info))
    {
        if ((error = pkcs_15_get_sngl_kmi(&key_management_info, p_pkcs_15_token)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting single key management info");
    }

    if (ps_get_curr_size(&key_management_info) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_sngl_kmi(s_der_buffer *p_key_management_info_der, s_pkcs_15_token *p_pkcs_15_token) {
    int error;
    tag tag;
    size_t len;
    uint8_t len_byte_cnt;
    s_key_management_info *p_sngl_kmi;
    s_der_buffer sngl_info;

    tag = 0;
    len = 0;
    len_byte_cnt = 0;
    memset(&sngl_info, 0, sizeof(s_der_buffer));


    if (!p_key_management_info_der || !p_pkcs_15_token)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_sngl_kmi = calloc(1, sizeof(s_key_management_info));
    if (!p_sngl_kmi)
        return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

    if ((error = asn_get_expected_tlv((CONSTRUCTED | TSEQUENCE), p_key_management_info_der, (void *) &sngl_info))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting single key management info in der");

    if ((error = asn_get_expected_tlv(TOCTET_STRING, &sngl_info, (void *) &p_sngl_kmi->m_key_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key id");

    asn_get_tag(sngl_info.mp_curr, &tag);

    if (tag == (CONTEXT_SPECIFIC | CONSTRUCTED | PWD_INFO))
    {
        p_sngl_kmi->m_type = PWD_INFO;
        p_sngl_kmi->m_key_info.mp_pwd_info = calloc(1, sizeof(s_pwd_info));
        if (!p_sngl_kmi->m_key_info.mp_pwd_info)
            return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

        if ((error = pkcs_15_get_password_info(&sngl_info, p_sngl_kmi->m_key_info.mp_pwd_info)) != ak_error_ok)
        {
            free(p_sngl_kmi->m_key_info.mp_pwd_info);
            return ak_error_message(error, __func__, "problems with getting password info");
        }
    }
    else if (tag == (CONTEXT_SPECIFIC | CONSTRUCTED | PWRI))
    {
        ak_error_message(ak_error_invalid_value, __func__,
                         "getting pwri into key management info does not realized yet");
        if ((error = asn_get_len(p_key_management_info_der->mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(p_key_management_info_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }
    else if (tag == (CONTEXT_SPECIFIC | CONSTRUCTED | KEKRI))
    {
        ak_error_message(ak_error_invalid_value, __func__,
                         "getting kekri into key management info does not realized yet");
        if ((error = asn_get_len(p_key_management_info_der->mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(p_key_management_info_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }

    if (ps_get_curr_size(&sngl_info) != 0)
        return ak_error_invalid_token;

    p_pkcs_15_token->mpp_key_infos[p_pkcs_15_token->m_info_size] = p_sngl_kmi;
    p_pkcs_15_token->m_info_size++;

    return error;
}

int pkcs_15_get_password_info(s_der_buffer *p_sngl_kmi_der, s_pwd_info *p_pwd_info) {
    int error;
    tag tag;
    s_der_buffer pwd_info;

    tag = 0;

    if (!p_sngl_kmi_der || !p_pwd_info)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    memset(&pwd_info, 0, sizeof(s_der_buffer));
    if ((error = asn_get_expected_tlv((CONTEXT_SPECIFIC | CONSTRUCTED | PWD_INFO), p_sngl_kmi_der, (void *) &pwd_info))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting single key management info in der");

    asn_get_tag(pwd_info.mp_curr, &tag);

    if (tag == TUTF8_STRING)
    {
        if ((error = asn_get_expected_tlv(TUTF8_STRING, &pwd_info, (void *) &p_pwd_info->m_hint)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting password hint");
    }

    if ((error = pkcs_15_get_alg_id(&pwd_info, p_pwd_info)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting algorithm id");

    if (ps_get_curr_size(&pwd_info) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_alg_id(s_der_buffer *p_pwd_info_der, s_pwd_info *p_pwd_info) {
    int error = ak_error_ok;
    s_der_buffer alg_id;

    memset(&alg_id, 0, sizeof(s_der_buffer));


    if (!p_pwd_info_der || !p_pwd_info)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv((CONSTRUCTED | TSEQUENCE), p_pwd_info_der, (void *) &alg_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting algorithm id in der");

    if ((error = asn_get_expected_tlv((TOBJECT_IDENTIFIER), &alg_id, (void *) &p_pwd_info->m_algorithm)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting algorithm identifier");

    if (ps_get_curr_size(&alg_id))
    {
        if ((error = pkcs_15_get_params_pbkdf2(&alg_id, p_pwd_info)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting PBKDF2 parameters");
    }

    if (ps_get_curr_size(&alg_id) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_params_pbkdf2(s_der_buffer *p_alg_id_der, s_pwd_info *p_pwd_info) {
    int error;
    tag tag = 0;
    s_der_buffer pbkdf2_prms;
    s_der_buffer prf_der;

    tag = 0;
    memset(&pbkdf2_prms, 0, sizeof(s_der_buffer));
    memset(&prf_der, 0, sizeof(s_der_buffer));

    if (!p_alg_id_der || !p_pwd_info)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    if ((error = asn_get_expected_tlv((CONSTRUCTED | TSEQUENCE), p_alg_id_der, (void *) &pbkdf2_prms)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting PBKDF2 parameters in der");

    if ((error = asn_get_expected_tlv((TOCTET_STRING), &pbkdf2_prms, (void *) &p_pwd_info->m_salt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting salt");

    if ((error = asn_get_expected_tlv((TINTEGER), &pbkdf2_prms, (void *) &p_pwd_info->m_iteration_count)) !=
        ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting iteration count");

    asn_get_tag(pbkdf2_prms.mp_curr, &tag);
    if (tag == TINTEGER)
    {
        if ((error = asn_get_expected_tlv((TINTEGER), &pbkdf2_prms, (void *) &p_pwd_info->m_key_len)) !=
            ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting key length");
    }

    if ((error = asn_get_expected_tlv((CONSTRUCTED | TSEQUENCE), &pbkdf2_prms, (void *) &prf_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting prf in der");

    if ((error = asn_get_expected_tlv((TOBJECT_IDENTIFIER), &prf_der, (void *) &p_pwd_info->m_prf_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting prf");

    if (ps_get_curr_size(&prf_der) != 0)
        return ak_error_invalid_token;

    if (ps_get_curr_size(&pbkdf2_prms) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_pkcs_objects(s_der_buffer *p_pkcs_15_token_der, s_pkcs_15_token *p_pkcs_15_token) {
    int error;
    s_der_buffer pkcs_15_objects;
    uint8_t num_of_pkcs_15_objects;

    memset(&pkcs_15_objects, 0, sizeof(s_der_buffer));
    num_of_pkcs_15_objects = 0;


    if (!p_pkcs_15_token_der || !p_pkcs_15_token)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    if ((error = asn_get_expected_tlv((CONSTRUCTED | TSEQUENCE), p_pkcs_15_token_der, (void *) &pkcs_15_objects))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting pkcs 15 objects in der");

    if ((error = asn_get_num_of_elems_in_constructed_obj(&pkcs_15_objects, &num_of_pkcs_15_objects)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting num of elements in constructed data object");

    p_pkcs_15_token->m_obj_size = num_of_pkcs_15_objects;
    p_pkcs_15_token->mpp_pkcs_15_objects = calloc(num_of_pkcs_15_objects, sizeof(s_pkcs_15_object *));

    for (size_t i = 0; i < num_of_pkcs_15_objects; i++)
    {
        p_pkcs_15_token->mpp_pkcs_15_objects[i] = calloc(1, sizeof(s_pkcs_15_object));;
        if (!p_pkcs_15_token->mpp_pkcs_15_objects[i])
            return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

        if ((error = pkcs_15_get_obj(&pkcs_15_objects, p_pkcs_15_token->mpp_pkcs_15_objects[i])) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting object");
    }

    if (ps_get_curr_size(&pkcs_15_objects) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_obj(s_der_buffer *p_pkcs_15_objects_der, s_pkcs_15_object *p_pkcs_15_object) {
    int error;
    tag tag;
    size_t len;
    uint8_t len_byte_cnt;
    s_der_buffer pkcs_15_sngl_object_der;

    tag = 0;
    len = 0;
    len_byte_cnt = 0;
    memset(&pkcs_15_sngl_object_der, 0, sizeof(s_der_buffer));


    if (!p_pkcs_15_objects_der || !p_pkcs_15_object)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    asn_get_tag(p_pkcs_15_objects_der->mp_curr, &tag);
    switch (tag)
    {
        case (CONTEXT_SPECIFIC | CONSTRUCTED | SEC_KEY):
            p_pkcs_15_object->m_type = SEC_KEY;
            break;
        case (CONTEXT_SPECIFIC | CONSTRUCTED | PRI_KEY):
            ak_error_message(ak_error_invalid_value,
                             __func__,
                             "getting private key does not realized yet");
            if ((error = asn_get_len(p_pkcs_15_objects_der->mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting data length");

            if ((error = ps_move_cursor(p_pkcs_15_objects_der, len + len_byte_cnt)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with moving cursor");
            break;
        case (CONTEXT_SPECIFIC | CONSTRUCTED | PUB_KEY):
            ak_error_message(ak_error_invalid_value,
                             __func__,
                             "getting public key does not realized yet");
            if ((error = asn_get_len(p_pkcs_15_objects_der->mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting data length");

            if ((error = ps_move_cursor(p_pkcs_15_objects_der, len + len_byte_cnt)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with moving cursor");
            break;
        default:
            break;
    }

    if ((error = asn_get_expected_tlv(tag, p_pkcs_15_objects_der, (void *) &pkcs_15_sngl_object_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting pkcs 15 object in der");

    asn_get_tag(pkcs_15_sngl_object_der.mp_curr, &tag);
    switch (tag)
    {
        case (CONTEXT_SPECIFIC | CONSTRUCTED | 0u):
            if ((error = pkcs_15_get_direct_obj(&pkcs_15_sngl_object_der, p_pkcs_15_object)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting object direct");
            break;
        case (CONTEXT_SPECIFIC | CONSTRUCTED | 2u):
            ak_error_message(ak_error_invalid_value,
                             __func__,
                             "getting direct protected object does not realized yet");
            if ((error = asn_get_len(pkcs_15_sngl_object_der.mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting data length");

            if ((error = ps_move_cursor(&pkcs_15_sngl_object_der, len + len_byte_cnt)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with moving cursor");
        default:
            break;
    }

    if (ps_get_curr_size(&pkcs_15_sngl_object_der) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_direct_obj(s_der_buffer *p_pkcs_15_object_der, s_pkcs_15_object *p_pkcs_15_object) {
    int error;
    tag tag;
    s_der_buffer direct_object_der;

    tag = 0;
    memset(&direct_object_der, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_object_der || !p_pkcs_15_object)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    if ((error = asn_get_expected_tlv((CONTEXT_SPECIFIC | CONSTRUCTED | 0u),
                                      p_pkcs_15_object_der,
                                      (void *) &direct_object_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting pkcs 15 direct object in der");

    asn_get_tag(direct_object_der.mp_curr, &tag);
    switch (tag)
    {
        case (CONTEXT_SPECIFIC | CONSTRUCTED | 27u):
            p_pkcs_15_object->m_obj.mp_sec_key = calloc(1, sizeof(s_gost_sec_key));
            if (!p_pkcs_15_object->m_obj.mp_sec_key)
                return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

            if ((error = pkcs_15_get_gost_key(&direct_object_der, p_pkcs_15_object->m_obj.mp_sec_key)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting object direct");
            break;
        default:
            break;
    }

    if (ps_get_curr_size(&direct_object_der) != 0)
        return ak_error_invalid_token;

    return error;
}

void free_pkcs_15_token(s_pkcs_15_token *p_pkcs_15_token) {
    int i;
    if (p_pkcs_15_token)
    {
        asn_free_int(&p_pkcs_15_token->m_version);
        if (p_pkcs_15_token->mpp_key_infos)
        {
            for (i = 0; i < p_pkcs_15_token->m_info_size; i++)
            {
                free_key_management_info(p_pkcs_15_token->mpp_key_infos[i]);
                p_pkcs_15_token->mpp_key_infos[i] = NULL;
            }
            free(p_pkcs_15_token->mpp_key_infos);
            p_pkcs_15_token->mpp_key_infos = NULL;
        }

        if (p_pkcs_15_token->mpp_pkcs_15_objects)
        {
            for (i = 0; i < p_pkcs_15_token->m_obj_size; i++)
            {
                free_pkcs_15_object(p_pkcs_15_token->mpp_pkcs_15_objects[i]);
                p_pkcs_15_token->mpp_pkcs_15_objects[i] = NULL;
            }
            free(p_pkcs_15_token->mpp_pkcs_15_objects);
            p_pkcs_15_token->mpp_pkcs_15_objects = NULL;
        }
    }
}

void free_key_management_info(s_key_management_info *p_kmi) {
    if (p_kmi)
    {
        switch (p_kmi->m_type)
        {
            case PWD_INFO:
                free_pwd_info(p_kmi->m_key_info.mp_pwd_info);
                p_kmi->m_key_info.mp_pwd_info = NULL;
                break;
            default:
                break;
        }
    }
}

void free_pwd_info(s_pwd_info *p_pwd_info) {
    if (p_pwd_info)
    {
        asn_free_int(&p_pwd_info->m_key_len);
        asn_free_int(&p_pwd_info->m_iteration_count);
        asn_free_octetstr(&p_pwd_info->m_salt);
        asn_free_objid(&p_pwd_info->m_algorithm);
        asn_free_objid(&p_pwd_info->m_prf_id);
        asn_free_utf8string(&p_pwd_info->m_hint);
    }
}

void free_pkcs_15_object(s_pkcs_15_object *p_object) {
    if (p_object)
    {
        switch (p_object->m_type)
        {
            case SEC_KEY:
                pcks_15_free_gost_sec_key(p_object->m_obj.mp_sec_key);
                break;
            case PRI_KEY:
                break;
            case PUB_KEY:
                break;
            default:
                break;
        }
    }

}
