#include <ak_buffer.h>
#include <pkcs_15_cryptographic_token/ak_pkcs_15_gost_secret_key.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_pkcs_15_token_der указатель на токен, содержащий всю DER последовательность
    @param p_key указатель на секретный ключ
    @param p_gost_key_der ресультат закодирования ключа
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_put_gost_key(s_der_buffer *p_pkcs_15_token_der, s_gost_sec_key *p_key, s_der_buffer *p_gost_key_der) {
    int error;
    s_der_buffer key_attr_der;
    s_der_buffer key_type_gost_der;
    size_t gost_key_der_len;

    error = ak_error_ok;
    memset(&key_attr_der, 0, sizeof(key_attr_der));
    memset(&key_type_gost_der, 0, sizeof(key_type_gost_der));
    gost_key_der_len = 0;

    if (!p_pkcs_15_token_der || !p_key || !p_gost_key_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (!p_key->m_key_type_gost)
        return ak_error_message(ak_error_null_pointer, __func__, "key type gost oid absent");

    /* Добавляем атрибуты ключа */
    if ((error = pkcs_15_put_key_attr(p_pkcs_15_token_der, p_key, &key_attr_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding gost key");

    /*
     * В контейнере могут хранится секретные
     * ключи, испоьзуемые только в алгоритме Магма
     * (см. Р 50.1.110 - 2016 стр.7)
     * keyTypeGost = id-Gost28147-89
     */
    /* Добавляем идентификатор алгоритма, для которого предназнаен ключ */
    if (0 == strcmp(p_key->m_key_type_gost, "1.2.643.2.2.21") ||
        0 == strcmp(p_key->m_key_type_gost, "1.2.643.7.1.1.5.1") ||
        0 == strcmp(p_key->m_key_type_gost, "1.2.643.7.1.1.5.2"))
    {
        if ((error = asn_put_universal_tlv(TOBJECT_IDENTIFIER, (void *) &p_key->m_key_type_gost, 0, p_pkcs_15_token_der,
                                           &key_type_gost_der)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding gost key type oid");
    }
    else
        return ak_error_message_fmt(ak_error_wrong_oid,
                                    __func__,
                                    "this type of key (%s) is prohibited. Allowed only other (%s)",
                                    p_key->m_key_type_gost,
                                    "1.2.643.2.2.21");

    gost_key_der_len = ps_get_full_size(&key_attr_der) + ps_get_full_size(&key_type_gost_der);

    if ((error = ps_move_cursor(p_pkcs_15_token_der, 1 + asn_get_len_byte_cnt(gost_key_der_len))) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    /* Добавляем тег, указывающий на то, что объект является ГОСТ'овским секретным ключом */
    asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 27u, p_pkcs_15_token_der->mp_curr);

    if ((error = asn_put_len(gost_key_der_len, p_pkcs_15_token_der->mp_curr + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding gost key length");

    if ((error = ps_set(p_gost_key_der,
                        p_pkcs_15_token_der->mp_curr,
                        gost_key_der_len + asn_get_len_byte_cnt(gost_key_der_len) + 1,
                        PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_pkcs_15_token_der указатель на токен, содержащий всю DER последовательность
    @param p_key указатель на секретный ключ
    @param p_key_attr_der ресультат закодирования аттрибутов ключа
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_put_key_attr(s_der_buffer *p_pkcs_15_token_der, s_gost_sec_key *p_key, s_der_buffer *p_key_attr_der) {
    int error;
    s_der_buffer gost_secret_key_attributes_der;
    s_der_buffer common_secret_key_attributes_der;
    s_der_buffer common_key_attributes_der;
    s_der_buffer common_object_attributes_der;
    size_t key_attr_der_len;

    error = ak_error_ok;
    memset(&gost_secret_key_attributes_der, 0, sizeof(gost_secret_key_attributes_der));
    memset(&common_secret_key_attributes_der, 0, sizeof(common_secret_key_attributes_der));
    memset(&common_key_attributes_der, 0, sizeof(common_key_attributes_der));
    memset(&common_object_attributes_der, 0, sizeof(common_object_attributes_der));
    key_attr_der_len = 0;

    if (!p_pkcs_15_token_der || !p_key || !p_key_attr_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    /* Добавляем атрибуты ГОСТ'овского секретного ключа */
    if ((error = pkcs_15_put_gost_secret_key_attributes(p_pkcs_15_token_der, p_key, &gost_secret_key_attributes_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding gost key attributes");

    /* Добавляем общие атрибуты секретных ключей (если они указаны) */
    if (p_key->m_key_len.mp_value != NULL)
    {
        if ((error =
                     pkcs_15_put_common_secret_key_attributes(p_pkcs_15_token_der, p_key,
                                                              &common_secret_key_attributes_der))
            != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding common secret key attributes");
    }

    /* Добавляем общие атрибуты ключей  */
    if ((error = pkcs_15_put_common_key_attributes(p_pkcs_15_token_der, &p_key->m_key_attrs,
                                                   &common_key_attributes_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding common key attributes");

    /* Добавляем общие атрибуты объекта PKCS 15 */
    if ((error = pkcs_15_put_common_object_attributes(p_pkcs_15_token_der,
                                                      &p_key->m_obj_attrs,
                                                      &common_object_attributes_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding common object attributes");

    key_attr_der_len = ps_get_full_size(&gost_secret_key_attributes_der) +
                       ps_get_full_size(&common_secret_key_attributes_der) +
                       ps_get_full_size(&common_key_attributes_der) +
                       ps_get_full_size(&common_object_attributes_der);

    /* Обединяем все атрибуты в один объект sequence */
    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, key_attr_der_len, p_pkcs_15_token_der, p_key_attr_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_pkcs_15_token_der указатель на токен, содержащий всю DER последовательность
    @param p_key указатель на секретный ключ
    @param p_gost_secret_key_attributes_der ресультат закодирования атрибутов секретного ключа ГОСТ
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_put_gost_secret_key_attributes(s_der_buffer *p_pkcs_15_token_der, s_gost_sec_key *p_key,
                                           s_der_buffer *p_gost_secret_key_attributes_der) {
    int error;
    s_der_buffer direct_protected_key_der;
    size_t gost_sec_key_attrs_der_len;

    memset(&direct_protected_key_der, 0, sizeof(direct_protected_key_der));

    if (!p_pkcs_15_token_der || !p_key || !p_gost_secret_key_attributes_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");


    /* Добавляем зашифрованный ключ и информацию о шифровании */
    if ((error = pkcs_15_put_object_direct_protected(p_pkcs_15_token_der,
                                                     &p_key->m_enveloped_data,
                                                     &direct_protected_key_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding key direct protected");

    gost_sec_key_attrs_der_len = ps_get_full_size(&direct_protected_key_der);// + ps_get_full_size(&key_info_der);

    if ((error = ps_move_cursor(p_pkcs_15_token_der, asn_get_len_byte_cnt(gost_sec_key_attrs_der_len) + 1))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    /* Добавляем тег, указывающий на то, что объект содержит атрибуты ГОСТ'овского секретного ключа */
    asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 1u, p_pkcs_15_token_der->mp_curr);

    if ((error = asn_put_len(gost_sec_key_attrs_der_len, p_pkcs_15_token_der->mp_curr + 1)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "problem with adding enveloped data length");

    if ((error = ps_set(p_gost_secret_key_attributes_der, p_pkcs_15_token_der->mp_curr,
                        gost_sec_key_attrs_der_len + asn_get_len_byte_cnt(gost_sec_key_attrs_der_len) + 1, PS_U_MODE))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_pkcs_15_token_der указатель на токен, содержащий всю DER последовательность
    @param p_key указатель на секретный ключ
    @param p_common_secret_key_attributes_der ресультат закодирования общих атрибутов секретного ключа
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_put_common_secret_key_attributes(s_der_buffer *p_pkcs_15_token_der, s_gost_sec_key *p_key,
                                             s_der_buffer *p_common_secret_key_attributes_der) {
    int error;
    s_der_buffer common_sec_key_attrs_der;
    size_t common_sec_key_attrs_der_len;

    if (!p_pkcs_15_token_der || !p_key || !p_common_secret_key_attributes_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    memset(&common_sec_key_attrs_der, 0, sizeof(common_sec_key_attrs_der));
    common_sec_key_attrs_der_len = 0;

    /* Добавляем размер ключа */
    if ((error = asn_put_universal_tlv(TINTEGER,
                                       (void *) &p_key->m_key_len,
                                       0,
                                       p_pkcs_15_token_der,
                                       &common_sec_key_attrs_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding secret key length attribute");

    common_sec_key_attrs_der_len = ps_get_full_size(&common_sec_key_attrs_der);

    if ((error = ps_move_cursor(p_pkcs_15_token_der, asn_get_len_byte_cnt(common_sec_key_attrs_der_len) + 1))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    /* Добавляем тег, указывающий на то, что объект содержит общие атрибуты секретных ключей */
    asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 0u, p_pkcs_15_token_der->mp_curr);

    if ((error = asn_put_len(common_sec_key_attrs_der_len, p_pkcs_15_token_der->mp_curr + 1)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "problem with adding common secret key attributes length");

    if ((error = ps_set(p_common_secret_key_attributes_der, p_pkcs_15_token_der->mp_curr,
                        common_sec_key_attrs_der_len + asn_get_len_byte_cnt(common_sec_key_attrs_der_len) + 1,
                        PS_U_MODE))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_pkcs_15_token_der указатель на токен, содержащий всю DER последовательность
    @param p_key указатель на секретный ключ
    @param p_key_info_der ресультат закодирования информации о ключе
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_put_key_info(s_der_buffer *p_pkcs_15_token_der, s_key_info *p_key_info, s_der_buffer *p_key_info_der) {
    int error;
    s_der_buffer supported_operations_der;
    s_der_buffer parameters_der;
    s_der_buffer prms_and_ops_der;
    size_t prms_and_ops_der_len;

    if (!p_pkcs_15_token_der || !p_key_info || !p_key_info_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (!p_key_info->m_parameters_id)
        return ak_error_message(ak_error_null_pointer, __func__, "parameters absent");

    error = ak_error_ok;
    memset(&supported_operations_der, 0, sizeof(supported_operations_der));
    memset(&parameters_der, 0, sizeof(parameters_der));
    memset(&prms_and_ops_der, 0, sizeof(prms_and_ops_der));
    prms_and_ops_der_len = 0;

    /* Добавляем поддерживаемы операции */
    if (p_key_info->m_supported_operations.mp_value != NULL)
    {
        if ((error = asn_put_universal_tlv(TBIT_STRING,
                                           (void *) &p_key_info->m_supported_operations,
                                           0,
                                           p_pkcs_15_token_der,
                                           &supported_operations_der)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding gost supported operations");
    }

    /* Добавляем идентификатор параметров */
    if (p_key_info->m_parameters_id != NULL)
    {
        s_der_buffer crypto_pro_param_set;
        memset(&crypto_pro_param_set, 0, sizeof(s_der_buffer));
        if (0 == strcmp(p_key_info->m_parameters_id, "1.2.643.7.1.2.5.1.1"))
        {
            if ((error = asn_put_universal_tlv(TOBJECT_IDENTIFIER,
                                               (void *) &p_key_info->m_parameters_id,
                                               0,
                                               p_pkcs_15_token_der,
                                               &crypto_pro_param_set)) != ak_error_ok)
                return ak_error_message(error, __func__, "problem with adding crypto pro parameters set oid");

            parameters_der = crypto_pro_param_set;
        }
        else
            return ak_error_message_fmt(ak_error_wrong_oid, __func__, "algorithm (%s) doesn't support", p_key_info->m_parameters_id);
    }

    /* Вариант хранения непосредственно значений параметров пока не реализован */

    prms_and_ops_der_len = ps_get_full_size(&parameters_der) + ps_get_full_size(&supported_operations_der);

    /* Обединяем параметры и операции в один объект sequence */
    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, prms_and_ops_der_len, p_pkcs_15_token_der, &prms_and_ops_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    *p_key_info_der = prms_and_ops_der;

    return ak_error_ok;
}

int pkcs_15_put_gost28147_89_prms(s_der_buffer *p_pkcs_15_token_der, s_gost28147_89_prms *p_params,
                                  s_der_buffer *p_params_der) {
    int error;
    s_der_buffer encryption_param_set;
    s_der_buffer iv;
    size_t papams_len;

    memset(&encryption_param_set, 0, sizeof(s_der_buffer));
    memset(&iv, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token_der || !p_params || !p_params_der || !p_params->m_iv.mp_value
        || !p_params->m_encryption_param_set)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (p_params->m_iv.m_val_len != 8)
        return ak_error_message(ak_error_invalid_value, __func__, "iv length must be 8");

    if ((error = asn_put_universal_tlv(TOBJECT_IDENTIFIER,
                                       (void *) &p_params->m_encryption_param_set,
                                       0,
                                       p_pkcs_15_token_der,
                                       &encryption_param_set)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding content encryption parameter set id");

    if ((error = asn_put_universal_tlv(TOCTET_STRING, (void *) &p_params->m_iv, 0, p_pkcs_15_token_der, &iv))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding iv");

    papams_len = ps_get_full_size(&iv) + ps_get_full_size(&encryption_param_set);

    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, papams_len, p_pkcs_15_token_der, p_params_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_object_der указатель на объект, содержащий DER последовательность
    @param p_key указатель на секретный ключ
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_get_gost_key(s_der_buffer *p_object_der, s_gost_sec_key *p_key) {
    int error;
    s_der_buffer gost_key_der;

    if (!p_object_der || !p_key)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    memset(&gost_key_der, 0, sizeof(gost_key_der));

    /* Декодируем ГОСТ'овский секретный ключ */
    if ((error = asn_get_expected_tlv(CONTEXT_SPECIFIC | CONSTRUCTED | 27u, p_object_der, (void *) &gost_key_der))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting gost key in der");

    /* Декодируем идентификатор алгоритма, для которого предназначен ключ */
    if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER, &gost_key_der, (void *) &p_key->m_key_type_gost))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting gost key type");

    /* Декодируем атрибуты ключа */
    if ((error = pkcs_15_get_key_attr(&gost_key_der, p_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key attributes");

    /* Проверяем на наличие непрочитанных данных */
    if (ps_get_curr_size(&gost_key_der) != 0)
        return ak_error_invalid_token;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_key_der указатель на объект, содержащий DER последовательность
    @param p_key указатель на секретный ключ
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_get_key_attr(s_der_buffer *p_key_der, s_gost_sec_key *p_key) {
    int error;
    tag curr_tag;
    s_der_buffer key_attrs;

    if (!p_key_der || !p_key)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    curr_tag = 0;
    memset(&key_attrs, 0, sizeof(key_attrs));

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_key_der, (void *) &key_attrs)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting gost key attributes in der");

    /* Декодируем общие атрибуты объекта PKCS 15 */
    if ((error = pkcs_15_get_common_object_attributes(&key_attrs, &p_key->m_obj_attrs)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting common object attributes");

    /* Декодируем общие атрибуты ключа */
    if ((error = pkcs_15_get_common_key_attributes(&key_attrs, &p_key->m_key_attrs)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting common key attributes");

    /* Декодируем общие атрибуты секретного ключа (если они есть) */
    asn_get_tag(key_attrs.mp_curr, &curr_tag);
    if (curr_tag == (CONTEXT_SPECIFIC | CONSTRUCTED | 0u))
    {
        if ((error = pkcs_15_get_common_secret_key_attributes(&key_attrs, p_key)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting common secret key attributes");
    }

    /* Декодируем общие атрибуты ГОСТ'овского секретного ключа */
    if ((error = pkcs_15_get_gost_secret_key_attributes(&key_attrs, p_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting gost secret key attributes");

    /* Проверяем на наличие непрочитанных данных */
    if (ps_get_curr_size(&key_attrs) != 0)
        return ak_error_invalid_token;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_key_der указатель на объект, содержащий DER последовательность
    @param p_key указатель на секретный ключ
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_get_common_secret_key_attributes(s_der_buffer *p_key_der, s_gost_sec_key *p_key) {
    int error;
    s_der_buffer secret_key_attrs;

    if (!p_key_der || !p_key)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    memset(&secret_key_attrs, 0, sizeof(secret_key_attrs));

    if ((error = asn_get_expected_tlv((CONTEXT_SPECIFIC | CONSTRUCTED | 0u), p_key_der, (void *) &secret_key_attrs))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting common secret key attributes in der");

    /* Декодируем размер ключа */
    if ((error = asn_get_expected_tlv(TINTEGER, &secret_key_attrs, (void *) &p_key->m_key_len)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key length attribute");

    /* Проверяем на наличие непрочитанных данных */
    if (ps_get_curr_size(&secret_key_attrs))
        return ak_error_invalid_token;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_key_der указатель на объект, содержащий DER последовательность
    @param p_key указатель на секретный ключ
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_get_gost_secret_key_attributes(s_der_buffer *p_key_der, s_gost_sec_key *p_key) {
    int error;
    s_der_buffer gost_key_attrs;

    if (!p_key_der || !p_key)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    memset(&gost_key_attrs, 0, sizeof(gost_key_attrs));

    /* Декодируем атрибуты ГОСТ'овского секретного ключа  */
    if ((error = asn_get_expected_tlv((CONTEXT_SPECIFIC | CONSTRUCTED | 1u), p_key_der, (void *) &gost_key_attrs))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting common secret key attributes in der");

    /* Декодируем зашифрованное значение ключа и информацию о шифровании */
    if ((error = pkcs_15_get_object_direct_protected(&gost_key_attrs, &p_key->m_enveloped_data)) != ak_error_ok)
    {
        if (error != ak_error_diff_tags)
            return ak_error_message(error, __func__, "problems with getting gost key direct protected");
    }

    /* Декодируем информацию о ключе */
    /* В текущей версии не используется */
//    if(ps_get_curr_size(&gost_key_attrs))
//    {
//        if((error = pkcs_15_get_key_info(&gost_key_attrs, &p_key->m_key_info)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with getting gost key info");
//    }

    //if(ps_get_curr_size(&gost_key_attrs) != 0)
    //return ak_error_invalid_token;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_key_der указатель на объект, содержащий DER последовательность
    @param p_key указатель на секретный ключ
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_get_key_info(s_der_buffer *p_key_der, s_key_info *p_key_info) {
    int error;
    tag curr_tag;
    s_der_buffer key_info_der;

    if (!p_key_der || !p_key_info)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    curr_tag = 0;
    memset(&key_info_der, 0, sizeof(key_info_der));

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_key_der, (void *) &key_info_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting gost key info in der");

    /* Декодируем идентификатор параметров */
    asn_get_tag(key_info_der.mp_curr, &curr_tag);
    switch (curr_tag)
    {
        case TOBJECT_IDENTIFIER:
            if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER, &key_info_der, (void *) &p_key_info->m_parameters_id))
                != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting crypto pro parameters set");
            break;
        default:
            break;
    }

    /* Декодируем информацию о поддерживаемых операциях */
    if (ps_get_curr_size(&key_info_der))
    {
        if ((error = asn_get_expected_tlv(TBIT_STRING, &key_info_der, (void *) &p_key_info->m_supported_operations))
            != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting gost key supported operations");
    }

    /* Проверяем на наличие непрочитанных данных */
    if (ps_get_curr_size(&key_info_der) != 0)
        return ak_error_invalid_token;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция конкатенирует ключ, маску, значение счетчика. Результат в виде соответствующей DER
    последовательности записывается в gost_kvm_der.

    Примечание:
        - решение присоединенить значения счетчика к ключу и маске было придумано автором кода
          и разнится с требованиями рекомендации Р 50.1.110 - 2016;
        - под хранение значения счетчика выделяется 4 байта;

    @param masked_key замаскированный ключ
    @param mask маска
    @param counter счетчик (ресурс) ключа
    @param gost_kvm_der выходная DER последовательность, которая должна быть зашифрована
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_make_gost_key_value_mask(ak_buffer masked_key, ak_buffer mask, ssize_t counter, ak_buffer gost_kvm_der) {
    int error;
    uint8_t i;
    uint8_t counter_var_size;
    size_t key_val_mask_len;
    uint8_t len_byte_cnt;
    s_der_buffer kvm_der;

    if (!masked_key || !mask || !gost_kvm_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    counter_var_size = 4;
    key_val_mask_len = (size_t) (masked_key->size + mask->size + counter_var_size);
    len_byte_cnt = asn_get_len_byte_cnt(key_val_mask_len);
    ps_alloc(&kvm_der, 1 + len_byte_cnt + key_val_mask_len, PS_W_MODE);

    if ((error = ps_move_cursor(&kvm_der, counter_var_size)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    for (i = 0; i < counter_var_size; i++)
    {
        kvm_der.mp_curr[counter_var_size - i - 1] = (byte) ((counter >> (i * 8u)) & 0xFFu);
    }

    if ((error = ps_move_cursor(&kvm_der, masked_key->size)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    memcpy(kvm_der.mp_curr, masked_key->data, masked_key->size);

    if ((error = ps_move_cursor(&kvm_der, mask->size)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    memcpy(kvm_der.mp_curr, mask->data, mask->size);

    if ((error = ps_move_cursor(&kvm_der, 1 + len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    asn_put_tag(TOCTET_STRING, kvm_der.mp_curr);

    if ((error = asn_put_len(key_val_mask_len, kvm_der.mp_curr + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding data length");

    ak_buffer_set_ptr(gost_kvm_der, kvm_der.mp_begin, ps_get_full_size(&kvm_der), true);
    free(kvm_der.mp_begin);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param encrypted_cek зашифрованный ключ CEK (ключ представляен в виде конкатенации
           замаскированного значения ключа и маски)
    @param mac имитовставка
    @param encrypted_key_der выходная DER последовательность, которая помещается
           в поле m_encrypted_key структуры s_kekri
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_make_enc_key_plus_mac_seq(ak_buffer encrypted_cek, ak_buffer mac, ak_buffer encrypted_key_der) {
    int error;
    size_t enc_cek_der_len;
    size_t mac_der_len;
    size_t enc_key_der_len;
    s_der_buffer enc_key_der;

    if (!encrypted_cek || !mac || !encrypted_key_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    enc_cek_der_len = 1 + asn_get_len_byte_cnt(encrypted_cek->size) + encrypted_cek->size;
    mac_der_len = 1 + asn_get_len_byte_cnt(mac->size) + mac->size;
    enc_key_der_len = 1 + asn_get_len_byte_cnt(enc_cek_der_len + mac_der_len) + enc_cek_der_len + mac_der_len;

    ps_alloc(&enc_key_der, enc_key_der_len, PS_W_MODE);
    ps_move_cursor(&enc_key_der, 1 + asn_get_len_byte_cnt(mac->size) + mac->size);
    asn_put_tag(TOCTET_STRING, enc_key_der.mp_curr);
    asn_put_len(mac->size, enc_key_der.mp_curr + 1);
    memcpy(enc_key_der.mp_curr + 1 + asn_get_len_byte_cnt(mac->size), mac->data, mac->size);

    ps_move_cursor(&enc_key_der, 1 + asn_get_len_byte_cnt(encrypted_cek->size) + encrypted_cek->size);
    asn_put_tag(TOCTET_STRING, enc_key_der.mp_curr);
    asn_put_len(encrypted_cek->size, enc_key_der.mp_curr + 1);
    memcpy(enc_key_der.mp_curr + 1 + asn_get_len_byte_cnt(encrypted_cek->size), encrypted_cek->data,
           encrypted_cek->size);

    ps_move_cursor(&enc_key_der, 1 + asn_get_len_byte_cnt(enc_cek_der_len + mac_der_len));
    asn_put_tag(CONSTRUCTED | TSEQUENCE, enc_key_der.mp_curr);
    asn_put_len(enc_cek_der_len + mac_der_len, enc_key_der.mp_curr + 1);

    ak_buffer_set_ptr(encrypted_key_der, enc_key_der.mp_begin, ps_get_full_size(&enc_key_der), true);
    free(enc_key_der.mp_begin);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param gost_kvm_der
    @param masked_key
    @param mask
    @param counter
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_parse_gost_key_value_mask(ak_buffer gost_kvm_der, ak_buffer masked_key, ak_buffer mask, ssize_t *counter) {
    int error;
    uint8_t i;
    byte *p_curr_pos;
    tag curr_tag;
    size_t data_len;
    uint8_t len_byte_cnt;
    uint8_t counter_var_size;
    size_t key_len;

    counter_var_size = 4;
    p_curr_pos = gost_kvm_der->data;
    asn_get_tag(p_curr_pos, &curr_tag);
    if (curr_tag != (TOCTET_STRING))
        return ak_error_invalid_value;

    ++p_curr_pos;
    if ((error = asn_get_len(p_curr_pos, &data_len, &len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with getting data length");
    p_curr_pos += len_byte_cnt;

    key_len = (data_len - counter_var_size) / 2;

    if ((error = ak_buffer_set_ptr(masked_key, p_curr_pos, key_len, ak_true)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with getting masked key from DER sequence");
    p_curr_pos += key_len;

    if ((error = ak_buffer_set_ptr(mask, p_curr_pos, key_len, ak_true)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with getting mask from DER sequence");
    p_curr_pos += key_len;

    *counter = 0;
    for (i = 0; i < counter_var_size; i++)
    {
        *counter ^= p_curr_pos[i];
        if (i != counter_var_size - 1)
            *counter = *counter << 8;
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param encrypted_key_der
    @param p_encrypted_cek
    @param p_mac имитовставка
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_parse_enc_key_plus_mac_seq(octet_string encrypted_key_der, ak_buffer p_encrypted_cek, ak_buffer p_mac) {
    int error;
    byte *p_curr_pos;
    tag curr_tag;
    size_t data_len;
    uint8_t len_byte_cnt;

    p_curr_pos = encrypted_key_der.mp_value;
    asn_get_tag(p_curr_pos, &curr_tag);
    if (curr_tag != (CONSTRUCTED | TSEQUENCE))
        return ak_error_invalid_value;

    ++p_curr_pos;
    if ((error = asn_get_len(p_curr_pos, &data_len, &len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with getting data length");
    p_curr_pos += len_byte_cnt;

    /* Декодируем значение ключа и маски */
    asn_get_tag(p_curr_pos, &curr_tag);
    if (curr_tag != (TOCTET_STRING))
        return ak_error_invalid_value;

    ++p_curr_pos;
    if ((error = asn_get_len(p_curr_pos, &data_len, &len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with getting data length");
    p_curr_pos += len_byte_cnt;

    if ((error = ak_buffer_create_size(p_encrypted_cek, data_len)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with creating buffer for data");
    memcpy(p_encrypted_cek->data, p_curr_pos, data_len);
    p_curr_pos += data_len;


    /* Декодируем значение MAC */
    asn_get_tag(p_curr_pos, &curr_tag);
    if (curr_tag != (TOCTET_STRING))
        return ak_error_invalid_value;

    ++p_curr_pos;
    if ((error = asn_get_len(p_curr_pos, &data_len, &len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with getting data length");
    p_curr_pos += len_byte_cnt;

    if ((error = ak_buffer_create_size(p_mac, data_len)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with creating buffer for data");
    memcpy(p_mac->data, p_curr_pos, data_len);

    return ak_error_ok;
}

void pcks_15_free_gost_sec_key(s_gost_sec_key *p_key) {
    if (p_key)
    {
        asn_free_objid(&p_key->m_key_type_gost);
        pkcs_15_free_common_obj_attrs(&p_key->m_obj_attrs);
        pkcs_15_free_common_key_attrs(&p_key->m_key_attrs);
        asn_free_int(&p_key->m_key_len);
        pkcs_15_free_enveloped_data(&p_key->m_enveloped_data);
    }
}
