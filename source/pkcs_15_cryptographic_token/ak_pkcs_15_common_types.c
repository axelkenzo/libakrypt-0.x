#include "ak_pkcs_15_common_types.h"
#include "ak_pkcs_15_gost_secret_key.h"

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_pkcs_15_token_der указатель на объект, в котором храниться результат кодирования токена
    @param p_enveloped_data указатель на объект EnvelopedData
    @param p_enveloped_data_der указатель на объект, в котором храниться результат кодирования
           EnvelopedData
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int pkcs_15_put_object_direct_protected(s_der_buffer* p_pkcs_15_token_der, s_enveloped_data* p_enveloped_data, s_der_buffer* p_enveloped_data_der)
{
    int error;
    s_der_buffer encrypted_content_info_der;
    s_der_buffer recipient_infos_der;
    s_der_buffer version_der;
    size_t enveloped_data_der_len;

    if (!p_pkcs_15_token_der || !p_enveloped_data || !p_enveloped_data_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    memset(&encrypted_content_info_der, 0, sizeof(encrypted_content_info_der));
    memset(&recipient_infos_der, 0, sizeof(recipient_infos_der));
    memset(&version_der, 0, sizeof(version_der));

    /* Добавляем информацию о зашифрованном контенте */
    if ((error = pkcs_15_put_encrypted_content_info(p_pkcs_15_token_der, p_enveloped_data, &encrypted_content_info_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding encrypted content info");

    /* Добавляем информацию о получателе зашифрованных данных */
    if ((error = pkcs_15_put_recipient_infos(p_pkcs_15_token_der, p_enveloped_data->mpp_recipient_infos, p_enveloped_data->m_ri_size, &recipient_infos_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding recipient infos");

    /* Добавляем атрибут "версия" */
    if ((error = asn_put_universal_tlv(TINTEGER, (void*) &p_enveloped_data->m_version, 0, p_pkcs_15_token_der,
            &version_der))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding version attribute");

    enveloped_data_der_len = ps_get_full_size(&version_der) +
            ps_get_full_size(&recipient_infos_der) +
            ps_get_full_size(&encrypted_content_info_der);

    if ((error = ps_move_cursor(p_pkcs_15_token_der, asn_get_len_byte_cnt(enveloped_data_der_len) + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    /* Добавляем тег, указывающий, что объект хранится в зашифрованном виде и инкапсулирован в объект EnvelopedData */
    asn_put_tag(CONTEXT_SPECIFIC | CONSTRUCTED | 2u, p_pkcs_15_token_der->mp_curr);

    /* Добавляем длину закодированного объекта */
    if ((error = asn_put_len(enveloped_data_der_len, p_pkcs_15_token_der->mp_curr + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding direct protected key length");

    /* Устанвливаем значение объекта p_enveloped_data_der, чтобы он указывал на объект  */
    if ((error = ps_set(p_enveloped_data_der, p_pkcs_15_token_der->mp_curr, enveloped_data_der_len + asn_get_len_byte_cnt(enveloped_data_der_len) + 1, PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return error;
}

int pkcs_15_put_common_object_attributes(s_der_buffer* p_pkcs_15_token_der, s_common_obj_attrs* p_obj_attrs, s_der_buffer* p_common_object_attributes_der)
{
    int error;
    s_der_buffer flags_der;
    s_der_buffer label_der;
    size_t common_object_attributes_len;

    memset(&flags_der, 0, sizeof(s_der_buffer));
    memset(&label_der, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token_der || !p_obj_attrs || !p_common_object_attributes_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    error = ak_error_ok;
    if (p_obj_attrs->m_flags.mp_value != NULL)
    {
        if ((error = asn_put_universal_tlv(TBIT_STRING, (void*) &p_obj_attrs->m_flags, 0, p_pkcs_15_token_der, &flags_der))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding common object flags");
    }

    if (p_obj_attrs->m_label != NULL)
    {
        if ((error = asn_put_universal_tlv(TUTF8_STRING, (void*) &p_obj_attrs->m_label, 0, p_pkcs_15_token_der, &label_der))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding object label");
    }

    common_object_attributes_len = ps_get_full_size(&label_der) + ps_get_full_size(&flags_der);
    if (common_object_attributes_len)
    {
        if ((error = asn_put_universal_tlv(TSEQUENCE,
                NULL,
                common_object_attributes_len,
                p_pkcs_15_token_der,
                p_common_object_attributes_der)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding sequence tag and length");
    }
    else
        p_common_object_attributes_der->mp_begin = p_common_object_attributes_der->mp_curr =
        p_common_object_attributes_der->mp_end = NULL;

    return error;
}

int pkcs_15_put_common_key_attributes(s_der_buffer* p_pkcs_15_token_der, s_common_key_attrs* p_key_attrs,
        s_der_buffer* p_common_key_attributes_der)
{
    int error;
    s_der_buffer end_date_der;
    s_der_buffer start_date;
    s_der_buffer key_reference;
    s_der_buffer access_flags;
    s_der_buffer native;
    s_der_buffer usage;
    s_der_buffer id;
    size_t common_key_attributes_len;

    memset(&end_date_der, 0, sizeof(s_der_buffer));
    memset(&start_date, 0, sizeof(s_der_buffer));
    memset(&key_reference, 0, sizeof(s_der_buffer));
    memset(&access_flags, 0, sizeof(s_der_buffer));
    memset(&native, 0, sizeof(s_der_buffer));
    memset(&usage, 0, sizeof(s_der_buffer));
    memset(&id, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token_der || !p_key_attrs || !p_common_key_attributes_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (p_key_attrs->m_end_date)
    {
        uint8_t end_date_len = (uint8_t) asn_get_gentime_byte_cnt(p_key_attrs->m_end_date);
        if ((error = ps_move_cursor(p_pkcs_15_token_der, end_date_len + asn_get_len_byte_cnt(end_date_len) + 1)) !=
                ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        asn_put_tag(CONTEXT_SPECIFIC | PRIMITIVE | 0u, p_pkcs_15_token_der->mp_curr);
        if ((error = asn_put_len(end_date_len, p_pkcs_15_token_der->mp_curr + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key end date length");

        if ((error = asn_put_generalized_time(p_key_attrs->m_end_date,
                p_pkcs_15_token_der->mp_curr + asn_get_len_byte_cnt(end_date_len) + 1))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding key end date");

        if ((error = ps_set(&end_date_der,
                p_pkcs_15_token_der->mp_curr,
                (size_t) (end_date_len + asn_get_len_byte_cnt(end_date_len) + 1),
                PS_U_MODE)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with making union of asn data");
    }

    if (p_key_attrs->m_start_date)
    {
        if ((error = asn_put_universal_tlv(TGENERALIZED_TIME,
                (void*) &p_key_attrs->m_start_date,
                0,
                p_pkcs_15_token_der,
                &start_date)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key start date");
    }

    if (p_key_attrs->m_key_reference.mp_value)
    {
        if ((error = asn_put_universal_tlv(TINTEGER,
                (void*) &p_key_attrs->m_key_reference,
                0,
                p_pkcs_15_token_der,
                &key_reference)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key reference");
    }

    if (p_key_attrs->m_access_flags.mp_value)
    {
        if ((error = asn_put_universal_tlv(TBIT_STRING,
                (void*) &p_key_attrs->m_access_flags,
                0,
                p_pkcs_15_token_der,
                &access_flags)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key access flags");
    }

    if (!p_key_attrs->m_native)
    {
        if ((error = asn_put_universal_tlv(TBOOLEAN, (void*) &p_key_attrs->m_native, 0, p_pkcs_15_token_der, &native))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key native attribute");
    }

    if (p_key_attrs->m_usage.mp_value)
    {
        if ((error = asn_put_universal_tlv(TBIT_STRING, (void*) &p_key_attrs->m_usage, 0, p_pkcs_15_token_der, &usage))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key usage attribute");
    }
    else
        return ak_error_message(ak_error_invalid_value, __func__, "usage flags absent");

    if (p_key_attrs->m_id.mp_value)
    {
        if ((error = asn_put_universal_tlv(TOCTET_STRING, (void*) &p_key_attrs->m_id, 0, p_pkcs_15_token_der, &id))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key id");
    }
    else
        return ak_error_message(ak_error_invalid_value, __func__, "key id absent");

    common_key_attributes_len = ps_get_full_size(&end_date_der) +
            ps_get_full_size(&start_date) +
            ps_get_full_size(&key_reference) +
            ps_get_full_size(&access_flags) +
            ps_get_full_size(&native) +
            ps_get_full_size(&usage) +
            ps_get_full_size(&id);

    if ((error = asn_put_universal_tlv(TSEQUENCE,
            NULL,
            common_key_attributes_len,
            p_pkcs_15_token_der,
            p_common_key_attributes_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

int pkcs_15_put_recipient_infos(s_der_buffer* p_pkcs_15_token,
        s_recipient_info** pp_recipient_infos,
        uint8_t num_of_recipient_infos,
        s_der_buffer* p_recipient_infos_der)
{
    int error;
    uint8_t recipient_infos_len;
    s_der_buffer recipient_info;

    if (!p_pkcs_15_token || !pp_recipient_infos || !num_of_recipient_infos || !p_recipient_infos_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    recipient_infos_len = 0;

    for (uint8_t i = 0; i < num_of_recipient_infos; i++)
    {
        if (!pp_recipient_infos[i])
            return ak_error_message(ak_error_null_pointer, __func__, "recipient info absent");

        memset(&recipient_info, 0, sizeof(s_der_buffer));
        if ((error = pkcs_15_put_single_recipient_info(p_pkcs_15_token, pp_recipient_infos[i], &recipient_info))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding recipient info");
        recipient_infos_len += ps_get_full_size(&recipient_info);
    }

    if ((error = asn_put_universal_tlv(TSET, NULL, recipient_infos_len, p_pkcs_15_token, p_recipient_infos_der)) !=
            ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding set tag and length");

    return error;
}

int pkcs_15_put_single_recipient_info(s_der_buffer* p_pkcs_15_token, s_recipient_info* p_sngl_recipient_info,
        s_der_buffer* p_sngl_recipient_info_der)
{
    int error;

    if (!p_pkcs_15_token || !p_sngl_recipient_info || !p_sngl_recipient_info_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    switch (p_sngl_recipient_info->m_type)
    {
    case KEKRI:
        if ((error = pkcs_15_put_kekri(p_pkcs_15_token, p_sngl_recipient_info->m_ri.mp_kekri,
                p_sngl_recipient_info_der))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding kekri recipient info");
        break;
    case PWRI:
        // TODO: написать реализацию для вариатна PWRI.
        return ak_error_message(ak_error_invalid_value, __func__, "do not realized yet");
    default:return ak_error_message(ak_error_invalid_value, __func__, "unacceptable type of recipient info");
    }
    return error;
}

int pkcs_15_put_kekri(s_der_buffer* p_pkcs_15_token, s_kekri* p_kekri, s_der_buffer* p_kekri_der)
{
    int error;
    s_der_buffer encrypted_key;
    s_der_buffer key_encryption_algorithm;
    s_der_buffer date;
    s_der_buffer key_identifire;
    s_der_buffer version;
    s_der_buffer key_id;
    size_t key_id_len;
    size_t kekri_len;

    memset(&encrypted_key, 0, sizeof(s_der_buffer));
    memset(&key_encryption_algorithm, 0, sizeof(s_der_buffer));
    memset(&date, 0, sizeof(s_der_buffer));
    memset(&key_identifire, 0, sizeof(s_der_buffer));
    memset(&version, 0, sizeof(s_der_buffer));
    memset(&key_id, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_kekri || !p_kekri_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (!p_kekri->m_encrypted_key.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "encrypted key absent");

    if ((error =
                 asn_put_universal_tlv(TOCTET_STRING, (void*) &p_kekri->m_encrypted_key, 0, p_pkcs_15_token,
                         &encrypted_key))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding encrypted key");

    if ((error = pkcs_15_put_key_encryption_algorithm(p_pkcs_15_token, p_kekri, &key_encryption_algorithm))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding key encryption algorithm");

    // ----- добавляем kekid, вложенный в sequence -----
    if (p_kekri->m_date)
    {
        if ((error = asn_put_universal_tlv(TGENERALIZED_TIME, (void*) &p_kekri->m_date, 0, p_pkcs_15_token, &date))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding date attribute");
    }

    if (!p_kekri->m_key_identifire.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "key identifier absent");

    if ((error = asn_put_universal_tlv(TOCTET_STRING,
            (void*) &p_kekri->m_key_identifire,
            0,
            p_pkcs_15_token,
            &key_identifire)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding key identifier");

    key_id_len = ps_get_full_size(&date) + ps_get_full_size(&key_identifire);
    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, key_id_len, p_pkcs_15_token, &key_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");
    // ----- конец добавления kekid -----

    if (!p_kekri->m_version.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "kekri version absent");

    if ((error = asn_put_universal_tlv(TINTEGER, (void*) &p_kekri->m_version, 0, p_pkcs_15_token, &version))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding version attribute");

    kekri_len = ps_get_full_size(&version) +
            ps_get_full_size(&key_id) +
            ps_get_full_size(&key_encryption_algorithm) +
            ps_get_full_size(&encrypted_key);

    if ((error = ps_move_cursor(p_pkcs_15_token, 1 + asn_get_len_byte_cnt(kekri_len))) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    asn_put_tag((CONTEXT_SPECIFIC | CONSTRUCTED | KEKRI), p_pkcs_15_token->mp_curr);
    if ((error = asn_put_len(kekri_len, p_pkcs_15_token->mp_curr + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding kekri length");

    if ((error =
                 ps_set(p_kekri_der, p_pkcs_15_token->mp_curr, kekri_len + asn_get_len_byte_cnt(kekri_len) + 1,
                         PS_U_MODE))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    return error;
}

int pkcs_15_put_key_encryption_algorithm(s_der_buffer* p_pkcs_15_token, s_kekri* p_kekri,
        s_der_buffer* p_key_encryption_algorithm_der)
{
    int error;
    size_t key_enc_alg_len;

    if (!p_pkcs_15_token || !p_kekri || !p_key_encryption_algorithm_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (!p_kekri->m_key_enc_alg_id)
        return ak_error_message(ak_error_null_pointer, __func__, "key encryption algorithm info absent");

    if (!p_kekri->m_key_enc_alg_id)
        return ak_error_message(ak_error_null_pointer, __func__, "identifier of key encryption algorithm absent");

    key_enc_alg_len = 0;
    if (0 == strcmp(p_kekri->m_key_enc_alg_id, "1.2.643.2.2.13.1"))
    {
        s_der_buffer params;
        s_der_buffer id;

        memset(&params, 0, sizeof(s_der_buffer));

        if (p_kekri->m_prm_set_type == GOST_KEY_WRAP_SET)
        {
            s_der_buffer ukm;
            s_der_buffer enc_prm_set;
            s_gost28147_89_key_wrap_prms parameters;

            parameters = *((s_gost28147_89_key_wrap_prms*) p_kekri->m_prm_set.p_key_wrap_set);

            if (!parameters.m_ukm.mp_value)
                return ak_error_message(ak_error_null_pointer, __func__, "ukm value absent");

            if (parameters.m_ukm.m_val_len != 8)
                return ak_error_message(ak_error_invalid_value, __func__, "ukm length must be 8");

            memset(&ukm, 0, sizeof(s_der_buffer));
            if ((error = asn_put_universal_tlv(TOCTET_STRING, (void*) &parameters.m_ukm, 0, p_pkcs_15_token, &ukm))
                    != ak_error_ok)
                return ak_error_message(error, __func__, "problem with adding ukm");

            memset(&enc_prm_set, 0, sizeof(s_der_buffer));
            if ((error = asn_put_universal_tlv(TOBJECT_IDENTIFIER,
                    (void*) &parameters.m_enc_prm_set,
                    0,
                    p_pkcs_15_token,
                    &enc_prm_set)) != ak_error_ok)
                return ak_error_message(error, __func__, "problem with adding encryption parameter set");

            size_t prms_len = ps_get_full_size(&ukm) + ps_get_full_size(&enc_prm_set);
            if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, prms_len, p_pkcs_15_token, &params)) != ak_error_ok)
                return ak_error_message(error, __func__, "problem with adding sequence tag and length");
        }

        memset(&id, 0, sizeof(s_der_buffer));
        if ((error =
                     asn_put_universal_tlv(TOBJECT_IDENTIFIER, (void*) &p_kekri->m_key_enc_alg_id, 0, p_pkcs_15_token,
                             &id))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding key encryption algorithm");

        key_enc_alg_len = ps_get_full_size(&params) + ps_get_full_size(&id);
    }
    else
        return ak_error_message_fmt(ak_error_wrong_oid,
                __func__,
                "algorithm (%s) doesn't support",
                p_kekri->m_key_enc_alg_id);

    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, key_enc_alg_len, p_pkcs_15_token,
            p_key_encryption_algorithm_der))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

int pkcs_15_put_encrypted_content_info(s_der_buffer* p_pkcs_15_token, s_enveloped_data* p_enveloped_data,
        s_der_buffer* p_encrypted_content_info_der)
{
    int error;
    size_t encrypted_contetnt_len;
    s_der_buffer encrypted_contetnt;
    s_der_buffer content_enc_alg;
    s_der_buffer content_type;
    size_t encrypted_content_info_len;

    memset(&encrypted_contetnt, 0, sizeof(s_der_buffer));
    memset(&content_enc_alg, 0, sizeof(s_der_buffer));
    memset(&content_type, 0, sizeof(s_der_buffer));

    if (!p_pkcs_15_token || !p_enveloped_data || !p_encrypted_content_info_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    //TODO: добавить AnprotectedAttrs.

    encrypted_contetnt_len = p_enveloped_data->m_encrypted_content.m_val_len;
    if ((error =
                 ps_move_cursor(p_pkcs_15_token,
                         encrypted_contetnt_len + asn_get_len_byte_cnt(encrypted_contetnt_len) + 1))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    asn_put_tag(CONTEXT_SPECIFIC | PRIMITIVE | 0u, p_pkcs_15_token->mp_curr);

    if ((error = asn_put_len(encrypted_contetnt_len, p_pkcs_15_token->mp_curr + 1)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "problem with adding encrypted content length");

    if ((error = asn_put_octetstr(p_enveloped_data->m_encrypted_content,
            p_pkcs_15_token->mp_curr + 1 + asn_get_len_byte_cnt(encrypted_contetnt_len)))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with adding encrypted content");

    if ((error = ps_set(&encrypted_contetnt,
            p_pkcs_15_token->mp_curr,
            1 + asn_get_len_byte_cnt(encrypted_contetnt_len) + encrypted_contetnt_len,
            PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");

    if ((error = pkcs_15_put_content_encryption_algorithm(p_pkcs_15_token, p_enveloped_data, &content_enc_alg))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding content encryption algorithm");

    if ((error = asn_put_universal_tlv(TOBJECT_IDENTIFIER,
            (void*) &p_enveloped_data->m_content_type,
            0,
            p_pkcs_15_token,
            &content_type)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding content type oid");

    encrypted_content_info_len = ps_get_full_size(&encrypted_contetnt) +
            ps_get_full_size(&content_enc_alg) +
            ps_get_full_size(&content_type);

    if ((error = asn_put_universal_tlv(TSEQUENCE,
            NULL,
            encrypted_content_info_len,
            p_pkcs_15_token,
            p_encrypted_content_info_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

int pkcs_15_put_content_encryption_algorithm(s_der_buffer* p_pkcs_15_token,
        s_enveloped_data* p_enveloped_data,
        s_der_buffer* p_content_enc_alg_der)
{
    int error;
    size_t content_enc_alg_len;
    s_der_buffer params;
    s_der_buffer id;

    if (!p_pkcs_15_token || !p_enveloped_data || !p_content_enc_alg_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");
    if (!p_enveloped_data->m_content_enc_alg_id)
        return ak_error_message(ak_error_null_pointer, __func__, "content encryption algorithm absent");

    error = ak_error_ok;
    content_enc_alg_len = 0;
    if (0 == strcmp(p_enveloped_data->m_content_enc_alg_id, "1.2.643.2.4.3.2.2"))
    {
        memset(&params, 0, sizeof(s_der_buffer));
        if (p_enveloped_data->m_prm_set_type == GOST_CONTENT_ENC_SET)
        {
            if ((error = pkcs_15_put_gost28147_89_prms(p_pkcs_15_token,
                    p_enveloped_data->m_prm_set.p_content_enc_prm_set,
                    &params)) != ak_error_ok)
                return ak_error_message(error, __func__, "problem with adding gost parameters");
        }

        memset(&id, 0, sizeof(s_der_buffer));
        if ((error = asn_put_universal_tlv(TOBJECT_IDENTIFIER,
                (void*) &p_enveloped_data->m_content_enc_alg_id,
                0,
                p_pkcs_15_token,
                &id)) != ak_error_ok)
            return ak_error_message(error, __func__, "problem with adding content encryption algorithm id");

        content_enc_alg_len = ps_get_full_size(&params) + ps_get_full_size(&id);
    }
    else
        return ak_error_message_fmt(ak_error_wrong_oid,
                __func__,
                "algorithm (%s) doesn't support",
                p_enveloped_data->m_content_enc_alg_id);

    if ((error = asn_put_universal_tlv(TSEQUENCE, NULL, content_enc_alg_len, p_pkcs_15_token, p_content_enc_alg_der))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding sequence tag and length");

    return error;
}

int pkcs_15_get_object_direct_protected(s_der_buffer* p_object_der, s_enveloped_data* p_enveloped_data)
{
    int error;
    tag tag;
    size_t len;
    uint8_t len_byte_cnt;
    s_der_buffer enveloped_data_der;

    tag = 0;
    len = 0;
    len_byte_cnt = 0;
    memset(&enveloped_data_der, 0, sizeof(s_der_buffer));

    if (!p_object_der || !p_enveloped_data)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONTEXT_SPECIFIC | CONSTRUCTED | 2u, p_object_der, (void*) &enveloped_data_der))
            != ak_error_ok)
    {
        if (error != ak_error_diff_tags)
            return ak_error_message(error, __func__, "problems with getting protected object in der");
        else
            return error;
    }

    if ((error = asn_get_expected_tlv(TINTEGER, &enveloped_data_der, (void*) &p_enveloped_data->m_version))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting gost enveloped data version");

    asn_get_tag(enveloped_data_der.mp_curr, &tag);
    if (tag == (CONTEXT_SPECIFIC | CONSTRUCTED | 0u))
    {
        ak_error_message(ak_error_invalid_value, __func__, "getting originator does not realized yet");
        if ((error = asn_get_len(enveloped_data_der.mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(&enveloped_data_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }

    if ((error = pkcs_15_get_recipient_infos(&enveloped_data_der, p_enveloped_data)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting recipient infos");

    if ((error = pkcs_15_get_encrypted_content_info(&enveloped_data_der, p_enveloped_data)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting encrypted content info");

    if (ps_get_curr_size(&enveloped_data_der))
    {
        ak_error_message(ak_error_invalid_value, __func__, "getting unprotected attributes doesn't realized yet");
        if ((error = asn_get_len(enveloped_data_der.mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(&enveloped_data_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }

    if (ps_get_curr_size(&enveloped_data_der) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_common_object_attributes(s_der_buffer* p_object_der, s_common_obj_attrs* p_obj_attrs)
{
    int error;
    s_der_buffer object_attrs;

    memset(&object_attrs, 0, sizeof(s_der_buffer));

    if (!p_object_der || !p_obj_attrs)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_object_der, (void*) &object_attrs)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting common object attributes in der");

    if ((error = asn_get_expected_tlv(TUTF8_STRING, &object_attrs, (void*) &p_obj_attrs->m_label)) != ak_error_ok)
    {
        if (error != ak_error_diff_tags)
            return ak_error_message(error, __func__, "problems with getting object lable");
    }

    if ((error = asn_get_expected_tlv(TBIT_STRING, &object_attrs, (void*) &p_obj_attrs->m_flags)) != ak_error_ok)
    {
        if (error != ak_error_diff_tags)
            return ak_error_message(error, __func__, "problems with getting object flags");
    }

    return ak_error_ok;
}

int pkcs_15_get_common_key_attributes(s_der_buffer* p_object_der, s_common_key_attrs* p_key_attrs)
{
    int error = ak_error_ok;
    s_der_buffer key_attrs;

    memset(&key_attrs, 0, sizeof(s_der_buffer));

    if (!p_object_der || !p_key_attrs)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_object_der, (void*) &key_attrs)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting common key attributes in der");

    if ((error = asn_get_expected_tlv(TOCTET_STRING, &key_attrs, (void*) &p_key_attrs->m_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key id");

    if ((error = asn_get_expected_tlv(TBIT_STRING, &key_attrs, (void*) &p_key_attrs->m_usage)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key usage flags");

    if (ps_get_curr_size(&key_attrs))
    {
        if ((error = asn_get_expected_tlv(TBOOLEAN, &key_attrs, (void*) &p_key_attrs->m_native)) != ak_error_ok)
        {
            if (error != ak_error_diff_tags)
                return ak_error_message(error, __func__, "problems with getting key native attribute");
            else
                p_key_attrs->m_native = true;
        }
    }

    if (ps_get_curr_size(&key_attrs))
    {
        if ((error = asn_get_expected_tlv(TBIT_STRING, &key_attrs, (void*) &p_key_attrs->m_access_flags)) !=
                ak_error_ok)
        {
            if (error != ak_error_diff_tags)
                return ak_error_message(error, __func__, "problems with getting key access flags");
        }
    }

    if (ps_get_curr_size(&key_attrs))
    {
        if ((error = asn_get_expected_tlv(TINTEGER, &key_attrs, (void*) &p_key_attrs->m_key_reference)) != ak_error_ok)
        {
            if (error != ak_error_diff_tags)
                return ak_error_message(error, __func__, "problems with getting key reference attribute");
        }
    }

    if (ps_get_curr_size(&key_attrs))
    {
        if ((error = asn_get_expected_tlv(TGENERALIZED_TIME, &key_attrs, (void*) &p_key_attrs->m_start_date)) !=
                ak_error_ok)
        {
            if (error != ak_error_diff_tags)
                return ak_error_message(error, __func__, "problems with getting key start date");
        }
    }

    if (ps_get_curr_size(&key_attrs))
    {
        // В переменную end_date_der запишется значение атрибута end date,
        // которое затем передается в функцию декодирования Generalized time
        s_der_buffer end_date_der;
        memset(&end_date_der, 0, sizeof(s_der_buffer));
        if ((error = asn_get_expected_tlv(CONTEXT_SPECIFIC | PRIMITIVE | 0u, &key_attrs, (void*) &end_date_der))
                != ak_error_ok)
        {
            if (error != ak_error_diff_tags)
                return ak_error_message(error, __func__, "problems with getting key end date");
            else
                return ak_error_invalid_token;
        }

        if ((error =
                     asn_get_generalized_time(end_date_der.mp_curr, ps_get_full_size(&end_date_der),
                             &p_key_attrs->m_end_date))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting key end date");
    }

    if (ps_get_curr_size(&key_attrs) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_recipient_infos(s_der_buffer* p_enveloped_data_der, s_enveloped_data* p_enveloped_data)
{
    int error;
    uint8_t num_of_ri;
    s_der_buffer recipient_infos_der;

    num_of_ri = 0;
    memset(&recipient_infos_der, 0, sizeof(s_der_buffer));

    if (!p_enveloped_data_der || !p_enveloped_data)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSET, p_enveloped_data_der, (void*) &recipient_infos_der))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting recipient infos in der");

    asn_get_num_of_elems_in_constructed_obj(&recipient_infos_der, &num_of_ri);
    p_enveloped_data->m_ri_size = num_of_ri;
    p_enveloped_data->mpp_recipient_infos = malloc(num_of_ri * sizeof(s_recipient_info));
    if (!p_enveloped_data->mpp_recipient_infos)
        return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

    for (uint8_t i = 0; i < num_of_ri; i++)
    {
        p_enveloped_data->mpp_recipient_infos[i] = malloc(sizeof(s_recipient_info));
        if (!p_enveloped_data->mpp_recipient_infos[i])
            return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

        if ((error = pkcs_15_get_sngl_recipient_info(&recipient_infos_der, p_enveloped_data->mpp_recipient_infos[i]))
                != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting single recipient info");
    }

    if (ps_get_curr_size(&recipient_infos_der) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_sngl_recipient_info(s_der_buffer* p_recipient_infos_der, s_recipient_info* p_sngl_recipient_info)
{
    int error;
    tag tag;
    size_t len;
    uint8_t len_byte_cnt;

    tag = 0;
    len = 0;
    len_byte_cnt = 0;

    if (!p_recipient_infos_der || !p_sngl_recipient_info)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    asn_get_tag(p_recipient_infos_der->mp_curr, &tag);
    switch (tag)
    {
    case (CONTEXT_SPECIFIC | CONSTRUCTED | PWRI):
        ak_error_message(ak_error_invalid_value,
                __func__,
                "getting password recipient info does not realized yet");
        if ((error = asn_get_len(p_recipient_infos_der->mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(p_recipient_infos_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        break;
    case (CONTEXT_SPECIFIC | CONSTRUCTED | KEKRI):p_sngl_recipient_info->m_type = KEKRI;
        p_sngl_recipient_info->m_ri.mp_kekri = malloc(sizeof(s_kekri));
        if (!p_sngl_recipient_info->m_ri.mp_kekri)
            return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

        if ((error = pkcs_15_get_kekri(p_recipient_infos_der, p_sngl_recipient_info->m_ri.mp_kekri)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting single recipient info");
        break;
    default:break;
    }

    return error;
}

int pkcs_15_get_kekri(s_der_buffer* p_recipient_infos_der, s_kekri* p_kekri)
{
    int error;
    s_der_buffer kekri_der;
    s_der_buffer kek_id_der;

    memset(&kekri_der, 0, sizeof(s_der_buffer));
    memset(&kek_id_der, 0, sizeof(s_der_buffer));

    if (!p_recipient_infos_der || !p_kekri)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONTEXT_SPECIFIC | CONSTRUCTED | KEKRI, p_recipient_infos_der,
            (void*) &kekri_der))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting kekri in der");

    if ((error = asn_get_expected_tlv(TINTEGER, &kekri_der, (void*) &p_kekri->m_version)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting kekri version");

    // ----- декодируем kekid, вложенный в sequence -----
    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, &kekri_der, (void*) &kek_id_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting kek id in der");

    if ((error = asn_get_expected_tlv(TOCTET_STRING, &kek_id_der, (void*) &p_kekri->m_key_identifire)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting kek id in der");

    if (ps_get_curr_size(&kek_id_der) != 0)
        return ak_error_invalid_token;
    // ----- конец декодирования kekid -----

    if ((error = pkcs_15_get_key_encryption_algorithm(&kekri_der, p_kekri)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key encryption algorithm");

    if ((error = asn_get_expected_tlv(TOCTET_STRING, &kekri_der, (void*) &p_kekri->m_encrypted_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting encrypted key (CEK)");

    if (ps_get_curr_size(&kekri_der) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_key_encryption_algorithm(s_der_buffer* p_kekri_der, s_kekri* p_kekri)
{
    int error;
    size_t len;
    uint8_t len_byte_cnt;
    s_der_buffer key_enc_ald_der;
    s_der_buffer prms_der;

    len = 0;
    len_byte_cnt = 0;
    memset(&key_enc_ald_der, 0, sizeof(s_der_buffer));
    memset(&prms_der, 0, sizeof(s_der_buffer));

    if (!p_kekri_der || !p_kekri)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_kekri_der, (void*) &key_enc_ald_der)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key encryption algorithm in der");

    if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER, &key_enc_ald_der, (void*) &p_kekri->m_key_enc_alg_id))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key encryption algorithm in der");

    if (0 == strcmp(p_kekri->m_key_enc_alg_id, "1.2.643.2.2.13.1"))
    {
        if (ps_get_curr_size(&key_enc_ald_der))
        {
            s_gost28147_89_key_wrap_prms* p_key_wrap_prms = malloc(sizeof(s_gost28147_89_key_wrap_prms));
            if (!p_key_wrap_prms)
                return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

            if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, &key_enc_ald_der, (void*) &prms_der))
                    != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting key wrap algorithm parameters in der");

            if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER, &prms_der, (void*) &p_key_wrap_prms->m_enc_prm_set))
                    != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting encryption parameters set oid");

            if (ps_get_curr_size(&prms_der))
            {
                if ((error = asn_get_expected_tlv(TOCTET_STRING, &prms_der, (void*) &p_key_wrap_prms->m_ukm))
                        != ak_error_ok)
                    return ak_error_message(error, __func__, "problems with getting ukm value");
            }

            p_kekri->m_prm_set_type = GOST_KEY_WRAP_SET;
            p_kekri->m_prm_set.p_key_wrap_set = p_key_wrap_prms;

            if (ps_get_curr_size(&prms_der) != 0)
                return ak_error_invalid_token;
        }

    }
    else
    {
        ak_error_message(ak_error_invalid_value, __func__, "this algorithm doesn't support");
        if ((error = asn_get_len(key_enc_ald_der.mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(&key_enc_ald_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }

    if (ps_get_curr_size(&key_enc_ald_der) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_encrypted_content_info(s_der_buffer* p_enveloped_data_der, s_enveloped_data* p_enveloped_data)
{
    int error;
    s_der_buffer enc_content_info;

    memset(&enc_content_info, 0, sizeof(s_der_buffer));

    if (!p_enveloped_data_der || !p_enveloped_data)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_enveloped_data_der, (void*) &enc_content_info))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting key encryption algorithm in der");

    if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER, &enc_content_info,
            (void*) &p_enveloped_data->m_content_type))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting content type oid");

    if ((error = pkcs_15_get_content_encryption_algorithm(&enc_content_info, p_enveloped_data)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting content encryption algorithm");

    if (ps_get_curr_size(&enc_content_info))
    {
        // В переменную enc_content запишется значение зашифрованных дынных,
        // которое затем передается в функцию декодирования octet string
        s_der_buffer enc_content;
        memset(&enc_content, 0, sizeof(s_der_buffer));
        if ((error = asn_get_expected_tlv(CONTEXT_SPECIFIC | PRIMITIVE | 0u, &enc_content_info, (void*) &enc_content))
                != ak_error_ok)
        {
            if (error != ak_error_diff_tags)
                return ak_error_message(error, __func__, "problems with getting encrypted content");
            else
                return ak_error_invalid_token;
        }

        if ((error = asn_get_octetstr(enc_content.mp_curr,
                ps_get_full_size(&enc_content),
                &p_enveloped_data->m_encrypted_content)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting key end date");
    }

    if (ps_get_curr_size(&enc_content_info) != 0)
        return ak_error_invalid_token;

    return error;
}

int pkcs_15_get_content_encryption_algorithm(s_der_buffer* p_encrypted_content_info_der,
        s_enveloped_data* p_enveloped_data)
{
    int error = ak_error_ok;
    size_t len;
    uint8_t len_byte_cnt;
    s_der_buffer content_enc_alg_der;
    s_der_buffer prms_der;

    len = 0;
    len_byte_cnt = 0;
    memset(&content_enc_alg_der, 0, sizeof(s_der_buffer));
    memset(&prms_der, 0, sizeof(s_der_buffer));

    if (!p_encrypted_content_info_der || !p_enveloped_data)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if ((error =
                 asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, p_encrypted_content_info_der,
                         (void*) &content_enc_alg_der))
            != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting content encryption algorithm in der");

    if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER,
            &content_enc_alg_der,
            (void*) &p_enveloped_data->m_content_enc_alg_id)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting content encryption algorithm in der");

    if (0 == strcmp(p_enveloped_data->m_content_enc_alg_id, "1.2.643.2.4.3.2.2"))
    {
        if (ps_get_curr_size(&content_enc_alg_der))
        {
            s_gost28147_89_prms* p_gost_prms = calloc(1, sizeof(s_gost28147_89_prms));
            if (!p_gost_prms)
                return ak_error_message(ak_error_out_of_memory, __func__, "alloc memory fail");

            if ((error = asn_get_expected_tlv(CONSTRUCTED | TSEQUENCE, &content_enc_alg_der, (void*) &prms_der))
                    != ak_error_ok)
                return ak_error_message(error,
                        __func__,
                        "problems with getting content encryption algorithm parameters in der");

            if ((error = asn_get_expected_tlv(TOCTET_STRING, &prms_der, (void*) &p_gost_prms->m_iv)) != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting iv value");

            if ((error = asn_get_expected_tlv(TOBJECT_IDENTIFIER, &prms_der,
                    (void*) &p_gost_prms->m_encryption_param_set))
                    != ak_error_ok)
                return ak_error_message(error, __func__, "problems with getting encryption parameters set oid");

            p_enveloped_data->m_prm_set_type = GOST_CONTENT_ENC_SET;
            p_enveloped_data->m_prm_set.p_content_enc_prm_set = p_gost_prms;

            if (ps_get_curr_size(&prms_der) != 0)
                return ak_error_invalid_token;
        }

    }
    else
    {
        ak_error_message(ak_error_invalid_value, __func__, "this algorithm doesn't support");
        if ((error = asn_get_len(content_enc_alg_der.mp_curr + 1, &len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        if ((error = ps_move_cursor(&content_enc_alg_der, len + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }

    if (ps_get_curr_size(&content_enc_alg_der) != 0)
        return ak_error_invalid_token;

    return error;
}

void pkcs_15_free_key_info(s_key_info* p_ki)
{
    if (p_ki)
    {
        asn_free_bitstr(&p_ki->m_supported_operations);
        // todo: p_ki->m_parameters_id
    }
}

void pkcs_15_free_enveloped_data(s_enveloped_data* p_ed)
{
    int i;
    if (p_ed)
    {
        asn_free_int(&p_ed->m_version);
        asn_free_octetstr(&p_ed->m_encrypted_content);
        asn_free_objid(&p_ed->m_content_enc_alg_id);

        switch (p_ed->m_prm_set_type)
        {
        case GOST_CONTENT_ENC_SET:asn_free_objid(&p_ed->m_prm_set.p_content_enc_prm_set->m_encryption_param_set);
            asn_free_octetstr(&p_ed->m_prm_set.p_content_enc_prm_set->m_iv);
            break;
        default:break;
        }

        asn_free_objid(&p_ed->m_content_type);
        if (!p_ed->mpp_recipient_infos)
        {
            for (i = 0; i < p_ed->m_ri_size; i++)
            {
                pkcs_15_free_recipient_info(p_ed->mpp_recipient_infos[i]);
                p_ed->mpp_recipient_infos[i] = NULL;
            }
            free(p_ed->mpp_recipient_infos);
            p_ed->mpp_recipient_infos = NULL;
        }
    }
}

void pkcs_15_free_recipient_info(s_recipient_info* p_ri)
{
    if (p_ri)
    {
        switch (p_ri->m_type)
        {
        case KEKRI:pkcs_15_free_kekri(p_ri->m_ri.mp_kekri);
            p_ri->m_ri.mp_kekri = NULL;
        default:break;
        }
    }
}

void pkcs_15_free_kekri(s_kekri* p_kekri)
{
    if (p_kekri)
    {
        asn_free_int(&p_kekri->m_version);
        switch (p_kekri->m_prm_set_type)
        {
        case GOST_KEY_WRAP_SET:asn_free_octetstr(&p_kekri->m_prm_set.p_key_wrap_set->m_ukm);
            asn_free_objid(&p_kekri->m_prm_set.p_key_wrap_set->m_enc_prm_set);
            break;
        default:break;
        }

        asn_free_octetstr(&p_kekri->m_encrypted_key);
        asn_free_octetstr(&p_kekri->m_key_identifire);
        asn_free_generalized_time(&p_kekri->m_date);
    }
}

void pkcs_15_free_common_key_attrs(s_common_key_attrs* p_cka)
{
    if (p_cka)
    {
        asn_free_octetstr(&p_cka->m_id);
        asn_free_bitstr(&p_cka->m_usage);
        asn_free_bitstr(&p_cka->m_access_flags);
        asn_free_int(&p_cka->m_key_reference);
        asn_free_generalized_time(&p_cka->m_start_date);
        asn_free_generalized_time(&p_cka->m_end_date);
    }
}

void pkcs_15_free_common_obj_attrs(s_common_obj_attrs* p_coa)
{
    if (p_coa)
    {
        asn_free_utf8string(&p_coa->m_label);
        asn_free_bitstr(&p_coa->m_flags);
    }
}
