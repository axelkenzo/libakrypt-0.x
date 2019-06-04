#include "ak_pkcs_15_token_manager.h"
#include <assert.h>

#include <ak_tools.h>
#include <ak_skey.h>

const object_identifier ALGORITHM_PBKDF2 = {"1.2.840.113549.1.5.12"};
const object_identifier HMAC_GOST_3411_12_512 = {"1.2.643.7.1.1.4.2"};
const object_identifier CRYPTO_PRO_PARAM_SET = {"1.2.643.7.1.2.5.1.1"};
const object_identifier KEY_TYPE_GOST = {"1.2.643.7.1.1.5.1"};
const object_identifier KEY_ENG_ALGORITHM = {"1.2.643.2.2.13.1"};
const object_identifier CONTENT_TYPE = {"1.2.840.113549.1.7.1"};
const object_identifier CONTENT_ENG_ALGORITHM = {"1.2.643.2.4.3.2.2"};
const object_identifier CRYPTO_PRO_PARAM_A = {"1.2.643.2.2.31.1"};

int set_asn_boolean(boolean *p_asn_1_bool, bool val) {

    if (!p_asn_1_bool)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    *p_asn_1_bool = val;

    return ak_error_ok;
}

int set_asn_utf8_string(utf8_string *p_asn_1_utf8_string, ak_pointer p_val) {

    /* Предполагается, что на вход фун-ции подается
     * массив байтов, в котором записана строка в кодировке UTF-8 */
    size_t size;

    if (!p_asn_1_utf8_string || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    size = strlen((char *) p_val) + 1;

    *p_asn_1_utf8_string = malloc(size * sizeof(char));
    if (!(*p_asn_1_utf8_string))
        return ak_error_message(ak_error_out_of_memory, __func__, "out of mem");

    memcpy((char *) *p_asn_1_utf8_string, (char *) p_val, size);

    return ak_error_ok;
}

int set_asn_visible_string(visible_string *p_asn_1_visible_string, const char *p_val) {

    size_t size;

    if (!p_asn_1_visible_string || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    size = strlen((char *) p_val) + 1;

    *p_asn_1_visible_string = (visible_string) malloc(size);
    if (!(*p_asn_1_visible_string))
        return ak_error_message(ak_error_out_of_memory, __func__, "out of mem");

    memcpy(*p_asn_1_visible_string, p_val, size);

    return ak_error_ok;
}

int set_asn_object_identifier(object_identifier *p_asn_1_object_identifier, const char *p_val) {

    if (!p_asn_1_object_identifier || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    *p_asn_1_object_identifier = (object_identifier) malloc(strlen(p_val) + 1);
    strcpy(*p_asn_1_object_identifier, p_val);

    return ak_error_ok;
}

int set_asn_integer(integer *p_asn_int, int32_t val) {

    byte *p_val;
    int32_t val_len;

    if (!p_asn_int)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_asn_int->m_positive = (val >= 0);
    val_len = p_asn_int->m_val_len = sizeof(val);

    if (val == 0 || val == -1)
    {
        p_asn_int->mp_value = malloc(sizeof(byte));
        *p_asn_int->mp_value = val;
        p_asn_int->m_val_len = 1;
        return ak_error_ok;
    }

    if (p_asn_int->m_positive)
    {
        int8_t i = sizeof(val) - 1;
        while (!((val >> (i * 8u)) & 0xFF) && (i >= 0))
        {
            val_len = p_asn_int->m_val_len -= 1;
            i -= 1;
        }
    }
    else
    {
        // todo допилить реализацию добавления отрицательного числа
        //int8_t i = sizeof(val) - 1;
        while ((((val >> ((val_len - 1) * 8u)) & 0xFF) == 0xFF) && (val_len - 1 >= 0))
        {
            val_len = p_asn_int->m_val_len -= 1;
            //i -= 1;
        }
    }

    p_val = p_asn_int->mp_value = (byte *) malloc(val_len);

    if (val_len == 1)
        *p_val = (byte) val;
    else
    {
        while (--val_len >= 0)
            *(p_val++) = (byte) ((val >> (8u * val_len)) & 0xFFu);
    }

    return ak_error_ok;
}

int set_asn_bit_string(bit_string *p_asn_1_bit_string, const byte *p_val, uint32_t size, uint8_t num_of_unused_bits) {

    if (!p_asn_1_bit_string || !p_val || (size <= 0) || (num_of_unused_bits <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_asn_1_bit_string->mp_value = (byte *) malloc(size);
    p_asn_1_bit_string->m_val_len = size;
    p_asn_1_bit_string->m_unused = num_of_unused_bits;

    memcpy(p_asn_1_bit_string->mp_value, p_val, size);

    return ak_error_ok;
}

int set_asn_octet_string(octet_string *p_asn_1_octet_string, const byte *p_val, uint32_t size) {

    if (!p_asn_1_octet_string || !p_val || (size <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_asn_1_octet_string->mp_value = (byte *) malloc(size);
    p_asn_1_octet_string->m_val_len = size;

    memcpy(p_asn_1_octet_string->mp_value, p_val, size);

    return ak_error_ok;
}

int asn_integer_to_int64(integer *p_asn_val, ak_int64 *p_value) {

    size_t i;

    if (!p_asn_val || !p_value)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if (p_asn_val->m_val_len > sizeof(ak_int64) || (p_asn_val->m_positive && (p_asn_val->mp_value[0] & 0x80)))
        return ak_error_message(ak_error_invalid_value, __func__, "invalid value");

    *p_value = 0;
    for (i = 0; i < p_asn_val->m_val_len; i++)
    {
        *p_value ^= p_asn_val->mp_value[i];
        if (i != p_asn_val->m_val_len - 1)
            *p_value = (*p_value) << 8;
    }

    return ak_error_ok;
}

int asn_utf8_to_byte_arr(utf8_string *p_src, byte **pp_dst) {
    size_t str_size;

    if (!p_src)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    str_size = strlen((char *) p_src) + 1;
    *pp_dst = malloc(str_size);
    if (!*pp_dst)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    memcpy(*pp_dst, p_src, str_size);

    return ak_error_ok;
}

int asn_generalized_time_to_date(generalized_time time, date date) {
    //TODO проверка??

    char *p_next_num;

    /* year */
    date[0] = (unsigned int) strtoul(time, &p_next_num, 10);
    /* month */
    date[1] = (unsigned int) strtoul(p_next_num + 1, &p_next_num, 10);
    /* day */
    date[2] = (unsigned int) strtoul(p_next_num + 1, &p_next_num, 10);
    /* hours */
    date[3] = (unsigned int) strtoul(p_next_num + 1, &p_next_num, 10);
    /* minutes */
    date[4] = (unsigned int) strtoul(p_next_num + 1, &p_next_num, 10);
    /* seconds */
    date[5] = (unsigned int) strtoul(p_next_num + 1, &p_next_num, 10);

    return ak_error_ok;
}

int set_usage_flags(bit_string asn_val, key_usage_flags_t *flags) {
    if (asn_val.m_val_len > 2)
        return ak_error_message(ak_error_invalid_value, __func__, "invalid input value");

    *flags = 0;
    *flags ^= asn_val.mp_value[0];
    *flags = *flags << 8;

    if (asn_val.m_val_len == 2)
        *flags ^= asn_val.mp_value[1];

    return ak_error_ok;
}

int set_key_id(octet_string id, ak_skey p_key) {

    //TODO проверка??

    // Если под хранение идентификатора недостаточно памяти, то перевыделяем ее
    if (p_key->number.size < id.m_val_len)
    {
        p_key->number.free(&p_key->number);
        p_key->number.alloc(id.m_val_len);
        if (!p_key->number.data)
            return ak_error_null_pointer;
    }
    memcpy(p_key->number.data, id.mp_value, id.m_val_len);
    p_key->number.size = id.m_val_len;

    return ak_error_ok;
}

int date_to_asn_generalized_time(date current_date, generalized_time *result) {

    //TODO проверка??

    generalized_time date_time = (generalized_time) malloc(strlen("YYYY-MM-DD HH:MM:SS UTC") + 1);

    // Корректные значения года: диапазон от 1970 до 9999
    if (current_date[0] < 1970 || current_date[0] > 9999)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "invalid year input value");
    }

    // Корректные значения месяца: диапазон от 1 до 12
    if (current_date[1] < 1 || current_date[1] > 12)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "invalid month input value");
    }

    // Корректные значения дня: диапазон от 1 до 31
    if (current_date[2] < 1 || current_date[2] > 31)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "invalid day input value");
    }

    // Корректные значения часа: диапазон от 0 до 23
    if (current_date[3] < 0 || current_date[3] > 23)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "invalid hour input value");
    }

    // Корректные значения минуты: диапазон от 0 до 59
    if (current_date[4] < 0 || current_date[4] > 59)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "invalid minute input value");
    }

    // Корректные значения секунды: диапазон от 0 до 59
    if (current_date[5] < 0 || current_date[5] > 59)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "invalid second input value");
    }

    sprintf(date_time, "%d-%02d-%02d %02d:%02d:%02d UTC",
            current_date[0], current_date[1], current_date[2],
            current_date[3], current_date[4], current_date[5]);

    *result = date_time;

    return ak_error_ok;
}

int generate_random_bytes(octet_string *p_data, const size_t size) {

    int error;
    ak_context_manager p_context;

    if (!p_data || (size <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_context = ak_libakrypt_get_context_manager();

    p_data->mp_value = malloc(size * sizeof(p_data->mp_value));
    p_data->m_val_len = size;

    if (!p_data->mp_value)
    {
        return ak_error_message(ak_error_null_pointer, __func__, "null value");
    }

    if ((error = (p_context->key_generator.random(&p_context->key_generator, p_data->mp_value, p_data->m_val_len)))
        != ak_error_ok)
    {
        return ak_error_message(error, __func__, "error in generating random bytes");
    }

    return ak_error_ok;
}

static int pkcs_15_kek_generator(ak_bckey p_key, ak_pointer password, size_t pwd_len, s_key_management_info *p_kmi) {
    int error;
    ak_int64 iteration_cnt;
    ak_int64 key_len;
    s_pwd_info *p_pwd_info;

    if (p_kmi->m_type != PWD_INFO)
        return ak_error_message(ak_error_invalid_value, __func__,
                                "only key management info with password info support");

    p_pwd_info = p_kmi->m_key_info.mp_pwd_info;

    if ((strcmp(p_pwd_info->m_algorithm, "1.2.840.113549.1.5.12") != 0)
        || (strcmp(p_pwd_info->m_prf_id, "1.2.643.7.1.1.4.2") != 0))
    {
        return ak_error_message(ak_error_invalid_value, __func__, "unallowed algorithm");
    }

    if (!p_pwd_info->m_iteration_count.mp_value)
        return ak_error_message(ak_error_invalid_value, __func__, "iteration count absent");

    /* Устанавливаем длину ключа (если в контейнере есть значение, то записываем его, иначе устанавливаем константное) */
    key_len = 32;
    if (p_pwd_info->m_key_len.mp_value)
    {
        if ((error = asn_integer_to_int64(&p_pwd_info->m_key_len, &key_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "can't get key length");
    }

//    /* Создаем контекст секретного ключа */
//    if((error = ak_skey_context_create(p_key, (size_t)key_len, 8)) != ak_error_ok)
//        return ak_error_message(error, __func__, "can't create secret key context");

    /* Присваиваем ключу идентификатор, указанный в поле keyId структуры KeyManagementInfo */
    set_key_id(p_kmi->m_key_id, &p_key->key);

    /* Устанвливаем кол-во итераций */
    if ((error = asn_integer_to_int64(&p_pwd_info->m_iteration_count, &iteration_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "can't get iteration count");

    if ((error = ak_libakrypt_set_option("pbkdf2_iteration_count", iteration_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "can't set iteration count value");

    /* Генерируем ключ */
    if ((error = ak_bckey_context_set_key_from_password(p_key,
                                                        password,
                                                        pwd_len,
                                                        p_pwd_info->m_salt.mp_value,
                                                        p_pwd_info->m_salt.m_val_len)) != ak_error_ok)
        return ak_error_message(error, __func__, "can't create key from password");

    return ak_error_ok;
}

static int fill_enveloped_data(ak_skey sec_key, s_enveloped_data *enveloped_data, ak_bckey kek) {

    int error;
    ak_context_manager p_context;
    struct bckey cek;
    struct buffer gost_key_der;
    byte mac[4];
    s_gost28147_89_prms *p_content_enc_prms;
    octet_string iv;
    s_kekri *kekri;
    s_gost28147_89_key_wrap_prms *p_key_wrap_prms;
    byte ukm[8];
    struct buffer cek_plus_mask;
    struct buffer encrypted_key_mac;
    struct buffer encrypted_key_der;
    s_recipient_info **recipient_infos;
    s_recipient_info *recipient_info;
    uint8_t recipient_infos_size;

    // Пример заполнения mac и ukm
    for (int i = 0; i < 4; ++i)
    {
        mac[i] = 0xFF;
    }

    for (int i = 0; i < 8; ++i)
    {
        ukm[i] = 0xFF;
    }

    recipient_infos_size = 1;


    if (!sec_key || !enveloped_data || !kek)
    {
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");
    }

    // Заполняем version
    set_asn_integer(&enveloped_data->m_version, 2);

    // Создаем Content Encryption Key

    if ((error = ak_bckey_context_create_magma(&cek)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with magma context creation");
    }

    p_context = ak_libakrypt_get_context_manager();

    if ((error = ak_bckey_context_set_key_random(&cek, &p_context->key_generator)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with cek generation");
    }

    // Подготоваливаем даннные к шифрованию

    if ((error = ak_buffer_create(&gost_key_der)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with ak buffer creation");
    }

    if ((error =
                 pkcs_15_make_gost_key_value_mask(&sec_key->key, &sec_key->mask, sec_key->resource.value.counter,
                                                  &gost_key_der))
        != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with gost key mask setting");
    }


    // Зашифровываем подготовленную DER - последовательность и считаем имитовставку
    //TODO вызываем фнукцию шифрования gost_key_der
    //TODO добавляем имитовставку (mac var)

    // Заполняем encryptedContentInfo

    // Заполняем encryptedContent
    enveloped_data->m_encrypted_content.m_val_len = gost_key_der.size + sizeof(mac);
    enveloped_data->m_encrypted_content.mp_value = (byte *) malloc(enveloped_data->m_encrypted_content.m_val_len);

    if (!enveloped_data->m_encrypted_content.mp_value)
    {
        return ak_error_null_pointer;
    }

    memcpy(enveloped_data->m_encrypted_content.mp_value, gost_key_der.data, gost_key_der.size);
    memcpy(enveloped_data->m_encrypted_content.mp_value + gost_key_der.size, mac, sizeof(mac));

    if ((error = ak_buffer_destroy(&gost_key_der)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with buffer destroy");
    }

    // Заполняем contentEncryptionAlgorithm
    set_asn_object_identifier(&enveloped_data->m_content_enc_alg_id, CONTENT_ENG_ALGORITHM);
    p_content_enc_prms = calloc(1, sizeof(s_gost28147_89_prms));

    if ((error = generate_random_bytes(&iv, 8)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with iv generation");
    }

    set_asn_octet_string(&p_content_enc_prms->m_iv, iv.mp_value, iv.m_val_len);
    set_asn_object_identifier(&p_content_enc_prms->m_encryption_param_set, CRYPTO_PRO_PARAM_A);

    enveloped_data->m_prm_set_type = GOST_CONTENT_ENC_SET;
    enveloped_data->m_prm_set.p_content_enc_prm_set = p_content_enc_prms;

    // Заполняем contentType
    set_asn_object_identifier(&enveloped_data->m_content_type, CONTENT_TYPE);

    // Заполняем recipientInfos

    // Kekri
    kekri = calloc(1, sizeof(s_kekri));

    set_asn_integer(&kekri->m_version, 4); // всегда равно 4 по стандарту RFC-5652

    set_asn_octet_string(&kekri->m_key_identifire, kek->key.number.data, kek->key.number.size);

    set_asn_object_identifier(&kekri->m_key_enc_alg_id, KEY_ENG_ALGORITHM);
    p_key_wrap_prms = calloc(1, sizeof(s_gost28147_89_key_wrap_prms));

    //TODO добавляем значения для wrapping
    // TODO заменить на реальное значение ukm
    set_asn_octet_string(&p_key_wrap_prms->m_ukm, ukm, sizeof(ukm));
    set_asn_object_identifier(&p_key_wrap_prms->m_enc_prm_set, CRYPTO_PRO_PARAM_A);

    kekri->m_prm_set_type = GOST_KEY_WRAP_SET;
    kekri->m_prm_set.p_key_wrap_set = p_key_wrap_prms;

    // Шифруем CEK при помощи KEK

    if ((error = ak_buffer_create_size(&cek_plus_mask, cek.key.key.size + cek.key.mask.size)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with cek + mask buffer creation");
    }

    memcpy(cek_plus_mask.data, cek.key.key.data, cek.key.key.size);
    memcpy((byte *) cek_plus_mask.data + cek.key.key.size, cek.key.mask.data, cek.key.mask.size);

    // TODO Заменить на реальное значение

    if ((error = ak_buffer_create(&encrypted_key_mac)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with encrypted key mac buffer creation");
    }

    encrypted_key_mac.data = mac;
    encrypted_key_mac.size = sizeof(mac);

    if ((error = ak_buffer_create(&encrypted_key_der)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with encrypted key der buffer creation");
    }

    if ((error = pkcs_15_make_enc_key_plus_mac_seq(&cek_plus_mask, &encrypted_key_mac, &encrypted_key_der))
        != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with encrypted key + mac sequence creation");
    }

    if ((error = ak_buffer_destroy(&cek_plus_mask)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with cek + mask buffer destroy");
    }

    if ((error = ak_buffer_destroy(&encrypted_key_mac)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with encrypted key mac buffer destroy");
    }

    set_asn_octet_string(&kekri->m_encrypted_key, encrypted_key_der.data, encrypted_key_der.size);

    if ((error = ak_buffer_destroy(&encrypted_key_der)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with encrypted key der buffer destroy");
    }

    recipient_info = malloc(sizeof(s_recipient_info));// = {KEKRI, &kekri};

    recipient_info->m_type = KEKRI;
    recipient_info->m_ri.mp_kekri = kekri;

    //Данная реадизация позволяет хранить только один объект recipientInfo, а именно KEKRI
    recipient_infos = malloc(sizeof(s_recipient_info *) * recipient_infos_size);
    recipient_infos[0] = recipient_info;

    enveloped_data->mpp_recipient_infos = recipient_infos;
    enveloped_data->m_ri_size = recipient_infos_size;

    if ((error = ak_bckey_context_destroy(&cek)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with cek destroy");
    }

    return ak_error_ok;
}

static int put_key_management_info(s_key_management_info *current_key_info, ak_buffer key_id) {

    int error;
    ak_int64 pbkdf2_iteration_count; // значение номера для pbkdf2_iteration_count
    s_pwd_info *pwd_info; // структура passwordInfo

    if (!current_key_info || !key_id)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    pwd_info = calloc(1, sizeof(s_pwd_info));

    // TODO Заполняем hint (если нужно необходимо добавить)

    set_asn_object_identifier(&pwd_info->m_algorithm, ALGORITHM_PBKDF2);

    if ((error = generate_random_bytes(&pwd_info->m_salt, 8)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with salt generation");
    }

    pbkdf2_iteration_count = ak_libakrypt_get_option("pbkdf2_iteration_count");
    set_asn_integer(&pwd_info->m_iteration_count, pbkdf2_iteration_count);

    set_asn_integer(&pwd_info->m_key_len, 32); // Всегда 32

    set_asn_object_identifier(&pwd_info->m_prf_id, HMAC_GOST_3411_12_512);

    set_asn_octet_string(&current_key_info->m_key_id, key_id->data, key_id->size);

    current_key_info->m_type = PWD_INFO;
    current_key_info->m_key_info.mp_pwd_info = pwd_info;

    return ak_error_ok;
}

static int put_gost_secret_key(s_gost_sec_key *gost_sec_key, struct extended_key *p_inp_keys, ak_bckey kek) {

    int error;
    s_common_obj_attrs obj_attrs;
    s_common_key_attrs common_key_attrs;
    byte key_usage_flags[2];

    key_usage_flags[0] = (byte) ((p_inp_keys->flags >> 8) & 0xFFu);
    key_usage_flags[1] = (byte) (p_inp_keys->flags & 0xFF);

    if (!gost_sec_key || !p_inp_keys || !kek)
    {
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");
    }

    // CommonObjectAttributes
    memset(&obj_attrs, 0, sizeof(obj_attrs));
    // Заполняем label
    set_asn_utf8_string(&obj_attrs.m_label, p_inp_keys->label);

    // Записываем в s_gost_sec_key
    gost_sec_key->m_obj_attrs = obj_attrs;

    // CommonKeyAttributes
    memset(&common_key_attrs, 0, sizeof(s_common_key_attrs));

    // Заполняем iD
    set_asn_octet_string(&common_key_attrs.m_id, p_inp_keys->key.sec_key->key.number.data,
                         p_inp_keys->key.sec_key->key.number.size);

    // Заполняем usage
    set_asn_bit_string(&common_key_attrs.m_usage, key_usage_flags, sizeof(key_usage_flags), 6);

    // Заполняем native константным значением
    set_asn_boolean(&common_key_attrs.m_native, true);

    // Заполняем startDate
    date_to_asn_generalized_time(p_inp_keys->start_date, &common_key_attrs.m_start_date);

    // Заполняем endDate
    date_to_asn_generalized_time(p_inp_keys->end_date, &common_key_attrs.m_end_date);

    // Записываем в s_gost_sec_key
    gost_sec_key->m_key_attrs = common_key_attrs;

    set_asn_object_identifier(&gost_sec_key->m_key_type_gost, KEY_TYPE_GOST);

    if ((error = fill_enveloped_data(&p_inp_keys->key.sec_key->key, &gost_sec_key->m_enveloped_data, kek))
        != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with fill of enveloped data");
    }

    return ak_error_ok;
}

static int decrypt_content_enc_key(s_recipient_info *p_recipient_info, ak_skey p_kek, ak_skey p_cek) {
    int error;
    struct buffer encrypted_cek;
    struct buffer encrypted_cek_mac;

    if (p_recipient_info->m_type != KEKRI)
        return ak_error_message(ak_error_invalid_value, __func__, "only kekri support");

    s_kekri *p_kekri = p_recipient_info->m_ri.mp_kekri;

    /* Создаем контекст ключа KEK */
    // Сравниваем идентификатор ключа из структуры KeyManagementInfo и KEKRI
    if (memcmp(p_kekri->m_key_identifire.mp_value, p_kek->number.data, p_kek->number.size) != 0)
        return ak_error_message(ak_error_invalid_value,
                                __func__,
                                "id from kekri doesn't match id from key management info");

    if ((error = pkcs_15_parse_enc_key_plus_mac_seq(p_kekri->m_encrypted_key, &encrypted_cek, &encrypted_cek_mac))
        != ak_error_ok)
        return ak_error_message(error, __func__, "problem with parsing CEK");

    /*TODO: комментарий для Алексея Юрьевича: здесь необходимо вызвать
            фунцию расшифрования ключа CEK и сравнить имитовставку.
            Данные для расшифрования находятся в переменной encrypted_cek. */

    memcpy((byte *) p_cek->key.data, (byte *) encrypted_cek.data, encrypted_cek.size / 2);
    memcpy((byte *) p_cek->mask.data, (byte *) encrypted_cek.data + encrypted_cek.size / 2, encrypted_cek.size / 2);

    /* Устанавливаем флаги наличия ключа и маски */
    p_cek->flags |= skey_flag_set_key | skey_flag_set_mask;

    /* Перемаскируем ключ */
    if ((error = p_cek->set_mask(p_cek)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with key remasking");

    /* Вычисляем контрольную сумму ключа */
    if ((error = p_cek->set_icode(p_cek)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with setting icode");

    /* Устанавливаем флаг наличия контрольной суммы */
    p_cek->flags |= skey_flag_set_icode;

    return ak_error_ok;
}

static int decrypt_enveloped_data(s_enveloped_data *p_enveloped_data, ak_skey p_kek, ak_skey p_libakrypt_key) {
    int error;
    struct bckey cek;
    struct buffer encrypted_content;
    struct buffer encrypted_content_mac;
    struct buffer iv;
    s_gost28147_89_prms *p_content_enc_prms;

    assert(p_enveloped_data && p_kek && p_libakrypt_key);

    /* Проверяем наличие информации Recipient info */
    if (!p_enveloped_data->m_ri_size)
        return ak_error_message(ak_error_invalid_value, __func__, "recipient info absent");


    /* Определяем алгоритм шифрования контента */
    if (!p_enveloped_data->m_content_enc_alg_id)
        return ak_error_message(ak_error_invalid_value,
                                __func__,
                                "encrypted_content encryption algorithm identifier absent");

    if (strcmp(p_enveloped_data->m_content_enc_alg_id, "1.2.643.2.4.3.2.2") == 0)
        ak_bckey_context_create_magma(&cek);
    else if (strcmp(p_enveloped_data->m_content_enc_alg_id, "1.2.643.2.4.3.2.3") == 0)
        ak_bckey_context_create_kuznechik(&cek);
    else
        return ak_error_message_fmt(ak_error_invalid_value,
                                    __func__,
                                    "this algorithm ('%s') doesn't support",
                                    p_enveloped_data->m_content_enc_alg_id);

    /* Устанавливаем параметры шифрования */
    if (p_enveloped_data->m_prm_set_type != GOST_CONTENT_ENC_SET)
        return ak_error_message(ak_error_invalid_value, __func__, "only CryptoPro parameters support");

    //TODO: Разобраться с идентификатором набора параметров
    p_content_enc_prms = p_enveloped_data->m_prm_set.p_content_enc_prm_set;

    if (!p_content_enc_prms->m_iv.mp_value)
        return ak_error_message(ak_error_invalid_value, __func__, "initialization vector absent");

    ak_buffer_create(&iv);
    ak_buffer_set_ptr(&iv, p_content_enc_prms->m_iv.mp_value, p_content_enc_prms->m_iv.m_val_len, ak_true);

    /* Расшифровываем ключ шифрования контента (CEK) */
    if ((error = decrypt_content_enc_key(p_enveloped_data->mpp_recipient_infos[0], p_kek, &cek.key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with decrypting CEK");

    /* Расшифровываем контент */
    ak_buffer_create_size(&encrypted_content, p_enveloped_data->m_encrypted_content.m_val_len - 4);
    memcpy(encrypted_content.data, p_enveloped_data->m_encrypted_content.mp_value, encrypted_content.size);
    ak_buffer_create_size(&encrypted_content_mac, 4);
    memcpy(encrypted_content_mac.data,
           p_enveloped_data->m_encrypted_content.mp_value + encrypted_content.size,
           encrypted_content_mac.size);

    /*TODO: комментарий для Алексея Юрьевича: здесь необходимо вызвать
            фунцию расшифрования данных и сравнить имитовставку */

    /* Переносим значение ключа, маски, счетчика в структуру skey */
    if ((error = pkcs_15_parse_gost_key_value_mask(&encrypted_content,
                                                   &p_libakrypt_key->key,
                                                   &p_libakrypt_key->mask,
                                                   &p_libakrypt_key->resource.value.counter)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with parsing key value mask");

    /* Устанавливаем флаги наличия ключа и маски */
    p_libakrypt_key->flags |= skey_flag_set_key | skey_flag_set_mask;

    /* Перемаскируем ключ */
    if ((error = p_libakrypt_key->set_mask(p_libakrypt_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with key remasking");

    /* Вычисляем контрольную сумму ключа */
    if ((error = p_libakrypt_key->set_icode(p_libakrypt_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with setting icode");

    /* Устанавливаем флаг наличия контрольной суммы */
    p_libakrypt_key->flags |= skey_flag_set_icode;

    return ak_error_ok;
}

static int get_extended_key(s_pkcs_15_object *p_obj, struct skey *p_kek, struct extended_key *p_key) {
    int error;
    s_gost_sec_key *p_pkcs_sec_key;
    ak_bckey p_libakrypt_sec_key;

    assert(p_obj && p_kek && p_key);

    if (p_obj->m_type != SEC_KEY)
        return ak_error_message(ak_error_invalid_value, __func__, "only secret key support");

    p_key->key_type = SEC_KEY;

    p_pkcs_sec_key = p_obj->m_obj.mp_sec_key;

    /* Создаем контекст секретного ключа */
    p_libakrypt_sec_key = calloc(1, sizeof(struct bckey));
    if (strcmp(p_pkcs_sec_key->m_key_type_gost, "1.2.643.7.1.1.5.1") == 0)
        ak_bckey_context_create_magma(p_libakrypt_sec_key);
    else if (strcmp(p_pkcs_sec_key->m_key_type_gost, "1.2.643.7.1.1.5.2") == 0)
        ak_bckey_context_create_kuznechik(p_libakrypt_sec_key);
    else
        return ak_error_message(ak_error_invalid_value, __func__, "only R 34.11 - 2015 key support");

    /* Заполняем общие атрибуты (объектов, ключей, секретных ключей) */
    // метка ключа
    if (p_pkcs_sec_key->m_obj_attrs.m_label)
    {
        p_key->label = malloc(strlen((char *) p_pkcs_sec_key->m_obj_attrs.m_label) + 1);
        strcpy((char *) p_key->label, (char *) p_pkcs_sec_key->m_obj_attrs.m_label);
        //asn_utf8_to_byte_arr(&p_pkcs_sec_key->m_obj_attrs.m_label, &p_key->key_label);
    }

    // уникальный идентификатор ключа
    set_key_id(p_pkcs_sec_key->m_key_attrs.m_id, &p_libakrypt_sec_key->key);

    // флаги предназначения ключа
    set_usage_flags(p_pkcs_sec_key->m_key_attrs.m_usage, &p_key->flags);

    // дата начала периода действия ключа
    if (p_pkcs_sec_key->m_key_attrs.m_start_date)
        asn_generalized_time_to_date(p_pkcs_sec_key->m_key_attrs.m_start_date, p_key->start_date);

    // дата окончания периода действия ключа
    if (p_pkcs_sec_key->m_key_attrs.m_end_date)
        asn_generalized_time_to_date(p_pkcs_sec_key->m_key_attrs.m_end_date, p_key->end_date);

    /* Расшифровываем ключ */
    if ((error = decrypt_enveloped_data(&p_pkcs_sec_key->m_enveloped_data, p_kek, &p_libakrypt_sec_key->key))
        != ak_error_ok)
    {
        ak_bckey_context_destroy(p_libakrypt_sec_key);
        return ak_error_message(error, __func__, "problem with decrypting enveloped data");
    }

    p_key->key.sec_key = p_libakrypt_sec_key;

    return ak_error_ok;
}

int read_keys_from_container(byte *password,
                             size_t pwd_size,
                             byte *inp_container,
                             size_t inp_container_size,
                             struct extended_key ***ppp_out_keys,
                             ak_uint8 *num_of_out_keys) {

    int error;
    uint8_t i;
    s_pkcs_15_token main_token;
    struct bckey kek;
    struct extended_key **pp_keys;

    memset(&main_token, 0, sizeof(main_token));

    /* Разбираем контейнер */
    if ((error = pkcs_15_parse_token(inp_container, inp_container_size, &main_token)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with parsing container");
    }

    if (!main_token.m_info_size)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "key management info absent");
    }

    if (!main_token.m_obj_size)
    {
        return ak_error_message(ak_error_invalid_value, __func__, "objects absent");
    }

    /* Создаем ключ KEK */
    //TODO FIX
    ak_bckey_context_create_magma(&kek);
    pkcs_15_kek_generator(&kek, password, pwd_size, main_token.mpp_key_infos[0]);

    /* Расшифровываем данные и создаем объекты extended_key */
    pp_keys = malloc(main_token.m_obj_size * sizeof(struct extended_key *));
    if (!pp_keys)
        return ak_error_message(ak_error_null_pointer, __func__, "alloc memory fail");

    *num_of_out_keys = 0;
    for (i = 0; i < main_token.m_obj_size; i++)
    {
        pp_keys[i] = calloc(1, sizeof(struct extended_key));
        if (!pp_keys[i])
            return ak_error_message(ak_error_null_pointer, __func__, "alloc memory fail");

        if (get_extended_key(main_token.mpp_pkcs_15_objects[i], &kek.key, pp_keys[i]) != ak_error_ok)
            pp_keys[i] = NULL;
        else
            *num_of_out_keys += 1;
    }

    /* Освобождаем память */
    free_pkcs_15_token(&main_token);

    *ppp_out_keys = pp_keys;

    return ak_error_ok;
}

int write_keys_to_container(struct extended_key **pp_inp_keys,
                            ak_uint8 num_of_inp_keys,
                            ak_pointer password,
                            size_t password_size,
                            byte **pp_out_container,
                            size_t *p_out_container_size) {

    int error;
    struct bckey kek;
    s_pkcs_15_token main_token;
    s_key_management_info *p_kmi;
    size_t token_obj_ind;

    if (!(*pp_inp_keys) || (num_of_inp_keys < 0) || !password || (password_size <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    // Создание токена
    memset(&main_token, 0, sizeof(s_pkcs_15_token));

    // Заполняем верхнюю часть PKCS15Token
    set_asn_integer(&main_token.m_version, 0);

    //Данная реадизация позволяет хранить только один объект KeyManagementInfo, а именно passwordInfo
    main_token.m_info_size = 1;
    main_token.mpp_key_infos = malloc(sizeof(s_key_management_info *) * main_token.m_info_size);


    // Возможно может быть другой ak_bckey_context
    if ((error = ak_bckey_context_create_magma(&kek)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with magma context creation");
    }

    p_kmi = (s_key_management_info *) calloc(1, sizeof(s_key_management_info));

    if ((error = put_key_management_info(p_kmi, &kek.key.number)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with fill of key management info");
    }

    main_token.mpp_key_infos[0] = p_kmi;

    if ((error = pkcs_15_kek_generator(&kek, password, password_size, p_kmi)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "generation key from password failed!");
    }

    main_token.mpp_pkcs_15_objects = calloc(num_of_inp_keys, sizeof(s_pkcs_15_object *));
    main_token.m_obj_size = num_of_inp_keys;

    token_obj_ind = 0;

    // Заполняем PKCS15Objects
    for (ak_uint32 i = 0; i < num_of_inp_keys; i++)
    {

        s_pkcs_15_object *current_pkcs15_object = (s_pkcs_15_object *) calloc(1, sizeof(s_pkcs_15_object));

        // Определеяем тип pkcs15_object
        switch (pp_inp_keys[i]->key_type)
        {
            case PRI_KEY:

                //TODO реализовать

                ak_error_message(ak_error_invalid_value, __func__, "private key support not implemented yet!");
                --main_token.m_obj_size;
                free(current_pkcs15_object);
                current_pkcs15_object = NULL;
                break;

            case PUB_KEY:

                //TODO реализовать

                ak_error_message(ak_error_invalid_value, __func__, "public key support not implemented yet!");
                --main_token.m_obj_size;
                free(current_pkcs15_object);
                current_pkcs15_object = NULL;
                break;

            case SEC_KEY:

                current_pkcs15_object->m_obj.mp_sec_key = (s_gost_sec_key *) calloc(1, sizeof(s_gost_sec_key));
                current_pkcs15_object->m_type = SEC_KEY;

                if ((error = put_gost_secret_key(current_pkcs15_object->m_obj.mp_sec_key, pp_inp_keys[i], &kek))
                    != ak_error_ok)
                {
                    return ak_error_message(error, __func__, "problem with fill of gost secret key");
                }

                break;

            default:
                ak_error_message(ak_error_invalid_value, __func__, "unsupported type of object!");
                --main_token.m_obj_size;
                free(current_pkcs15_object);
                current_pkcs15_object = NULL;
                break;
        }

        if (current_pkcs15_object != NULL)
        {
            main_token.mpp_pkcs_15_objects[token_obj_ind] = current_pkcs15_object;
            ++token_obj_ind;
        }

    }

    // Получаем DER - последовательность
    if ((error = pkcs_15_generate_token(&main_token, pp_out_container, p_out_container_size)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with generation of DER sequence");
    }

    // Освобождаем память
    //TODO добавить код возврата
    free_pkcs_15_token(&main_token);

    if ((error = ak_bckey_context_destroy(&kek)) != ak_error_ok)
    {
        return ak_error_message(error, __func__, "problem with kek destroy");
    }

    return ak_error_ok;
}

char *key_usage_flags_to_str(key_usage_flags_t flags) {
    if (flags == 0)
        return NULL;

    char *str = calloc(112, sizeof(char));
    if (flags & ENCRYPT)
    { strcat(str, "ENCRYPT | "); }
    if (flags & DECRYPT)
    { strcat(str, "DECRYPT | "); }
    if (flags & SIGN)
    { strcat(str, "SIGN | "); }
    if (flags & SIGN_RECOVER)
    { strcat(str, "SIGN_RECOVER | "); }
    if (flags & WRAP)
    { strcat(str, "WRAP | "); }
    if (flags & UNWRAP)
    { strcat(str, "UNWRAP | "); }
    if (flags & VERIFY)
    { strcat(str, "VERIFY | "); }
    if (flags & VERIFY_RECOVER)
    { strcat(str, "VERIFY_RECOVER | "); }
    if (flags & DERIVE)
    { strcat(str, "DERIVE | "); }
    if (flags & NON_REPUDIATION)
    { strcat(str, "NON_REPUDIATION | "); }

    str[strlen(str) - 3] = '\0';
    return str;
}
