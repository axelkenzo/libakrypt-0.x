#include <pkcs_15_cryptographic_token/ak_asn_codec.h>

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент разбираюся только теги,
    представленные в одном байте.

    @param p_buff указатель на тег
    @param p_tag указатель на переменную, содержащую тег
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_tag(byte *p_buff, tag *p_tag) {
    if (!p_buff || !p_tag)
        return ak_error_null_pointer;

    *p_tag = *p_buff;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент определяется длинна, представленная не более,
    чем в 4 байтах.

    @param p_buff указатель на длину данных
    @param p_len указатель переменную, содержащую длинну блока данных
    @param p_len_byte_cnt указатель переменную, содержащую кол-во памяти (в байтах),
           необходимое для хранения длины блока данных в DER последовательности
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_len(byte *p_buff, size_t *p_len, uint8_t *p_len_byte_cnt) {
    if (!p_buff || !p_len_byte_cnt)
        return ak_error_null_pointer;

    *p_len = 0;
    *p_len_byte_cnt = 1;

    if (*p_buff & 0x80u)
    {
        *p_len_byte_cnt = (uint8_t) ((*p_buff++) & 0x7Fu);
        if (*p_len_byte_cnt > 4)
            return ak_error_wrong_length;

        for (uint8_t i = 0; i < *p_len_byte_cnt; i++)
        {
            *p_len = (*p_len << 8u) | (*p_buff);
            p_buff++;
        }
        *p_len_byte_cnt += 1;
    }
    else
        *p_len = *p_buff;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на закодированное целое число
    @param len длинна блока данных
    @param p_val указатель переменную, содержащую целое число
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_int(byte *p_buff, size_t len, integer *p_val) {
    size_t val_len;

    if (!p_buff || !p_val)
        return ak_error_null_pointer;

    // TODO: Переделать представление отрицательного числа
    val_len = len;

    p_val->mp_value = malloc((size_t) len);
    if (!p_val->mp_value)
    {
        memset(p_val, 0, sizeof(integer));
        return ak_error_out_of_memory;
    }

    p_val->m_positive = (*p_buff & 0x80u) ? false : true;

    if (p_val->m_positive && val_len > 1)
    {
        /*
         * Если число беззнаковое, и в нем возведен старшиц бит,
         * то перед значением добавляется нулевой байт
        */
        if (*p_buff == 0x00)
        {
            p_buff++;
            val_len--;

            if (!(*p_buff & 0x80u))
            {
                free(p_val->mp_value);
                memset(p_val, 0, sizeof(integer));
                return ak_error_wrong_asn1_decode;
            }
        }
    }

    memcpy(p_val->mp_value, p_buff, val_len);
    p_val->m_val_len = val_len;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на закодированную строку
    @param len длинна блока данных
    @param p_str указатель переменную, содержащую указатель на строку
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_utf8string(byte *p_buff, size_t len, utf8_string *p_str) {
    utf8_string str;

    if (!p_buff || !p_str)
        return ak_error_null_pointer;

    str = (utf8_string) malloc(len + 1);
    if (!str)
        return ak_error_out_of_memory;

    memcpy(str, p_buff, len);
    str[len] = '\0';

    *p_str = str;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на массив октетов
    @param len длинна блока данных
    @param p_str указатель переменную, содержащую массив октетов и их кол-во
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_octetstr(byte *p_buff, size_t len, octet_string *p_dst) {
    if (!p_buff || !p_dst)
        return ak_error_null_pointer;

    p_dst->mp_value = (byte *) malloc(len);
    if (!p_dst->mp_value)
    {
        memset(p_dst, 0, sizeof(octet_string));
        return ak_error_out_of_memory;
    }

    memcpy(p_dst->mp_value, p_buff, len);
    p_dst->m_val_len = len;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на закодированную строку
    @param len длинна блока данных
    @param p_str указатель переменную, содержащую указатель на строку
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_vsblstr(byte *p_buff, size_t len, visible_string *p_str) {
    visible_string str;

    if (!p_buff || !p_str)
        return ak_error_null_pointer;

    str = (visible_string) malloc(len + 1);
    if (!str)
        return ak_error_out_of_memory;

    memcpy(str, p_buff, len);
    str[len] = '\0';

    *p_str = str;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент разбираются только идентификаторы, у который первое число 1 или 2,
    а второе не превосходит 32

    @param p_buff указатель на закодированный идентификатор объекта
    @param len длинна блока данных
    @param p_objid указатель переменную, содержащую указатель на строку для хранения идентификатора
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_objid(byte *p_buff, size_t len, object_identifier *p_objid) {
    uint32_t value;
    size_t curr_size;
    object_identifier obj_id;

    if (!p_buff || !p_objid)
        return ak_error_null_pointer;

    if (((p_buff[0] / 40) > 2) || ((p_buff[0] % 40) > 32))
        return ak_error_wrong_asn1_decode;

    obj_id = (object_identifier) malloc(50);
    if (!obj_id)
        return ak_error_out_of_memory;

    sprintf(obj_id, "%d.%d", p_buff[0] / 40, p_buff[0] % 40);

    for (int i = 1; i < len; i++)
    {
        value = 0u;
        while (p_buff[i] & 0x80u)
        {
            value ^= p_buff[i] & 0x7Fu;
            value = value << 7u;
            i++;
        }

        value += p_buff[i] & 0x7Fu;

        if ((curr_size = strlen(obj_id)) >= 50)
        {
            free(obj_id);
            return ak_error_wrong_asn1_decode;
        }

        sprintf(obj_id + curr_size, ".%u", value);
    }

    *p_objid = obj_id;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на массив байтов
    @param len длинна блока данных
    @param p_dst указатель переменную, содержащую указатель на массив байтов, их кол-во и кол-во
           не используемых битов в последнем байте
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_bitstr(byte *p_buff, size_t len, bit_string *p_dst) {
    if (!p_buff || !p_dst)
        return ak_error_null_pointer;

    p_dst->mp_value = (byte *) malloc((size_t) len - 1);
    if (!p_dst->mp_value)
    {
        memset(p_dst, 0, sizeof(bit_string));
        return ak_error_out_of_memory;
    }

    p_dst->m_unused = p_buff[0];
    if (p_dst->m_unused > 7)
    {
        free(p_dst->mp_value);
        memset(p_dst, 0, sizeof(bit_string));
        return ak_error_wrong_asn1_decode;
    }

    memcpy(p_dst->mp_value, p_buff + 1, (size_t) (len - 1));

    p_dst->m_val_len = len - 1;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на закодированное значение типа boolean
    @param len длинна блока данных
    @param p_value указатель переменную, содержащую значение типа boolean
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_bool(byte *p_buff, size_t len, boolean *p_value) {
    if (!p_buff || !p_value)
        return ak_error_null_pointer;

    if (len > 1 || (p_buff[0] > 0x00 && p_buff[0] < 0xFF))
        return ak_error_wrong_asn1_decode;

    *p_value = p_buff[0];

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_buff указатель на закодированное время
    @param len длинна блока данных
    @param p_time указатель переменную, содержащую указатель на строку для хранения времени
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_generalized_time(byte *p_buff, size_t len, generalized_time *p_time) {
    generalized_time date_time;

    if (!p_buff || !p_time)
        return ak_error_null_pointer;

    if (len < 15 || toupper(p_buff[len - 1]) != 'Z')
    {
        *p_time = NULL;
        return ak_error_wrong_asn1_decode;
    }

    /* Дополнительные 9 байтов для символов пробела, тире и т.д. */
    date_time = (generalized_time) malloc(len + 9);
    date_time[0] = '\0';

    /* YYYY */
    strncat(date_time, (char *) p_buff, 4);
    strcat(date_time, "-");
    p_buff += 4;

    /* MM */
    strncat(date_time, (char *) p_buff, 2);
    strcat(date_time, "-");
    p_buff += 2;

    /* DD */
    strncat(date_time, (char *) p_buff, 2);
    strcat(date_time, " ");
    p_buff += 2;

    /* HH */
    strncat(date_time, (char *) p_buff, 2);
    strcat(date_time, ":");
    p_buff += 2;

    /* MM */
    strncat(date_time, (char *) p_buff, 2);
    strcat(date_time, ":");
    p_buff += 2;

    /* SS.mmm */
    strncat(date_time, (char *) p_buff, len - 13); /* 13 = YYYY + MM + DD + HH + MM + 'Z' */
    strcat(date_time, " UTC");

    *p_time = date_time;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция декодирует тег из последовательнсти и сравнивает его с ожидаемым тегом.
    Если теги совпадают, то начинается процесс декодирования данных и результат
    помещается в переменную p_result.
    В процессе декодирование указатель на текущую позицию в объекте p_curr_ps
    смещается на необходимое расстояние.

    Примечание: expected_tag необходим для возможности реализации однозначного декодирования
    DER последовательности.

    @param expected_tag тег, который ожидается в DER последовательности
    @param p_curr_ps длинна блока данных
    @param p_result указатель переменную, содержащую указатель на строку для хранения времени
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_expected_tlv(tag expected_tag, s_ptr_server *p_curr_ps, void *p_result) {
    int error;
    tag real_tag;
    size_t value_len;
    uint8_t len_byte_cnt;

    if (!expected_tag || !p_curr_ps || !p_result)
        return ak_error_null_pointer;

    real_tag = 0;
    value_len = 0;
    len_byte_cnt = 0;

    if ((error = asn_get_tag(p_curr_ps->mp_curr, &real_tag)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting tag");

    if (expected_tag != real_tag)
        return ak_error_diff_tags;

    if ((error = asn_get_len(p_curr_ps->mp_curr + 1, &value_len, &len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with getting data length");

    if ((error = ps_move_cursor(p_curr_ps, 1 + len_byte_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    if (expected_tag == TOCTET_STRING)
    {
        if ((error = asn_get_octetstr(p_curr_ps->mp_curr, value_len, (octet_string *) p_result)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting octet string value");
    }
    else if (expected_tag == TINTEGER)
    {
        if ((error = asn_get_int(p_curr_ps->mp_curr, value_len, (integer *) p_result)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting integer value");
    }
    else if (expected_tag == TBIT_STRING)
    {
        if ((error = asn_get_bitstr(p_curr_ps->mp_curr, value_len, (bit_string *) p_result)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting bit string value");
    }
    else if (expected_tag == TGENERALIZED_TIME)
    {
        if ((error = asn_get_generalized_time(p_curr_ps->mp_curr, value_len, (generalized_time *) p_result))
            != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting generalized time value");
    }
    else if (expected_tag == TOBJECT_IDENTIFIER)
    {
        if ((error = asn_get_objid(p_curr_ps->mp_curr, value_len, (object_identifier *) p_result)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting object identifier value");
    }
    else if (expected_tag == TUTF8_STRING)
    {
        if ((error = asn_get_utf8string(p_curr_ps->mp_curr, value_len, (utf8_string *) p_result)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting utf8 string value");
    }
    else if (expected_tag == TBOOLEAN)
    {
        if ((error = asn_get_bool(p_curr_ps->mp_curr, value_len, (boolean *) p_result)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting boolean value");
    }
    else
    {
        if ((error = ps_set((s_ptr_server *) p_result, p_curr_ps->mp_curr, value_len, PS_R_MODE)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with setting pointer server");
    }

    if ((error = ps_move_cursor(p_curr_ps, value_len)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with moving cursor");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_data указатель на объект типа s_ptr_server, содержащий указатели на блок данных DER
    @param p_num_of_elems указатель переменную, содержащую кол-во объектов
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_get_num_of_elems_in_constructed_obj(s_ptr_server *p_data, uint8_t *p_num_of_elems) {
    int error;
    size_t value_len;
    uint8_t len_byte_cnt;
    s_ptr_server data_copy;
    value_len = 0;
    len_byte_cnt = 0;

    data_copy = *p_data;
    *p_num_of_elems = 0;

    while (ps_get_curr_size(&data_copy))
    {
        if ((error = asn_get_len(data_copy.mp_curr + 1, &value_len, &len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with getting data length");

        // смещаемся на расстояние равное длине блока tlv
        if ((error = ps_move_cursor(&data_copy, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
        *p_num_of_elems += 1;
    }

    return ak_error_ok;
}

void asn_free_int(integer *p_val) {
    if (p_val->mp_value)
    {
        free(p_val->mp_value);
        p_val->mp_value = NULL;
    }
}

void asn_free_utf8string(utf8_string *p_val) {
    if (*p_val)
    {
        free(*p_val);
        *p_val = NULL;
    }
}

void asn_free_octetstr(octet_string *p_val) {
    if (p_val->mp_value)
    {
        free(p_val->mp_value);
        p_val->mp_value = NULL;
    }
}

void asn_free_vsblstr(visible_string *p_val) {
    if (*p_val)
    {
        free(*p_val);
        *p_val = NULL;
    }
}

void asn_free_objid(object_identifier *p_val) {
    if (*p_val)
    {
        free(*p_val);
        *p_val = NULL;
    }
}

void asn_free_bitstr(bit_string *p_val) {
    if (p_val->mp_value)
    {
        free(p_val->mp_value);
        p_val->mp_value = NULL;
    }
}

void asn_free_generalized_time(generalized_time *p_val) {
    if (*p_val)
    {
        free(*p_val);
        *p_val = NULL;
    }
}
