#include <pkcs_15_cryptographic_token/ak_asn_codec.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param tag тег
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_tag(tag tag, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    *p_buff = tag;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param len длина данных
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_len(size_t len, byte *p_buff) {
    int8_t len_byte_cnt;

    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    len_byte_cnt = asn_get_len_byte_cnt(len);
    if (!len_byte_cnt)
        return ak_error_message(ak_error_null_pointer, __func__, "wrong length");

    if (len_byte_cnt == 1)
        *p_buff = (byte) len;
    else
    {
        *(p_buff++) = (byte) (0x80u ^ (uint8_t) (--len_byte_cnt));
        while (--len_byte_cnt >= 0)
            *(p_buff++) = (byte) ((len >> (8u * len_byte_cnt)) & 0xFFu);
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param val входное значение (описание формата значения находится в определении типа integer)
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_int(integer val, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!val.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    if (!val.m_positive && !(val.mp_value[0] & 0x80u))
        return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

    if (!val.m_positive)
    {
        memcpy(p_buff, val.mp_value, val.m_val_len);
    }
    else
    {
        if (val.mp_value[0] & 0x80u)
        {
            *p_buff = 0x00;
            p_buff++;
        }

        memcpy(p_buff, val.mp_value, val.m_val_len);
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param str входная UTF-8 строка
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_utf8string(utf8_string str, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!str)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    memcpy(p_buff, str, strlen((char *) str));

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param src массив октетов
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_octetstr(octet_string src, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!src.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    memcpy(p_buff, src.mp_value, src.m_val_len);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param src входная строка
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_vsblstr(visible_string str, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!str)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    memcpy(p_buff, str, strlen(str));

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент добавляются только идентификаторы, у который первое число 1 или 2,
    а второе не превосходит 32

    @param obj_id входная строка, содержая идентификатор в виде чисел, разделенных точками
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_objid(object_identifier obj_id, byte *p_buff) {
    size_t num;
    object_identifier p_objid_end;

    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!obj_id)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    num = (size_t) strtoul((char *) obj_id, &p_objid_end, 10);
    obj_id = ++p_objid_end;
    num = num * 40 + (size_t) strtol((char *) obj_id, &p_objid_end, 10);
    *(p_buff++) = (byte) num;

    while (*p_objid_end != '\0')
    {
        obj_id = ++p_objid_end;
        num = (size_t) strtol((char *) obj_id, &p_objid_end, 10);

        if (num > 0x7Fu)
        {
            byte seven_bits;
            int8_t i;
            i = 3;
            while (i > 0)
            {
                seven_bits = (byte) ((num >> ((uint8_t) i * 7u)) & 0x7Fu);
                if (seven_bits)
                    *(p_buff++) = (byte) (0x80u ^ seven_bits);
                i--;
            }
        }

        *(p_buff++) = (byte) (num & 0x7Fu);
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param src входные данные (описание формата данных находится в определении типа bit_string)
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_bitstr(bit_string src, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!src.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    if (src.m_unused > 7 || !src.m_val_len)
        return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

    *(p_buff++) = src.m_unused;
    memcpy(p_buff, src.mp_value, src.m_val_len);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param val входное значение
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_bool(boolean val, byte *p_buff) {
    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (val)
        *p_buff = 0xFFu;
    else
        *p_buff = 0x00;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param time строка в формате "YYYY-MM-DD HH:MM:SS.[ms] UTC"
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_generalized_time(generalized_time time, byte *p_buff) {
    int8_t byte_cnt;

    if (!p_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    if (!time)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to time string");

    byte_cnt = asn_get_gentime_byte_cnt(time);
    if (byte_cnt < 15)
        return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong length of time string");

    /* YYYY */
    for (uint8_t i = 0; i < 4; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of year value");
        *(p_buff++) = (byte) *(time++);
    }
    time++;

    /* MM */
    for (uint8_t i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of month value");
        *(p_buff++) = (byte) *(time++);
    }
    time++;

    /* DD */
    for (uint8_t i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of day value");
        *(p_buff++) = (byte) *(time++);
    }
    time++;

    /* HH */
    for (uint8_t i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of hour value");
        *(p_buff++) = (byte) *(time++);
    }
    time++;

    /* MM */
    for (uint8_t i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of minute value");
        *(p_buff++) = (byte) *(time++);
    }
    time++;

    /* SS */
    for (uint8_t i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of second value");
        *(p_buff++) = (byte) *(time++);
    }

    /* .mmm */
    if (*time == '.')
    {
        int8_t ms_cnt = (int8_t) ((strchr(time, ' ') - time) - 1);
        if (ms_cnt == 0)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "quota of second absent");

        if (time[ms_cnt] == '0')
            return ak_error_message(ak_error_wrong_asn1_encode,
                                    __func__,
                                    "wrong format of quota of second value (it can't end by 0 symbol)");

        *(p_buff++) = (byte) *(time++); // помещаем символ точки
        for (uint8_t i = 0; i < ms_cnt; i++)
        {
            if (!isdigit(*time))
                return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of quota of second value");
            *(p_buff++) = (byte) *(time++);
        }
    }

    *p_buff = 'Z';

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция добавляет стандартный тег ASN.1, длину данных, данные (если они присутствуют).
    В случае, когда tag_number = TSEQUENCE | TSET, параметр p_data должен быть равен NULL,
    а seq_or_set_len содержать длину данных, которые объединются в объект sequence или set.
    В остальных случаях параметр p_data указывает на область памяти с данными, а seq_or_set_len
    должен быть равен 0.

    @param tag_number номер стандартного тега
    @param p_data указатель на область памяти, в которой находятся данные для кодирования
    @param seq_or_set_len длина закодированных данных
    @param p_main_ps указатель на главный объект типа s_ptr_server
    @param p_result указатель на объект типа s_ptr_server, в который поместиться блок
           закодированных данных
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int asn_put_universal_tlv(uint8_t tag_number,
                          void *p_data,
                          size_t seq_or_set_len,
                          s_ptr_server *p_main_ps,
                          s_ptr_server *p_result) {
    int error;
    size_t value_len;
    size_t len_byte_cnt;

    if (!tag_number || !p_main_ps || !p_result)
        return ak_error_message(ak_error_null_pointer, __func__, "input argument is null");

    value_len = 0;
    len_byte_cnt = 0;

    if (tag_number == TOCTET_STRING)
    {
        octet_string str = *((octet_string *) p_data);

        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        if (!str.mp_value)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        value_len = str.m_val_len;
        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_octetstr(str, p_main_ps->mp_curr + 1 + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding octet string value");
    }
    else if (tag_number == TINTEGER)
    {
        integer num = *((integer *) p_data);
        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        if (!num.mp_value)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        value_len = num.m_val_len;
        if (num.m_positive && (num.mp_value[0] & 0x80u))
            value_len += 1;

        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_int(num, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding integer value");
    }
    else if (tag_number == TBIT_STRING)
    {
        bit_string str = *((bit_string *) p_data);

        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        if (!str.mp_value)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        value_len = str.m_val_len + 1; // 1 - для хранения кол-ва неиспользуемых битов

        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_bitstr(str, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding bit string value");
    }
    else if (tag_number == TGENERALIZED_TIME)
    {
        generalized_time time = *((generalized_time *) p_data);

        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        value_len = asn_get_gentime_byte_cnt(time);
        len_byte_cnt = asn_get_len_byte_cnt(value_len);

        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_generalized_time(time, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding generalized time value");
    }
    else if (tag_number == TOBJECT_IDENTIFIER)
    {
        object_identifier oid = *((object_identifier *) p_data);

        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        value_len = asn_get_oid_byte_cnt(oid);

        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_objid(oid, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding object identifier value");
    }
    else if (tag_number == TUTF8_STRING)
    {
        utf8_string str = *((utf8_string *) p_data);
        value_len = strlen((char *) str);

        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_utf8string(str, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding utf8 string value");
    }
    else if (tag_number == TBOOLEAN)
    {
        boolean bval = *((boolean *) p_data);

        if (!p_data)
            return ak_error_message(ak_error_null_pointer, __func__, "null value");

        value_len = 1;

        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");

        if ((error = asn_put_bool(bval, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with adding boolean value");
    }
    else if (tag_number == TSEQUENCE || tag_number == TSET)
    {
        value_len = seq_or_set_len;
        tag_number |= CONSTRUCTED;

        len_byte_cnt = asn_get_len_byte_cnt(value_len);
        if (!len_byte_cnt)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");

        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt)) != ak_error_ok)
            return ak_error_message(error, __func__, "problems with moving cursor");
    }

    asn_put_tag(tag_number, p_main_ps->mp_curr);

    if ((error = asn_put_len(value_len, p_main_ps->mp_curr + 1)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with adding data length");

    if ((error = ps_set(p_result, p_main_ps->mp_curr, 1 + len_byte_cnt + value_len, PS_U_MODE)) != ak_error_ok)
        return ak_error_message(error, __func__, "problems with making union of asn data");
    return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param len длина данных
    @return Кол-во байтов, необходимое для хранения закодированной длины.                          */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 asn_get_len_byte_cnt(size_t len) {
    if (len < 0x80u && len >= 0)
        return 1;
    if (len <= 0xFFu)
        return 2;
    if (len <= 0xFFFFu)
        return 3;
    if (len <= 0xFFFFFFu)
        return 4;
    if (len <= 0xFFFFFFFFu)
        return 5;
    else
        return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid строка, содержая идентификатор в виде чисел, разделенных точками
    @return Кол-во байтов, необходимое для хранения закодированного идентификатора.                */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 asn_get_oid_byte_cnt(object_identifier oid) {
    ak_uint8 byte_cnt;
    object_identifier p_end;
    size_t num;

    if (!oid)
        return 0;

    byte_cnt = 1;

    /* Пропускаем 2 первых идентификатора */
    strtoul((char *) oid, &p_end, 10);
    oid = ++p_end;
    strtol((char *) oid, &p_end, 10);

    while (*p_end != '\0')
    {
        oid = ++p_end;
        num = (size_t) strtol((char *) oid, &p_end, 10);
        if (num <= 0x7Fu)             /*                               0111 1111 -  7 бит */
            byte_cnt += 1;
        else if (num <= 0x3FFFu)      /*                     0011 1111 1111 1111 - 14 бит */
            byte_cnt += 2;
        else if (num <= 0x1FFFFFu)    /*           0001 1111 1111 1111 1111 1111 - 21 бит */
            byte_cnt += 3;
        else if (num <= 0x0FFFFFFFu)  /* 0000 1111 1111 1111 1111 1111 1111 1111 - 28 бит */
            byte_cnt += 4;
        else
            return 0;
    }
    return byte_cnt;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param time строка, содержая время в формате "YYYY-MM-DD HH:MM:SS.[ms] UTC"
    @return Кол-во байтов, необходимое для хранения закодированного времени.                       */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 asn_get_gentime_byte_cnt(generalized_time time) {
    if (!time)
        return 0;
    /*
     * 8 имеет след. смысл:
     * - из строки "YYYY-MM-DD HH:MM:SS.[ms] UTC" удалить символы "-- :: UTC"
     * - добавить символ "Z"
     * Примечание: эл-ов ms может быть неограниченное кол-во.
    */
    return (ak_uint8) (strlen(time) - 8);
}
