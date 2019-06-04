#include "ak_pointer_server.h"

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_ps указатель на объект типа s_ptr_server
    @param size размер памяти, которую нужно выделить
    @param mode режим использования (возможные значения PS_R_MODE / PS_W_MODE)
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ps_alloc(s_ptr_server *p_ps, size_t size, uint8_t mode) {
    if (!p_ps)
        return ak_error_message(ak_error_null_pointer, __func__, "input value is null");

    if (mode != PS_R_MODE)
    {
        if (mode != PS_W_MODE)
        {
            memset(p_ps, 0, sizeof(s_ptr_server));
            return ak_error_message(ak_error_wrong_ps_mode, __func__, "wrong ps mode");
        }
    }

    p_ps->mp_begin = (byte *) malloc(size);
    if (!p_ps->mp_begin)
    {
        memset(p_ps, 0, sizeof(s_ptr_server));
        return ak_error_message(ak_error_null_pointer, __func__, "null value");
    }

    p_ps->mp_end = p_ps->mp_begin + size;

    if (mode == PS_R_MODE)
        p_ps->mp_curr = p_ps->mp_begin;
    else
        p_ps->mp_curr = p_ps->mp_end;

    p_ps->m_mode = mode;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_ps указатель на объект типа s_ptr_server
    @param from указатель на начало блока памяти
    @param len размер блока памяти, на который должен указывать объект типа s_ptr_server
    @param mode режим использования (возможные значения PS_R_MODE / PS_W_MODE / PS_U_MODE)
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ps_set(s_ptr_server *p_ps, byte *from, size_t len, uint8_t mode) {
    if (!p_ps || !from)
        return ak_error_message(ak_error_null_pointer, __func__, "input value is null");

    if (mode != PS_U_MODE)
    {
        if (mode != PS_R_MODE)
        {
            if (mode != PS_W_MODE)
                return ak_error_message(ak_error_wrong_ps_mode, __func__, "wrong ps mode");
        }
    }

    p_ps->m_mode = mode;
    p_ps->mp_begin = from;
    p_ps->mp_end = p_ps->mp_begin + len;

    switch (mode)
    {
        case PS_U_MODE:
            p_ps->mp_curr = NULL;
            break;
        case PS_R_MODE:
            p_ps->mp_curr = p_ps->mp_begin;
            break;
        case PS_W_MODE:
            p_ps->mp_curr = p_ps->mp_end - 1;
        default:
            break;
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_ps указатель на объект типа s_ptr_server
    @param new_size размер памяти, которую нужно выделить
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ps_realloc(s_ptr_server *p_ps, size_t new_size) {
    size_t old_size;
    byte *p_new_mem;

    if ((!p_ps) || !p_ps->mp_begin)
        return 0;

    if (p_ps->m_mode != PS_W_MODE)
        return ak_error_message(ak_error_wrong_ps_mode, __func__, "wrong ps mode");

    old_size = ps_get_curr_size(p_ps);
    if (new_size < old_size)
        return ak_error_message(ak_error_invalid_value, __func__, "invalid value");

    p_new_mem = (byte *) malloc(new_size);
    if (!p_new_mem)
        return ak_error_message(ak_error_null_pointer, __func__, "null value");

    printf("realloc mem! new size = %zu\n", new_size);

    memmove(p_new_mem + (new_size - old_size), p_ps->mp_curr, old_size);

    free(p_ps->mp_begin);
    p_ps->mp_begin = p_new_mem;
    p_ps->mp_end = p_ps->mp_begin + new_size;
    p_ps->mp_curr = p_ps->mp_end - old_size;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_ps указатель на объект типа s_ptr_server
    @param num кол-во байт, на которое нужно переместить указатель на текущую позицию
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ps_move_cursor(s_ptr_server *p_ps, size_t num) {
    size_t free_size;

    if ((!p_ps) || !p_ps->mp_begin)
        return 0;

    if (p_ps->m_mode != PS_W_MODE)
    {
        if (p_ps->m_mode != PS_R_MODE)
            return ak_error_message(ak_error_wrong_ps_mode, __func__, "wrong ps mode");
    }

    if (p_ps->m_mode == PS_R_MODE)
    {
        if (num > ps_get_curr_size(p_ps))
            return ak_error_message(ak_error_wrong_length, __func__, "wrong length");

        p_ps->mp_curr += num;
    }
    else
    {
        free_size = (size_t) (p_ps->mp_curr - p_ps->mp_begin);

        if (free_size < num)
            ps_realloc(p_ps, (size_t) (ps_get_full_size(p_ps) * 1.5));

        p_ps->mp_curr -= num;
    }
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В режиме PS_R_MODE возвращается кол-во непрочитанных байтов.
    В режиме PS_W_MODE возвращается кол-во записанных байтов.

    @param p_ps указатель на объект типа s_ptr_server
    @return Зависит от режима использования сервера (см. описание)                                 */
/* ----------------------------------------------------------------------------------------------- */
size_t ps_get_curr_size(s_ptr_server *p_ps) {
    if ((!p_ps) || !p_ps->mp_begin)
        return 0;

    if (p_ps->m_mode == PS_R_MODE || p_ps->m_mode == PS_W_MODE)
        return (size_t) (p_ps->mp_end - p_ps->mp_curr);
    else
        return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param p_ps указатель на объект типа s_ptr_server
    @return Размер памяти, на которую указывает объект типа s_ptr_server.                          */
/* ----------------------------------------------------------------------------------------------- */
size_t ps_get_full_size(s_ptr_server *p_ps) {
    if ((!p_ps) || !p_ps->mp_begin)
        return 0;

    return (size_t) (p_ps->mp_end - p_ps->mp_begin);
}
