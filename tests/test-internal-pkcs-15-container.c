/*
 * Цель данного примера - продемонстрировать процесс
 * создания и разбора контейнера хранения ключевой
 * информации, соответствующего стандарту PKCS 15.
 * При этом в контейнер помещается случайный ключ для
 * алгоритма Магма.
 */

#include <libakrypt.h>
#include <ak_bckey.h>
#include <pkcs_15_cryptographic_token/ak_pkcs_15_token_manager.h>

char password[] = "123";
char key_label[] = "This is test key";
date start_date = {2019, 5, 21, 0, 0, 0};
date end_date = {2020, 5, 21, 23, 59, 59};
key_usage_flags_t flags = ENCRYPT | DECRYPT;

void print_container_info(struct extended_key** pp_keys, uint8_t num_of_keys);
int gen_random_key(struct extended_key *p_kc_key, char *label, date sd, date ed, key_usage_flags_t flags);

int main()
{
    int error;
    size_t i;
    struct extended_key* pp_kc_keys[2];
    struct extended_key** pp_kc_keys_from_container;
    ak_uint8 num_of_keys;
    byte* p_container_der;
    size_t container_der_size;

    /* Инициализируем библиотеку */
    if (ak_libakrypt_create(ak_function_log_stderr) != ak_true)
    {
        return ak_libakrypt_destroy();
    }

    /* Добавляем ключ в массив объектов */
    for(i = 0; i < sizeof(pp_kc_keys) / sizeof(pp_kc_keys[i]); i++)
    {
        pp_kc_keys[i] = malloc(sizeof(struct extended_key));
        gen_random_key(pp_kc_keys[i], key_label, start_date, end_date, flags);
    }

    /* Создаем контейнер */
    p_container_der = NULL;
    container_der_size = 0;
    if((error = write_keys_to_container(pp_kc_keys, sizeof(pp_kc_keys) / sizeof(pp_kc_keys[0]), password, strlen(password), &p_container_der, &container_der_size)) != ak_error_ok)
    {
        ak_error_message(error, __func__, "can't write keys to container");
        return ak_libakrypt_destroy();
    }

    /* Выводим получившийся результат */
    printf("Container in DER code: ");
    for (i = 0; i < container_der_size; ++i)
    {
        printf("%02X ", p_container_der[i]);
    }
    printf("\nSize: %zd bytes\n", container_der_size);
    printf("You can parse this byte sequence in any ASN.1 decoder and you'll see the structure of container\n");

    /* Разбираем контейнер */
    pp_kc_keys_from_container = NULL;
    num_of_keys = 0;
    read_keys_from_container((byte*)password, strlen(password), p_container_der, container_der_size, &pp_kc_keys_from_container, &num_of_keys);

    /* Выводим оинформацию о содержимом контейнера */
    print_container_info(pp_kc_keys_from_container, num_of_keys);

    /* Деинициализируем библиотеку */
    return ak_libakrypt_destroy();
}

void print_container_info(struct extended_key** pp_keys, uint8_t num_of_keys)
{
    uint8_t i, j;
    struct extended_key* p_key;

    for(i = 0; i < num_of_keys; i++)
    {
        p_key = pp_keys[i];
        printf("\n------------------------- key %d -------------------------\n", i + 1);

        if(p_key->label)
            printf("\t%-20s'%s'\n", "Label: ", (char*)p_key->label);

        if(p_key->flags)
            printf("\t%-20s%s\n", "Key usage: ", key_usage_flags_to_str(p_key->flags));

        if(p_key->start_date[0])
            printf("\t%-20s%04d-%02d-%02d %02d:%02d:%02d UTC\n", "Start date: ",
                    p_key->start_date[0], p_key->start_date[1], p_key->start_date[2],
                    p_key->start_date[3], p_key->start_date[4], p_key->start_date[5]);

        if(p_key->end_date[0])
            printf("\t%-20s%04d-%02d-%02d %02d:%02d:%02d UTC\n", "End date: ",
                   p_key->end_date[0], p_key->end_date[1], p_key->end_date[2],
                   p_key->end_date[3], p_key->end_date[4], p_key->end_date[5]);

        if(p_key->key.sec_key)
        {
            printf("\t%-20s%s\n", "Key for algorithm: ", p_key->key.sec_key->key.oid->name);

            printf("\t%-20s", "Key id:");
            for(j = 0; j < p_key->key.sec_key->key.number.size; j++)
            {
                printf("%02X", *((byte*)p_key->key.sec_key->key.number.data + j));
            }
            putchar('\n');
        }

        printf("-------------------------- end --------------------------\n");
    }
}

int gen_random_key(struct extended_key *p_kc_key, char *label, date sd, date ed, key_usage_flags_t flags)
{
    int error;
    ak_context_manager p_ctx_manager;
    ak_bckey p_random_libakrypt_key;

    p_random_libakrypt_key = calloc(1, sizeof(struct bckey));
    if(!p_random_libakrypt_key)
        return ak_error_null_pointer;

    /* Создаем контекст ключа */
    if ((error = ak_bckey_context_create_magma(p_random_libakrypt_key)) != ak_error_ok)
    {
        ak_error_message(error, __func__, "can't create bckey context");
        return ak_libakrypt_destroy();
    }

    /* Заполняем контекст ключа произвольным значением */
    p_ctx_manager = ak_libakrypt_get_context_manager();
    if ((error = ak_bckey_context_set_key_random(p_random_libakrypt_key, &p_ctx_manager->key_generator)) != ak_error_ok)
    {
        ak_error_message(error, __func__, "can't create random kc_secret_key");
        return ak_libakrypt_destroy();
    }

    /* Создаем объект ключа, помещаемого в контейнер */
    memset(p_kc_key, 0, sizeof(struct extended_key));
    p_kc_key->key.sec_key = p_random_libakrypt_key;  // Добавляем ключ
    p_kc_key->key_type = SEC_KEY;                    // Указываем тип ключа (секретный, публичный, приватный)
    p_kc_key->label = key_label;                     // Добавляем человеку понятное название ключа
    p_kc_key->flags = flags;                         // Указываем флаги использования ключа

    for (int j = 0; j < 6; ++j)
    {
        p_kc_key->start_date[j] = start_date[j]; // Указываем начальную дату периода использования ключа
        p_kc_key->end_date[j] = end_date[j];     // Указываем конечную дату периода использования ключа
    }

    return ak_error_ok;
}
