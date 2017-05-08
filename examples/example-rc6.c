#include <stdio.h>
#include <libakrypt.h>
#include <ak_skey.h>

void print_key( ak_skey skey )
{
    int i = 0;
    char *str = NULL;
    ak_resource res = skey->resource;

    printf("key:      %s\n", str = ak_buffer_to_hexstr( &skey->key )); if( str ) free( str );
    printf("mask:     %s\n", str = ak_buffer_to_hexstr( &skey->mask )); if( str ) free( str );
    printf("icode:    %s ", str = ak_buffer_to_hexstr( &skey->icode )); if( str ) free( str );
    if( ak_skey_check_icode_additive( skey )) printf("(Ok)\n"); else printf("(No)\n");
    printf("number:   %s\n", ak_buffer_get_str( &skey->number ));

    printf("resource: %lu\n", res.counter );
    if( skey->oid == NULL ) printf("oid:     (null)\n");
     else printf("oid:      %s (%s)\n", ak_oid_get_name( skey->oid ), ak_oid_get_id( skey->oid ));
    printf("random:   "); for( i = 0; i < 16; i++ ) printf("%02x ", ak_random_uint8( skey->generator ));
    printf("\n");
}

int main( void )
{
    /* Инициализируем библиотеку */
    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
        return ak_libakrypt_destroy();

    /* Проверка тестовых векторов для ключа 256 бит
     * The RC6 (TM) Block Cipher
     * Ronald L. Rivest, M.J.B. Robshaw, R. Sidney, and Y.L. Yin
     * Страница 20
     */

    /* Тестовые векторы 1 (нулевые вектора) + шифртекст */
    ak_uint8 user_key[32]       = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ak_uint8 user_text[16]      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ak_uint8 cipher_text[16]    = {0x8f, 0x5f, 0xbd, 0x05, 0x10, 0xd1, 0x5f, 0xa8, 0x93, 0xfa, 0x3f, 0xda, 0x6e, 0x85, 0x7e, 0xc2};

    /* Прочие данные для тестирования */
    ak_uint8 out[16];
    ak_bckey bkey = NULL;
    char *str = NULL;

    printf("RC6 algorithm example test\n\n");
    /* Создаем тестовый ключ */
    bkey = ak_bckey_new_rc6_ptr(user_key, 32, ak_true);
    print_key(&bkey->key);

    /* Зашифрование одного блока информации */
    printf("\nEncryption test:\n");
    bkey->encrypt(&bkey->key, user_text, out);
    printf("out ciphertext:\t%s\n", str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
    printf("std ciphertext:\t%s\n", str = ak_ptr_to_hexstr( cipher_text, 8, ak_true )); free( str );

    /* Расшифрование одного блока информации */
    printf("Decryption test:\n");
    bkey->decrypt(&bkey->key, cipher_text, out);
    printf("out user text:\t%s\n", str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
    printf("std user text:\t%s\n", str = ak_ptr_to_hexstr( user_text, 8, ak_true )); free( str );

    return ak_libakrypt_destroy();
}
