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

void test(ak_uint8 *user_key, ak_uint8 *user_text, ak_uint8 *cipher_text)
{
    /* Прочие данные для тестирования */
    ak_uint8 out[16];
    ak_bckey bkey = NULL;
    char *str = NULL;

    /* Создаем тестовый ключ */
    bkey = ak_bckey_new_rc6_ptr(user_key, 32, ak_true);
    print_key(&bkey->key);

    /* Зашифрование одного блока информации */
    printf("\nEncryption test:\n");
    bkey->encrypt(&bkey->key, user_text, out);
    printf("out ciphertext:\t%s\n", str = ak_ptr_to_hexstr( out, 16, ak_false )); free( str );
    printf("std ciphertext:\t%s\n", str = ak_ptr_to_hexstr( cipher_text, 16, ak_false )); free( str );

    /* Расшифрование одного блока информации */
    printf("\nDecryption test:\n");
    bkey->decrypt(&bkey->key, cipher_text, out);
    printf("out user text:\t%s\n", str = ak_ptr_to_hexstr( out, 16, ak_false )); free( str );
    printf("std user text:\t%s\n", str = ak_ptr_to_hexstr( user_text, 16, ak_false )); free( str );

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

    printf("RC6 algorithm example tests\n\n");
    printf("Test set 1:\n");
    ak_uint8 user_key_1[32]         = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ak_uint8 user_text_1[16]        = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ak_uint8 cipher_text_1[16]      = {0x8f, 0x5f, 0xbd, 0x05, 0x10, 0xd1, 0x5f, 0xa8, 0x93, 0xfa, 0x3f, 0xda, 0x6e, 0x85, 0x7e, 0xc2};
    test(user_key_1, user_text_1, cipher_text_1);

    printf("Test set 2:\n");
    ak_uint8 user_key_2[32]         = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
                                       0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe};
    ak_uint8 user_text_2[16]        = {0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1};
    ak_uint8 cipher_text_2[16]      = {0xc8, 0x24, 0x18, 0x16, 0xf0, 0xd7, 0xe4, 0x89, 0x20, 0xad, 0x16, 0xa1, 0x67, 0x4e, 0x5d, 0x48};
    test(user_key_2, user_text_2, cipher_text_2);
    return ak_libakrypt_destroy();
}
