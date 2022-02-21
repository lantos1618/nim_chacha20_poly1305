# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest

import nim_chacha20_poly1305/[common, chacha20_poly1305]
import stint
import std/sysrand

suite "chacha20_poly1305":
    test "chacha20_poly1305_key_gen":
        # https://datatracker.ietf.org/doc/html/rfc8439#section-2.6.2
        var
            key_in: Key = [
                0x80'u8, 0x81'u8, 0x82'u8, 0x83'u8, 0x84'u8, 0x85'u8, 0x86'u8, 0x87'u8,
                0x88'u8, 0x89'u8, 0x8a'u8, 0x8b'u8, 0x8c'u8, 0x8d'u8, 0x8e'u8, 0x8f'u8,
                0x90'u8, 0x91'u8, 0x92'u8, 0x93'u8, 0x94'u8, 0x95'u8, 0x96'u8, 0x97'u8,
                0x98'u8, 0x99'u8, 0x9a'u8, 0x9b'u8, 0x9c'u8, 0x9d'u8, 0x9e'u8, 0x9f'u8,
            ]
            nonce_in: Nonce = [
                0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
                0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8,
                0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8
            ]
            otk_expected: Key = [
                0x8a'u8, 0xd5'u8, 0xa0'u8, 0x8b'u8, 0x90'u8, 0x5f'u8, 0x81'u8, 0xcc'u8,
                0x81'u8, 0x50'u8, 0x40'u8, 0x27'u8, 0x4a'u8, 0xb2'u8, 0x94'u8, 0x71'u8,
                0xa8'u8, 0x33'u8, 0xb6'u8, 0x37'u8, 0xe3'u8, 0xfd'u8, 0x0d'u8, 0xa5'u8,
                0x08'u8, 0xdb'u8, 0xb8'u8, 0xe2'u8, 0xfd'u8, 0xd1'u8, 0xa6'u8, 0x46'u8
            ]
            counter_in: Counter
            otk_out: Key

        otk_out = chacha20_poly1305_key_gen(key_in, nonce_in, counter_in)
        check(otk_out == otk_expected)

    test "chacha20_aead_poly1305":

        var
            key_in = [
                0x80'u8, 0x81'u8, 0x82'u8, 0x83'u8, 0x84'u8, 0x85'u8, 0x86'u8, 0x87'u8, 0x88'u8, 0x89'u8, 0x8a'u8, 0x8b'u8, 0x8c'u8, 0x8d'u8, 0x8e'u8, 0x8f'u8,
                0x90'u8, 0x91'u8, 0x92'u8, 0x93'u8, 0x94'u8, 0x95'u8, 0x96'u8, 0x97'u8, 0x98'u8, 0x99'u8, 0x9a'u8, 0x9b'u8, 0x9c'u8, 0x9d'u8, 0x9e'u8, 0x9f'u8,
            ]

            nonce_in: Nonce = [
                0x07'u8, 0x00'u8, 0x00'u8, 0x00'u8,
                0x40'u8, 0x41'u8, 0x42'u8, 0x43'u8, 0x44'u8, 0x45'u8, 0x46'u8, 0x47'u8
            ]
            counter: Counter = 0
            # Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
            message_in_bytes: array[114, byte] = [
                0x4c'u8, 0x61'u8, 0x64'u8, 0x69'u8, 0x65'u8, 0x73'u8, 0x20'u8, 0x61'u8, 0x6e'u8, 0x64'u8, 0x20'u8, 0x47'u8, 0x65'u8, 0x6e'u8, 0x74'u8, 0x6c'u8,
                0x65'u8, 0x6d'u8, 0x65'u8, 0x6e'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x63'u8, 0x6c'u8, 0x61'u8, 0x73'u8,
                0x73'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x20'u8, 0x27'u8, 0x39'u8, 0x39'u8, 0x3a'u8, 0x20'u8, 0x49'u8, 0x66'u8, 0x20'u8, 0x49'u8, 0x20'u8, 0x63'u8,
                0x6f'u8, 0x75'u8, 0x6c'u8, 0x64'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x66'u8, 0x65'u8, 0x72'u8, 0x20'u8, 0x79'u8, 0x6f'u8, 0x75'u8, 0x20'u8, 0x6f'u8,
                0x6e'u8, 0x6c'u8, 0x79'u8, 0x20'u8, 0x6f'u8, 0x6e'u8, 0x65'u8, 0x20'u8, 0x74'u8, 0x69'u8, 0x70'u8, 0x20'u8, 0x66'u8, 0x6f'u8, 0x72'u8, 0x20'u8,
                0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x66'u8, 0x75'u8, 0x74'u8, 0x75'u8, 0x72'u8, 0x65'u8, 0x2c'u8, 0x20'u8, 0x73'u8, 0x75'u8, 0x6e'u8, 0x73'u8,
                0x63'u8, 0x72'u8, 0x65'u8, 0x65'u8, 0x6e'u8, 0x20'u8, 0x77'u8, 0x6f'u8, 0x75'u8, 0x6c'u8, 0x64'u8, 0x20'u8, 0x62'u8, 0x65'u8, 0x20'u8, 0x69'u8,
                0x74'u8, 0x2e'u8,
            ]   
            auth_data_in = [
                0x50'u8, 0x51'u8, 0x52'u8, 0x53'u8, 0xc0'u8, 0xc1'u8, 0xc2'u8, 0xc3'u8, 0xc4'u8, 0xc5'u8, 0xc6'u8, 0xc7'u8
            ]
            otk_out: Key
            tag_out: Tag
            cipher_bytes_out: array[114, byte]
            otk_expected: Key = [
                0x7b'u8, 0xac'u8, 0x2b'u8, 0x25'u8, 0x2d'u8, 0xb4'u8, 0x47'u8, 0xaf'u8,
                0x09'u8, 0xb6'u8, 0x7a'u8, 0x55'u8, 0xa4'u8, 0xe9'u8, 0x55'u8, 0x84'u8,
                0x0a'u8, 0xe1'u8, 0xd6'u8, 0x73'u8, 0x10'u8, 0x75'u8, 0xd9'u8, 0xeb'u8,
                0x2a'u8, 0x93'u8, 0x75'u8, 0x78'u8, 0x3e'u8, 0xd5'u8, 0x53'u8, 0xff'u8
            ]
            tag_expected: Tag = [
                0x1a'u8, 0xe1'u8, 0x0b'u8, 0x59'u8, 0x4f'u8, 0x09'u8, 0xe2'u8, 0x6a'u8,
                0x7e'u8, 0x90'u8, 0x2e'u8, 0xcb'u8, 0xd0'u8, 0x60'u8, 0x06'u8, 0x91'u8
            ]
            cipher_message_expected: array[114, byte] = [
                0xd3'u8, 0x1a'u8, 0x8d'u8, 0x34'u8, 0x64'u8, 0x8e'u8, 0x60'u8, 0xdb'u8,
                0x7b'u8, 0x86'u8, 0xaf'u8, 0xbc'u8, 0x53'u8, 0xef'u8, 0x7e'u8, 0xc2'u8,
                0xa4'u8, 0xad'u8, 0xed'u8, 0x51'u8, 0x29'u8, 0x6e'u8, 0x08'u8, 0xfe'u8,
                0xa9'u8, 0xe2'u8, 0xb5'u8, 0xa7'u8, 0x36'u8, 0xee'u8, 0x62'u8, 0xd6'u8,
                0x3d'u8, 0xbe'u8, 0xa4'u8, 0x5e'u8, 0x8c'u8, 0xa9'u8, 0x67'u8, 0x12'u8,
                0x82'u8, 0xfa'u8, 0xfb'u8, 0x69'u8, 0xda'u8, 0x92'u8, 0x72'u8, 0x8b'u8,
                0x1a'u8, 0x71'u8, 0xde'u8, 0x0a'u8, 0x9e'u8, 0x06'u8, 0x0b'u8, 0x29'u8,
                0x05'u8, 0xd6'u8, 0xa5'u8, 0xb6'u8, 0x7e'u8, 0xcd'u8, 0x3b'u8, 0x36'u8,
                0x92'u8, 0xdd'u8, 0xbd'u8, 0x7f'u8, 0x2d'u8, 0x77'u8, 0x8b'u8, 0x8c'u8,
                0x98'u8, 0x03'u8, 0xae'u8, 0xe3'u8, 0x28'u8, 0x09'u8, 0x1b'u8, 0x58'u8,
                0xfa'u8, 0xb3'u8, 0x24'u8, 0xe4'u8, 0xfa'u8, 0xd6'u8, 0x75'u8, 0x94'u8,
                0x55'u8, 0x85'u8, 0x80'u8, 0x8b'u8, 0x48'u8, 0x31'u8, 0xd7'u8, 0xbc'u8,
                0x3f'u8, 0xf4'u8, 0xde'u8, 0xf0'u8, 0x8e'u8, 0x4b'u8, 0x7a'u8, 0x9d'u8,
                0xe5'u8, 0x76'u8, 0xd2'u8, 0x65'u8, 0x86'u8, 0xce'u8, 0xc6'u8, 0x4b'u8,
                0x61'u8, 0x16'u8
            ]
            # mac_expected: array[160, byte] = [
            #     0x50'u8, 0x51'u8, 0x52'u8, 0x53'u8, 0xc0'u8, 0xc1'u8, 0xc2'u8, 0xc3'u8, 0xc4'u8, 0xc5'u8, 0xc6'u8, 0xc7'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
            #     0xd3'u8, 0x1a'u8, 0x8d'u8, 0x34'u8, 0x64'u8, 0x8e'u8, 0x60'u8, 0xdb'u8, 0x7b'u8, 0x86'u8, 0xaf'u8, 0xbc'u8, 0x53'u8, 0xef'u8, 0x7e'u8, 0xc2'u8,
            #     0xa4'u8, 0xad'u8, 0xed'u8, 0x51'u8, 0x29'u8, 0x6e'u8, 0x08'u8, 0xfe'u8, 0xa9'u8, 0xe2'u8, 0xb5'u8, 0xa7'u8, 0x36'u8, 0xee'u8, 0x62'u8, 0xd6'u8,
            #     0x3d'u8, 0xbe'u8, 0xa4'u8, 0x5e'u8, 0x8c'u8, 0xa9'u8, 0x67'u8, 0x12'u8, 0x82'u8, 0xfa'u8, 0xfb'u8, 0x69'u8, 0xda'u8, 0x92'u8, 0x72'u8, 0x8b'u8,
            #     0x1a'u8, 0x71'u8, 0xde'u8, 0x0a'u8, 0x9e'u8, 0x06'u8, 0x0b'u8, 0x29'u8, 0x05'u8, 0xd6'u8, 0xa5'u8, 0xb6'u8, 0x7e'u8, 0xcd'u8, 0x3b'u8, 0x36'u8,
            #     0x92'u8, 0xdd'u8, 0xbd'u8, 0x7f'u8, 0x2d'u8, 0x77'u8, 0x8b'u8, 0x8c'u8, 0x98'u8, 0x03'u8, 0xae'u8, 0xe3'u8, 0x28'u8, 0x09'u8, 0x1b'u8, 0x58'u8,
            #     0xfa'u8, 0xb3'u8, 0x24'u8, 0xe4'u8, 0xfa'u8, 0xd6'u8, 0x75'u8, 0x94'u8, 0x55'u8, 0x85'u8, 0x80'u8, 0x8b'u8, 0x48'u8, 0x31'u8, 0xd7'u8, 0xbc'u8,
            #     0x3f'u8, 0xf4'u8, 0xde'u8, 0xf0'u8, 0x8e'u8, 0x4b'u8, 0x7a'u8, 0x9d'u8, 0xe5'u8, 0x76'u8, 0xd2'u8, 0x65'u8, 0x86'u8, 0xce'u8, 0xc6'u8, 0x4b'u8,
            #     0x61'u8, 0x16'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
            #     0x0c'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x72'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
            # ]


         
        otk_out = chacha20_poly1305_key_gen(key_in, nonce_in, 0)
        check(otk_out == otk_expected)

        chacha20_aead_poly1305(
            key_in,
            nonce_in,
            counter,
            auth_data_in,
            message_in_bytes,
            cipher_bytes_out,
            tag_out)

        check(cipher_bytes_out == cipher_message_expected)
        check(tag_out == tag_expected )
    test "chacha20_aead_poly1305_encrypt and chacha20_aead_poly1305_decrypt":
        var 
            key: Key
            nonce: Nonce
            counter: Counter = 0
            plain_data: array[114, byte] = [
                0x4c'u8, 0x61'u8, 0x64'u8, 0x69'u8, 0x65'u8, 0x73'u8, 0x20'u8, 0x61'u8, 0x6e'u8, 0x64'u8, 0x20'u8, 0x47'u8, 0x65'u8, 0x6e'u8, 0x74'u8, 0x6c'u8,
                0x65'u8, 0x6d'u8, 0x65'u8, 0x6e'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x63'u8, 0x6c'u8, 0x61'u8, 0x73'u8,
                0x73'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x20'u8, 0x27'u8, 0x39'u8, 0x39'u8, 0x3a'u8, 0x20'u8, 0x49'u8, 0x66'u8, 0x20'u8, 0x49'u8, 0x20'u8, 0x63'u8,
                0x6f'u8, 0x75'u8, 0x6c'u8, 0x64'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x66'u8, 0x65'u8, 0x72'u8, 0x20'u8, 0x79'u8, 0x6f'u8, 0x75'u8, 0x20'u8, 0x6f'u8,
                0x6e'u8, 0x6c'u8, 0x79'u8, 0x20'u8, 0x6f'u8, 0x6e'u8, 0x65'u8, 0x20'u8, 0x74'u8, 0x69'u8, 0x70'u8, 0x20'u8, 0x66'u8, 0x6f'u8, 0x72'u8, 0x20'u8,
                0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x66'u8, 0x75'u8, 0x74'u8, 0x75'u8, 0x72'u8, 0x65'u8, 0x2c'u8, 0x20'u8, 0x73'u8, 0x75'u8, 0x6e'u8, 0x73'u8,
                0x63'u8, 0x72'u8, 0x65'u8, 0x65'u8, 0x6e'u8, 0x20'u8, 0x77'u8, 0x6f'u8, 0x75'u8, 0x6c'u8, 0x64'u8, 0x20'u8, 0x62'u8, 0x65'u8, 0x20'u8, 0x69'u8,
                0x74'u8, 0x2e'u8,
            ]
            cipher_data:  array[114, byte]
            cipher_data_decrypted:  array[114, byte]
            aad: array[18, byte] = [
                97'u8, 117'u8, 116'u8, 104'u8, 101'u8, 110'u8, 116'u8, 105'u8, 99'u8, 97'u8, 116'u8, 101'u8, 100'u8, 32'u8, 100'u8, 97'u8, 116'u8, 97'u8]
            tag_expected: Tag
            tag_out: Tag

        discard urandom(nonce)
        chacha20_aead_poly1305_encrypt(
            key,
            nonce,
            counter,
            aad,
            plain_data,
            cipher_data,
            tag_expected
        )
        counter = 0
        chacha20_aead_poly1305_decrypt(
            key,
            nonce,
            counter,
            aad,
            cipher_data_decrypted,
            cipher_data,
            tag_out
        )

        check(tag_out == tag_expected)
        check(cipher_data_decrypted == plain_data)
        