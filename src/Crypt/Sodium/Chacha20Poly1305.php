<?php

namespace jbelich\DoubleRatchet\Crypt\Sodium;

use jbelich\DoubleRatchet\Crypt;
use jbelich\DoubleRatchet\CryptInterface;

class Chacha20Poly1305 extends Crypt implements CryptInterface {

    public function makeKeypair()
    {
        return \Sodium\crypto_box_keypair();
    }

    public function getPublicKey($key_pair)
    {
        return \Sodium\crypto_box_publickey($key_pair);
    }

    public function getSecretKey($key_pair)
    {
        return \Sodium\crypto_box_secretkey($key_pair);
    }

    public function getKeyPair($public_key, $secret_key)
    {
        return \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
    }

    public function makeSharedSecret($local_key_pair, $public_key, $mode = self::MODE_RECEIVER)
    {
        return \Sodium\crypto_kx(
            \Sodium\crypto_box_secretkey($local_key_pair),
            $public_key,
            $mode === self::MODE_SENDER ? \Sodium\crypto_box_publickey($local_key_pair) : $public_key,
            $mode === self::MODE_SENDER ? $public_key : \Sodium\crypto_box_publickey($local_key_pair)
        );
    }

    public function getRandomBytes($length)
    {
        return \Sodium\randombytes_buf($length);
    }

    public function Encrypt($message_key, $headerstring, $plaintext)
    {
        return \Sodium\crypto_aead_chacha20poly1305_encrypt(
            $plaintext,
            $headerstring,
            substr(\Sodium\crypto_generichash($this->state['nonce']), 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES),
            $message_key
        );
    }

    public function Decrypt($message_key, $headerstring, $ciphertext)
    {
        return \Sodium\crypto_aead_chacha20poly1305_decrypt(
            $ciphertext,
            $headerstring,
            substr(\Sodium\crypto_generichash($this->state['nonce']), 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES),
            $message_key
        );
    }

}
