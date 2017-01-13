<?php

namespace jbelich\DoubleRatchet\Crypt\Sodium\Ietf;

use jbelich\DoubleRatchet\Crypt\Sodium\Chacha20Poly1305 as NonIetf;

class Chacha20Poly1305 extends NonIetf {

    public function Encrypt($message_key, $headerstring, $plaintext)
    {
        return \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            $headerstring,
            substr(\Sodium\crypto_generichash($this->state['nonce']), 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES),
            $message_key
        );
    }

    public function Decrypt($message_key, $headerstring, $ciphertext)
    {
        return \Sodium\crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext,
            $headerstring,
            substr(\Sodium\crypto_generichash($this->state['nonce']), 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES),
            $message_key
        );
    }

}
