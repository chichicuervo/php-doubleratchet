<?php
/**
 *
 * Copyright (C) 2017 Jason E Belich <jason@belich.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
**/

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
