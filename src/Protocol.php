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

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\State;

class Protocol {

    const MODE_SENDER = 1;
    const MODE_RECEIVER = 0;

    const DEFAULT_SKIP_MAX = 100;
    const DEFAULT_BUFFER_SIZE = 64;

    public $state;

    public function __construct($mode, array $options = [])
    {
        if ($mode !== self::MODE_SENDER && $mode !== self::MODE_RECEIVER ) {
            throw new \InvalidArgumentException(sprintf('You must initialize the protocol init mode: (%1$s::MODE_SENDER|%1$s::MODE_RECEIVER).', __CLASS__));
        }

        $this->state = new State($mode, [
            'send_num' => 0,
            'recv_num' => 0,
            'prev_num' => 0,
            'skipped'  => [],
        ], $options);
    }

    public function getStateArray()
    {
        return $this->state->toArray();
    }

    public function setStateArray(array $state)
    {
        $mode = $state[0]['mode'];
        $this->state = (new State($mode))->fromArray($state);

        return $this;
    }

    public function Decrypt($header, $ciphertext)
    {
        if ($plaintext = $this->try_skipped($ciphertext, $header)) {
            return $plaintext;
        }

        if ($header instanceof Header) {
            $header_string = (string) $header;
            $this->state['header'] = $header;
        } else {
            $header_string = $header;
            $header = $this->state['header']->setString($header_string);
        }
        // what about encrypted?

        if ($header->isRatchetable()) {
            $this->skip($header['prev_num']);
            $this->ratchet();
        }
        $this->skip($header['send_num']);
        $header->resetValues(); // resetValues() only resets local object changes. Serialization reverts to $state then defaults

        $message_key = $this->state['kdf']->nextMessageKey(self::MODE_RECEIVER);

        $this->state['recv_num'] = $this->state['recv_num'] + 1; // can't ++ increment a \Container, fya

        // return decrypted string
        $plaintext = $this->state['crypt']->Decrypt($message_key, $header_string, $ciphertext);

        return $plaintext;
    }

    public function Encrypt($plaintext)
    {
        if(!isset($this->state['sender_chain_key'])) {
            $this->state['kdf']->nextChainKey(self::MODE_SENDER);
        }
        if(!isset($this->state['sender_chain_key'])) {
            throw new \Exception;
        }
        $cipher = [
            // resetValues() only resets local object changes. Serialization reverts to $state then defaults
            $headerstring = (string) $this->state['header']->resetValues(),
            $this->state['crypt']->Encrypt($this->state['kdf']->nextMessageKey(self::MODE_SENDER), $headerstring, $plaintext)
        ];

        $this->state['send_num'] = $this->state['send_num'] + 1; // can't ++ increment a \Container, fya

        return $cipher;
    }

    protected function ratchet()
    {
        unset($this->state['sender_chain_key']);
        $this->state['remote_public_key'] = $this->state['header']['remote_public_key'];

        $this->state['prev_num'] = $this->state['send_num']; // should this be from header insteader?
        $this->state['send_num'] = 0;
        $this->state['recv_num'] = 0;

        $this->state['kdf']->nextChainKey(self::MODE_RECEIVER);
        $this->state['local_key_pair'] = $this->state['crypt']->makeKeypair();
    }

    protected function skip($until)
    {
        $max = isset($this->state['skip_max']) ? $this->state['skip_max'] : self::DEFAULT_SKIP_MAX;

        if ($this->state['recv_num'] + $max < $until) {
            throw new \OutOfBoundsException();
        }

        if (isset($this->state['receive_chain_key']) && $this->state['receive_chain_key']) {
            $skip_key_name = is_callable([$this->state['header'], 'decrypt']) ? 'receive_header_key' : 'remote_public_key';
            $skipped = $this->state['skipped']; // stupid ArrayAccess indirect modification bullshit

            while ($this->state['recv_num'] < $until) { // shoudl recv_num use $header?
                if (!isset($this->state[$skip_key_name])) {
                    throw new \Exception; // should it retry/restart?
                }

                $message_key = $this->state['kdf']->nextMessageKey(self::MODE_RECEIVER);
                $skip_key = $this->state[$skip_key_name];

                $skipped[$skip_key] = $skipped[$skip_key] ?? [];
                $skipped[$skip_key][$this->state['recv_num']] = $message_key;
                $this->state['recv_num'] = $this->state['recv_num'] + 1; // can't ++ increment a \Container, fya
            }
            $this->state['skipped'] = $skipped;
        }
    }

    protected function try_skipped($ciphertext, $header = NULL)
    {
        if ($header) { // we're encrypted or serialized
            if ($header instanceof Header) {
                $header_string = (string) $header;
                $this->state['header'] = $header;
            } else {
                $header_string = $header;
                $header = $this->state['header'];
            }

            if (is_callable([$header, 'decrypt'])) { // we're expecting encrypted header
                foreach ($this->state['skipped'] as $header_key => $v) {
                    foreach ($v as $recv_num => $message_key) {
                        if ($decrypted = $header->decrypt($header_key, $header_string)) {
                            unset($this->state['skipped'][$header_key][$recv_num]);
                            break 2;
                        }
                    }
                }
                if (!$decrypted) {
                    // throw new \Exception;
                    return NULL;
                }

                $header->setString($decrypted);
            } else {
                $header->setString($header_string);
            }
        } else {
            $header = $this->state['header'];
        }

        if (!isset($message_key) || !$message_key) {
            $skip_key_name = is_callable([$header, 'decrypt']) ? 'receive_header_key' : 'remote_public_key';
            if (!isset($this->state[$skip_key_name])) {
                throw new \Exception; // should it retry/restart?
                // return NULL;
            }
            $skip_key = $this->state[$skip_key_name];

            if ($skip_key && isset($this->state['skipped'][$skip_key])) {  // fuck you indirect modification of overloaded element!!!!!!!!
                $skipped = $this->state['skipped'];

                if (isset($skipped[$skip_key][$header['send_num']])) {
                    $message_key = $skipped[$skip_key][$header['send_num']];
                    unset($skipped[$skip_key][$header['send_num']]);
                }
                $this->state['skipped'] = $skipped;
            }
        }

        if (!isset($message_key) || !$message_key) {
            // throw new \Exception();
            return NULL;
        }

        return $this->state['crypt']->Decrypt($message_key, (string) $header, $ciphertext);
    }
}
