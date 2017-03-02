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

use jbelich\DoubleRatchet\SchemaObject;
use jbelich\DoubleRatchet\Stateful;

class Header extends SchemaObject {
    use Stateful;

    const VAR_REMOTE_PUBLIC_KEY = 'remote_public_key';
    const VAR_LOCAL_PUBLIC_KEY = 'local_public_key';
    const VAR_PREV_NUM = 'prev_iter';
    const VAR_SEND_NUM = 'send_iter';

    const VAR_SERIALIZED_HEADER = 'serialized_header';

    const DEFAULT_BUFFER_SIZE = 64;

    static public function factory($state, array $options = [])
    {
        $options = $options + [
            'header_class' => __CLASS__
        ];

        if (!class_exists($options['header_class']) || ($options['header_class'] != __CLASS__ && !is_subclass_of($options['header_class'], __CLASS__))) {
            throw new \InvalidArgumentException('Options[header_class] must extend Header');
        }

        return new $options['header_class']($state, $options);
    }

    public function __construct($state, array $options = [])
    {
        $this->setState($state);
        parent::__construct($options['header_schema'] ?? [], $options['header_defaults'] ?? []);
    }

    public function __toString()
    {
        return $this->getString();
    }

    public function isRatchetable()  // rename?
    {
        if (!isset($this->values[self::VAR_REMOTE_PUBLIC_KEY])) {
            throw new \UnexpectedValueException('Header does not contain a valid ' . self::VAR_REMOTE_PUBLIC_KEY);
        }

        return (bool) (!isset($this->state['remote_public_key']) || !isset($this->state['receive_chain_key']) || $this->values[self::VAR_REMOTE_PUBLIC_KEY] != $this->state['remote_public_key']);
    }

    public function getString()
    {
        if (!isset($this->state['associated_data']) || !$this->state['associated_data']) {
            $buf = $this->state['crypt']->getRandomBytes(self::DEFAULT_BUFFER_SIZE);
            $this->state['associated_data'] = pack("V", strlen($buf)) . $buf;
        }

        if (!isset($this[self::VAR_SERIALIZED_HEADER]) || !$this->offsetIsset(self::VAR_SERIALIZED_HEADER)) {
            $this[self::VAR_SERIALIZED_HEADER] = $this[self::VAR_LOCAL_PUBLIC_KEY]
                . pack("V", $this[self::VAR_PREV_NUM])
                . pack("V", $this[self::VAR_SEND_NUM]);
        }

        return $this->state['associated_data'] . $this[self::VAR_SERIALIZED_HEADER];
    }

    public function setString($headerstring)
    {
        $this->resetValues();

        if (!isset($this->state['associated_data']) || !$this->state['associated_data']) {
            $len = unpack("V", substr($headerstring, 0, 4))[1] ?? 0;
            $this->state['associated_data'] = substr($headerstring, 0, 4 + $len);
            $headerstring = substr($headerstring, 4 + $len);

        } else {
            $len = strlen($this->state['associated_data']);
            $ad = substr($headerstring, 0, $len);
            if ($this->state['associated_data'] != $ad) {
                throw new \UnexpectedValueException('Session associated_data does not match Header associated_data');
            }
            $headerstring = substr($headerstring, $len);
        }

        $key_length = 32; // this needs to be a state var or accessible in $crypt

        $this[self::VAR_REMOTE_PUBLIC_KEY] = substr($headerstring, 0, $key_length);
        $this[self::VAR_PREV_NUM] = unpack("V", substr($headerstring, $key_length, 4))[1] ?: 0;
        $this[self::VAR_SEND_NUM] = unpack("V", substr($headerstring, $key_length + 4, 4))[1] ?: 0;
        $this[self::VAR_SERIALIZED_HEADER] = $headerstring;

        return $this;
    }

    public function offsetSet($offset, $value)
    {
        if ($offset != self::VAR_SERIALIZED_HEADER && isset($this->values[self::VAR_SERIALIZED_HEADER]) && $this->offsetExists($offset)) {
            self::offsetUnset(self::VAR_SERIALIZED_HEADER);
        }

        parent::offsetSet($offset, $value);
    }
}
