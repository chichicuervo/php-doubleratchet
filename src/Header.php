<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\SchemaObject;
use jbelich\DoubleRatchet\Stateful;

class Header extends SchemaObject {
    use Stateful;

    const VAR_REMOTE_PUBLIC_KEY = 'remote_public_key';
    const VAR_LOCAL_PUBLIC_KEY = 'local_public_key';
    const VAR_PREV_NUM = 'prev_num';
    const VAR_SEND_NUM = 'send_num';

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

    public function setString($serialized)
    {
        $this->resetValues();

        if (!isset($this->state['associated_data']) || !$this->state['associated_data']) {
            $len = unpack("V", substr($serialized, 0, 4))[1] ?? 0;
            $this->state['associated_data'] = substr($serialized, 0, 4 + $len);
            $serialized = substr($serialized, 4 + $len);

        } else {
            $len = strlen($this->state['associated_data']);
            $ad = substr($serialized, 0, $len);
            if ($this->state['associated_data'] != $ad) {
                throw new \UnexpectedValueException('Session associated_data does not match Header associated_data');
            }
            $serialized = substr($serialized, $len);
        }

        $key_length = 32; // this needs to be a state var or accessible in $crypt

        $this[self::VAR_REMOTE_PUBLIC_KEY] = substr($serialized, 0, $key_length);
        $this[self::VAR_PREV_NUM] = unpack("V", substr($serialized, $key_length, 4))[1] ?: 0;
        $this[self::VAR_SEND_NUM] = unpack("V", substr($serialized, $key_length + 4, 4))[1] ?: 0;
        $this[self::VAR_SERIALIZED_HEADER] = $serialized;

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
