<?php

namespace jbelich\DoubleRatchet;

use Pimple\Container;

class DefaultContainer extends Container {

    private $defaults;

    const BYPASS_PREFIX = '.';

    public function __construct(array $values = array())
    {
        $this->defaults = new Container;

        foreach ($values as $key => $value) {
            if ($value instanceof \Closure || method_exists($value, '__invoke')) {
                $this->offsetSet($key{0} == self::BYPASS_PREFIX ? $key : (self::BYPASS_PREFIX . $key), $value);
                unset($values[$key]); // we could just pass it on below, but why should we loop thru the whole array twice?
            }
        }

        parent::__construct($values);
    }

    public function offsetSet($offset, $value)
    {
        if ($offset{0} == self::BYPASS_PREFIX) {
            if ($value instanceof \Closure || method_exists($value, '__invoke')) {
                $value = $this->defaults->factory(function ($c) use ($value) {
                    return $value($this);
                });
            }
            return $this->defaults->offsetSet(substr($offset, 1), $value);
        }

        return parent::offsetSet($offset, $value);
    }

    public function offsetGet($offset)
    {
        if ($offset{0} == self::BYPASS_PREFIX) {
            return $this->defaults->offsetGet(substr($offset, 1));

        } elseif (!parent::offsetExists($offset) && $this->defaults->offsetExists($offset)) {
            parent::offsetSet($offset, $this->defaults->offsetGet($offset));
        }

        return parent::offsetGet($offset);
    }

    public function offsetExists($offset)
    {
        if ($offset{0} == self::BYPASS_PREFIX) {
            return $this->defaults->offsetExists(substr($offset, 1));
        }

        return parent::offsetExists($offset) || $this->defaults->offsetExists($offset);
    }

    public function offsetUnset($offset)
    {
        if ($offset{0} == self::BYPASS_PREFIX) {
            return $this->defaults->offsetUnset(substr($offset, 1));
        }

        return parent::offsetUnset($offset);
    }

}
