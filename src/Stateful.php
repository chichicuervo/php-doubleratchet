<?php

namespace jbelich\DoubleRatchet;

use jbelich\DoubleRatchet\SchemaObject;

trait Stateful {

    protected $state;

    public function setState($state)
    {
        if (!is_array($state) && !$state instanceof \ArrayAccess) {
            throw new \InvalidArgumentException('$state must be an array or implement \ArrayAccess');
        }

        $this->state = $state;

        return $this;
    }

    public function getState()
    {
        if (!isset($this->state)) {
            throw new \DomainException('$state must be set for ' . get_class($this));
        }

        return $this->state;
    }

    public function offsetGet($offset)
    {
        if (!$this instanceof \ArrayAccess) {
            throw new \BadMethodCallException('use of offsetGet() requires class ' . get_class($this) . ' to implement ArrayAccess');
        }

        if ($this instanceof SchemaObject) {
            if(!$this->offsetIsset($offset) && isset($this->state[$offset])) {
                $this->offsetSet($offset, $this->state[$offset]);
            }
        } elseif (!$this->offsetExists($offset) && isset($this->state[$offset])) {
            $this->offsetSet($offset, $this->state[$offset]);
        }

        return parent::offsetGet($offset);
    }
}
