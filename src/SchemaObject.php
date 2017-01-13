<?php

namespace jbelich\DoubleRatchet;

abstract class SchemaObject implements \ArrayAccess {

    protected $schema = [];
    protected $values = [];
    protected $defaults = [];

    protected function __construct(array $schema = [], array $defaults = [])
    {
        $constants = (new \ReflectionClass(get_class($this)))->getConstants();

        $vars = array_intersect_key($constants, array_flip(preg_grep('/^VAR_/', array_keys($constants))));
        $this->setSchema(array_unique(array_values($schema)
            + array_values($vars)
            + $this->schema));

        $vals = array_intersect_key($constants, array_flip(preg_grep('/^DEFAULT_/', array_keys($constants))));
        $nvals = [];
        foreach ($vars as $var_const => $var) {
            $val_const = preg_replace("/^VAR_/", "DEFAULT_", $var_const);
            if (isset($vals[$val_const])) {
                $nvals[$var] = $vals[$val_const];
            }
        }
        $this->setDefaults($defaults
            + $nvals
            + $this->defaults);
    }

    public function setSchema(array $schema = [], $merge = FALSE)
    {
        if ($merge === FALSE) {
            $this->schema = $schema;
        } elseif ($merge === TRUE) {
            $this->schema += $schema;
        } else {
            throw new \UnexpectedValueException('$merge parameter MUST be TRUE or FALSE');
        }

        return $this;
    }

    public function setDefaults(array $defaults = [], $merge = FALSE)
    {
        if ($merge === FALSE) {
            $this->defaults = $defaults;
        } elseif ($merge === TRUE) {
            $this->defaults = array_merge($this->defaults, $defaults);
        } else {
            throw new \UnexpectedValueException('$merge parameter MUST be TRUE or FALSE');
        }

        return $this;
    }

    public function getSchema()
    {
        return $this->schema;
    }

    public function getDefaults()
    {
        return $this->defaults;
    }

    public function resetValues()
    {
        $this->values = [];

        return $this;
    }

    public function toArray()
    {
        return $this->values + $this->defaults;
    }

    public function offsetIsset($offset)
    {
        if (!$this->offsetExists($offset)) {
            throw new \InvalidArgumentException(sprintf('Identifier "%s" is not defined.', $offset));
        }

        return isset($this->values[$offset]) && !is_null($this->values[$offset]);
    }

    public function offsetExists($offset)
    {
        return (bool) in_array($offset, $this->schema);
    }

    public function offsetGet($offset)
    {
        if ($this->offsetIsset($offset)) {
            return $this->values[$offset];
        }

        if (isset($this->defaults[$offset])) {
            return $this->defaults[$offset]; // do we want to set the value? not so sure;
        }

        return NULL;
    }

    public function offsetSet($offset, $value)
    {
        if (!$this->offsetExists($offset)) {
            throw new \InvalidArgumentException(sprintf('Identifier "%s" is not defined.', $offset));
        }

        $this->values[$offset] = $value;
    }

    public function offsetUnset($offset)
    {
        if (isset($this->values[$offset])) {
            unset($this->values[$offset]);
        }
    }
}
