<?php namespace SZonov\LightAcl;

class AclArray
{
    const DEFAULT_TAB = '    ';

    protected $array;
    protected $tab;

    public function __construct($array, $tab = self::DEFAULT_TAB)
    {
        $this->array = $array;
        $this->tab = $tab;
    }

    public static function stringify(Acl $acl, $tab = self::DEFAULT_TAB)
    {
        return (string)new self($acl->toArray(), $tab);
    }

    public function __toString()
    {
        $str = "[\n";

        foreach ($this->array as $roleName => $permissions)
        {
            $str .= $this->t() . $this->e($roleName) . " => [ ";

            $str .= $this->v(array_shift($permissions)) . ",\n";

            foreach ($permissions as $endpoint => $value) {
                if (is_int($endpoint)) {
                    $str .= $this->t(2) . $this->v($value) . ",\n";
                } else {
                    $str .= $this->t(2) . $this->e($endpoint) . " => " . $this->v($value) . ",\n";
                }
            }

            $str .= $this->t() . "],\n";
        }
        $str .= "]\n";
        return $str;
    }

    protected function t($amount = 1)
    {
        return str_repeat($this->tab, $amount);
    }

    protected function e($value)
    {
        return var_export($value, true);
    }

    protected function v($value)
    {
        if (false === $value)
            return 'false';

        if (true === $value)
            return 'true';

        if (null === $value)
            return 'null';

        if (is_array($value))
        {
            $values = [];
            foreach ($value as $k=>$v) {
                if (is_int($k))
                    $values[] = $this->v($v);
                else if ($v === true)
                    $values[] = $this->e($k);
                else
                    $values[] = $this->e($k) . ' => ' . $this->v($v);
            }
            return '[' . join(', ', $values) . ']';
        }

        return $this->e($value);
    }
}
