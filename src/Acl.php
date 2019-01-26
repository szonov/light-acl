<?php namespace SZonov\LightAcl;

class Acl
{
    protected $_defaultAccess = true;
    protected $_rolesNames = [];
    protected $_roleInherits = [];
    protected $_access = [];
    protected $_matchedAccessKey;

    /**
     * Acl constructor.
     *
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->fromArray($config);
    }

    /**
     * Static method to create Acl object
     *
     * @param array $config
     * @return Acl
     */
    public static function parse(array $config)
    {
        return new static($config);
    }

    /**
     * Load acl from config array
     *
     * key = role name
     * val = permissions (first element is inherit roles, then endpoints)
     *
     * Every permission item
     *  - can be single value 'resource!access' => it mean allow to 'resource!access' endpoint
     *  - can be  'resource!access' => value,
     *    * if value === false - access denied,
     *    * if value === true  - access allowed
     *    * if value === mixed_value, access allowed, but with come conditions
     *                                mixed_value can be used later as condition for limitation in functionality
     * <Example>
     * [
     *      'Guest' => [ null,
     *          'routes!*',
     *          'routes!profile' => false,
     *          'export!*',
     *          'export!documentation.json' => [ 'only' => 'Guest' ],
     *      ],
     *      'Administrator' => [ 'Guest',
     *          '*!*',
     *      ],
     *      'Developer' => [ 'Guest',
     *          '*!dev',
     *          'user!find',
     *          'album!find',
     *          'album!browse'
     *      ],
     *      'Programmer' => [ null,
     *          'routes!*',
     *          '*!pro',
     *      ],
     *      'Master' => [ [ 'Developer', 'Programmer' ] ]
     * ];
     *
     * @param array $config
     * @return $this
     */
    public function fromArray(array $config)
    {
        foreach ($config as $role => $permissions)
        {
            $this->addRole($role, array_shift($permissions));

            foreach ($permissions as $key => $val) {
                $endpoint = is_int($key) ? $val : $key;
                $action = is_int($key) ? true : $val;

                $this->_allowOrDeny($role, $endpoint, $action);
            }
        }
        return $this;
    }

    /**
     * Serializing acl rules to array
     *
     * @return array
     */
    public function toArray()
    {
        $result = [];
        $permissions = [];

        foreach ($this->_access as $key => $value) {
            list($roleName, $endpoint) = explode('!', $key, 2);
            $permissions[$roleName][$endpoint] = $value;
        }

        foreach ($this->_rolesNames as $roleName => $one) {
            $roleInherits = $this->_roleInherits[$roleName] ?? null;

            if (is_array($roleInherits) && count($roleInherits) === 1)
                $roleInherits = $roleInherits[0];

            $result[$roleName] = [ $roleInherits ];

            $p = $permissions[$roleName] ?? [];
            foreach ($p as $endpoint => $value)
            {
                if ($value === true)
                    $result[$roleName][] = $endpoint;
                else
                    $result[$roleName][$endpoint] = $value;
            }
        }
        return $result;
    }

    public function __toString()
    {
        return AclArray::stringify($this);
    }

    /**
     * Sets the default access level (true or false)
     *
     * @param bool $defaultAccess
     * @return $this
     */
    public function setDefaultAction(bool $defaultAccess)
    {
        $this->_defaultAccess = $defaultAccess;
        return $this;
    }

    /**
     *  Returns the default ACL access level
     *
     * @return bool
     */
    public function getDefaultAction()
    {
        return $this->_defaultAccess;
    }

    /**
     * Allow access to a role on a resource
     *
     * You can use '*' as wildcard
     *
     * @param string $roleName
     * @param string $resourceName
     * @param string $access
     * @param array $rules
     * @return Acl
     */
    public function allow($roleName, $resourceName, $access, $rules = [])
    {
        return $this->_allowOrDeny(
            $roleName,
            $resourceName . '!' . $access,
            empty($rules) ? true : $rules
        );
    }

    /**
     * Deny access to a role on a resource
     *
     * You can use '*' as wildcard
     *
     * @param string $roleName
     * @param string $resourceName
     * @param string $access
     * @return Acl
     */
    public function deny($roleName, $resourceName, $access)
    {
        return $this->_allowOrDeny($roleName, $resourceName . '!' . $access, false);
    }

    /**
     * Setup access to a role on an endpoint (resourceName!access)
     *
     * @param string $roleName
     * @param string $endpoint
     * @param bool|array $action
     * @return $this
     *
     */
    protected function _allowOrDeny($roleName, $endpoint, $action)
    {

        $finalAction = $action;
        if (is_array($finalAction))
        {
            $finalAction = [];
            foreach ($action as $key => $val)
            {
                if (is_int($key)) {
                    $key = $val;
                    $val = true;
                }
                $finalAction[$key] = $val;
            }
        }

        $this->_access[$roleName . '!' . $endpoint] = $finalAction;
        return $this;
    }

    /**
     * @param string $roleName
     * @param null|string|string[] $accessInherits
     * @return $this
     */
    public function addRole($roleName, $accessInherits = null)
    {
        $this->_rolesNames[$roleName] = true;

        foreach ((array)$accessInherits as $roleInheritName)
            $this->addInherit($roleName, $roleInheritName);

        return $this;
    }

    /**
     * @param string $roleName
     * @param string $roleInheritName
     * @return $this
     */
    public function addInherit($roleName, $roleInheritName)
    {
        // Make sure we know about this role
        $this->_rolesNames[$roleName] = true;

        // Make sure we know about inherit role
        $this->_rolesNames[$roleInheritName] = true;

        // Skip assigning role to itself
        if ($roleName !== $roleInheritName)
            $this->_roleInherits[$roleName][] = $roleInheritName;

        return $this;
    }

    /**
     * Get list of known roles
     *
     * @return array
     */
    public function getRoles()
    {
        return array_keys($this->_rolesNames);
    }

    /**
     * @param string $roleName
     * @param string $resourceName
     * @param string $access
     * @return mixed|null
     */
    protected function findAccess($roleName, $resourceName, $access)
    {
        $checklist = [
            [$resourceName, $access],
            [$resourceName, '*'],
            ['*', $access],
            ['*', '*'],
        ];

        foreach ($checklist as $row)
        {
            $accessKey = $roleName . '!' . $row[0] . '!' . $row[1];
            if (array_key_exists($accessKey, $this->_access)) {
                $this->_matchedAccessKey = $accessKey;
                return $this->_access[$accessKey];
            }
        }

        return null;
    }

    /**
     * @param string $roleName
     * @param string $resourceName
     * @param string $access
     * @param array $processedRoles
     * @return mixed|null
     */
    protected function findInheritAccess($roleName, $resourceName, $access, &$processedRoles)
    {
        if (in_array($roleName, $processedRoles))
            return null;

        $processedRoles[] = $roleName;

        $result = $this->findAccess($roleName, $resourceName, $access);

        if (null !== $result)
            return $result;

        $inherits = $this->_roleInherits[$roleName] ?? [];

        foreach ($inherits as $inheritRoleName)
        {
            $result = $this->findInheritAccess($inheritRoleName, $resourceName, $access, $processedRoles);

            if (null !== $result)
                return $result;
        }

        return null;
    }

    /**
     * Check whether a role is allowed to access an action from a resource
     *
     * @param string $roleName
     * @param string $resourceName
     * @param string $access
     * @return bool
     */
    public function isAllowed($roleName, $resourceName, $access)
    {
        $processedRoles = [];
        $this->_matchedAccessKey = null;
        $result = $this->findInheritAccess($roleName, $resourceName, $access, $processedRoles);

        if (null === $result)
            return $this->_defaultAccess;

        if (false === $result)
            return false;

        return true;
    }

    /**
     * Returns internal key by which isAllowed was success
     *
     * @return mixed
     */
    public function getMatchedAccessKey()
    {
        return $this->_matchedAccessKey;
    }

    /**
     * Returns a rule for success isAllowed call
     *
     * @return mixed|null
     */
    public function getMatchedRules()
    {
        $rules = $this->_access[$this->_matchedAccessKey] ?? null;
        return is_bool($rules) ? null : $rules;
    }

    /**
     * Returns array of roles allowed to this $resource!$access,
     * every elements of this array:
     *  - key is role name
     *  - value is NULL - access without conditions, mixed_value if access with conditions (mixed_value = conditions)
     *
     * @param string $resource
     * @param string $access
     * @return array
     */
    public function whichRolesHaveAccess($resource, $access)
    {
        // backup previously found access key
        $matchedAccessKey = $this->_matchedAccessKey;

        $response = [];
        foreach ($this->getRoles() as $roleName) {
            if ($this->isAllowed($roleName, $resource, $access))
                $response[$roleName] = $this->getMatchedRules();
        }

        // restore previously found access key
        $this->_matchedAccessKey = $matchedAccessKey;

        return $response;
    }
}
