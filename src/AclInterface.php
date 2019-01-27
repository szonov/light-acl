<?php namespace SZonov\LightAcl;

interface AclInterface
{
    /**
     * Check whether a role is allowed to access an action from a resource
     *
     * @param string $roleName
     * @param string $resourceName
     * @param string $access
     * @return bool
     */
    public function isAllowed($roleName, $resourceName, $access);

    /**
     * Returns a rule for success isAllowed call
     *
     * @return mixed|null
     */
    public function getMatchedRules();

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
    public function whichRolesHaveAccess($resource, $access);
}
