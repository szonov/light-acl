# LightAcl
Simplest ACL library, which main idea to store only acl rules.
Knowing of complete list of all roles, resources, actions is not a part of this library.

Every Acl rule can be
- true (allowed)
- false (denied)
- mixed data (allowed, this mixed data can be used later by calling $acl->getMatchedRules())

Instead of writing 'resource!action' => true acceptable short version - just 'resource!action'

Usage Example
-------------

```php
// acl.php file
return [
    'Guest' => [ null,
        'auth!login' => true,
        'public!*'
    ],
    'Authorized' => [ 'Guest',
        'auth!login' => false,
        'user!profile',
        'user!save_password',
    ],
    'Administrator' => [ null,
        '*!*'
    ],
    'Reader' => [ 'Authorized',
        '*!read' => [ 'hideDeleted' => true ]
    ],
];
```

```php
// index.php file
include "vendor/autoload.php";

use SZonov\LightAcl\Acl;

$acl = new Acl(include __DIR__ . '/acl.php');
// what is default when no appropriate rule (true - allow, false - deny)
$acl->setDefaultAction(false);

$test_data = [
    // RoleName, resourceName, action
    ['Reader', 'someresource', 'read'],
    ['Reader', 'user', 'profile'],
    ['Reader', 'auth', 'login'],
];

foreach ($test_data as $row)
{
    echo $acl->isAllowed($row[0], $row[1], $row[2]) ? 'TRUE' : 'FALSE', " ";
    var_export($acl->getMatchedRules());
    echo "\n";
}

// output:
//
// TRUE array (
//     'hideDeleted' => true,
// )
// TRUE NULL
// FALSE NULL

```
