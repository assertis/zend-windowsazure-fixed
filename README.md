# zend-windowsazure-fixed
pseudo-fork of zensservice-windowsazure repository. It contain fixes for current version of azure cloud and additional functionality for Asserts goals. Until it reach >= 1.0 version,
keep in mind it still can contain outdated elements (took live from original zenservice-windowazure library).

# Installation guide:

Recommended way to install this lib is composer install. Add to composer.json:

```
"repositories": [
	{
      "type": "vcs",
      "url": "https://github.com/assertis/zend-windowsazure-fixed"
    }
]
```
and
```
"require": {
	"assertis/zend-windowsazure-fixed": "*"
}
```

#Usage examples

## Pop message from queue

```
$queue = new \ZendService\WindowsAzure\Storage\Queue(
    "sample-host.servicebus.windows.net",
    "SAS_user_name",
    "SAS_user_key"
);

$response = $queue->popMessage("queue/sample/name");
echo $response->getBody();
```


