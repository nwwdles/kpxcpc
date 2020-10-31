# kpxcpc

A non-featureful [KeePassXC-proxy](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md) command line client.

Same as browser extension, it retrieves passwords from an unlocked DB. Unlike `secret-tool`, it doesn't require you to set KeePassXC to be your secret service ([there can only be one](https://github.com/keepassxreboot/keepassxc/issues/3945)).

## Installation

If you have Go set up, you can do

```sh
go get -u gitlab.com/nwwdles/kpxcpc/cmd/kpxcpc
```

Obviously, you may want to review the code first :^)

There's also a [PKGBUILD](meta/PKGBUILD) for Arch-based systems.

## Usage

```txt
Usage of kpxcpc:
  -associate
        associate and print association info to stdout in json format
  -fmt string
        format string for entry fields: name - %n, login - %l, pass - %p,
          uuid - %u, custom fields - %F:fieldname
           (default "%p")
  -identity string
        set identity file (default "~/.local/share/kpxcpc/identity.json")
  -json
        print json
  -socket string
        path to keepassxc-proxy socket
```

To delimit entries with null-character, use `\x00` instead of `\0`.

Custom entry fields need to have a name in the following format: `KPH: myfield` (with a space between prefix and field name) to be available through keepassxc-proxy. To refer to them in kpxcpc format string, use `%F:myfield` (without a space).

Example:

```sh
$ kpxcpc 'http://google.com'
pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9

$ kpxcpc -fmt 'pass: %p\n' 'http://google.com'
pass: pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9

$ kpxcpc -fmt 'pass: %p\nmyfield: %F:myfieldname\n' 'http://google.com'
pass: pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9
myfield: hello world

$ kpxcpc -json 'http://google.com'
[{"login":"elon","name":"google","password":"pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9","uuid":"d1e6cba53ad04e8fb23f2991c160ce5a","stringFields":[{"KPH: myfieldname":"hello world"}]}]
```

## Security

If you're really concerned about security, you can manage the storage of association info manually:

- use `-associate` to associate once and print identity json to stdout,
- use `-identity -` to read identity json from stdin.
