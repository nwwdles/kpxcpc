# kpxcpc

A non-featureful [KeePassXC-proxy](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md) command line client.

## Usage

```txt
Usage of kpxcpc:
  -ffmt string
        format string for stringFields
          key - %k, value - %v
  -fmt string
        format string for main entry fields
          name - %n, login - %l, pass - %p, uuid - %u
         (default "%p")
  -identity string
        set identity file (default "~/.local/share/kpxcpc/identity.json")
  -json
        print json
  -socket string
        path to keepassxc-proxy socket (default "/run/user/1000/kpxc_server")
```

Example:

```sh
$ kpxcpc 'http://google.com'
pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9

$ kpxcpc -fmt 'pass: %p\n' 'http://google.com'
pass: pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9

$ kpxcpc -json 'http://google.com'
[{"login":"elon","name":"google","password":"pwAJWsXs2HcDvz5HM4mk3ub@7rdP7473n7y5i9","uuid":"d1e6cba53ad04e8fb23f2991c160ce5a","stringFields":[]}]
```
