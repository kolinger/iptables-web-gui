iptables-web-gui
================

Lightweight website based GUI for iptables

Features
--------
- simple
- zero configuration
- writted in plain PHP (zero dependencies)
- clean interface
- editing rules on fly, no storage needed
- supported filter and nat tables with all chains

Requirements
------------
- PHP 5.3 or newer
- ssh2 extension
- and ofcourse iptables on remote server (tested only with v1.4.14)

How to install
--------------
1. [download sources](https://github.com/kolinger/iptables-web-gui/releases)
2. edit config.php and set SSH configuration (key or password based)
3. secure by our www server (some guide bellow)
4. run

How to secure (with nginx)
----------------------------
1. disallow public access, for instance - allow only my personal IP
2. set HTTP authentication

Example:
```
location {
  allow 123.123.123.123;
  deny all;

  auth_basic "iptables";
  auth_basic_user_file /path/to/htpasswd;
}
```

TODO
----
- ipv6 support

