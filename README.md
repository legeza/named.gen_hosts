named.gen_hosts
===============

Tool to generate **/etc/hosts** file from ISC BIND configuration.

Originally script was written to solve an annoying problem with one legacy application that disturbing our DNS servers fifty times a second from dozens of servers continuously.

Nowadays it uses to perform automated tests of inbound changes for:
 * Missing **A** record for an **CNAME**.
 * Missing files.
 * Inclusion loops.

Also usefull for debugging an inclussions assembling and **View** compilation. 

Currently supports IPv4 only.

```
usage: named.gen_hosts.py [-o OUTPUT] [--view VIEW] [--zone ZONE] [-e] [-t] [-v] [-a] config_file

Convert BIND configuration into /etc/hosts file.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        output to a file (default: STDOUT)

Conversion:
  config_file           configuration file name
  --view VIEW           view name from named.conf to work with
  --zone ZONE           FQDN of zone (convert single zone file)
  -e                    include external CNAMEs

Self Testing:
  -t                    perform all unit tests
  -v                    verbose testing output
  -a                    assemble file with resolved $INCLUDE's

Examples:
    ./named.gen_hosts -o hosts ./zones.master.public
    ./named.gen_hosts -o hosts --view public dns/named.conf
    ./named.gen_hosts -o hosts --zone gaijin.ru ./master/gaijin.ru
    ./named.gen_hosts -t -v ''
    ./named.gen_hosts -a ./master/gaijin.ru.public
    ./named.gen_hosts -a -v ./named.conf
```
