#!/usr/bin/env python
'''
Description: Generate hosts configuration from ISC BIND (Named) zone files

Author: Vladimir Legeza <vladimir.legeza@gmail.com>
'''

import sys
import os
import re
import socket
import argparse
import textwrap


re_view = re.compile(
    r'^([\s]+)?view[\s]+([\'"\s]+)?(?P<view>[a-zA-Z0-9._-]+)([\'"\s]+)?.*')
re_zone_file = re.compile(
    r'(\s?)*file\s+[\'"]\s?(?P<file>[a-zA-Z0-9/._-]+)\s?[\'"]\s?;.*')
re_zone_name = re.compile(
    r'(\s?)*zone\s+[\'"]\s?(?P<zone>[a-zA-Z0-9/._-]+)\s?[\'"]\s?{')
re_include = re.compile(
    r'^([\s]+)?(\$INCLUDE|include)([\'"\s]+)?(?P<file>[a-zA-Z0-9/._-]+).*')
re_origin = re.compile(
    r'^([\s]+)?\$ORIGIN([\'"\s]+)?(?P<domain>[a-zA-Z0-9/._-]+).*')
re_a_record = re.compile(
    r'^(?P<domain>[a-zA-Z0-9@/.-]+)\s+'
    '((\d+)?\s+IN\s+)?A\s+(?P<ip>\d+.\d+.\d+.\d+).*')
re_cname_record = re.compile(
    r'^(?P<cname>[a-zA-Z0-9/.-]+)\s+'
    '((\d+)?\s+IN\s+)?CNAME\s+(?P<domain>[a-zA-Z0-9@/.-]+).*')
re_ext_cname_record = re.compile(r'.*[.]$')

def regexp_test():
    '''
    >>> re_view.match('view "public" {').group('view')
    'public'

    >>> re_zone_file.match(' file "master/somedomain.org.public";').group('file')
    'master/somedomain.org.public'
    >>> re_zone_name.match('zone "somedomain.org" {').group('zone')
    'somedomain.org'

    >>> re_include.match(
    ... '$INCLUDE "master/somedomain.org"; test string').group('file')
    'master/somedomain.org'
    >>> re_include.match(
    ... 'include "zones.master.private.offices";').group('file')
    'zones.master.private.offices'

    >>> re_origin.match(
    ... '$ORIGIN forum.somedomain.org.; test string').group('domain')
    'forum.somedomain.org.'

    >>> re_a_record.match("test A 127.0.0.1; test string").group('ip')
    '127.0.0.1'
    >>> re_a_record.match("test A 127.0.0.1; test string").group('domain')
    'test'
    >>> re_a_record.match(
    ... "test  600 IN A 127.0.0.1; test string").group('domain')
    'test'
    >>> re_a_record.match("test  IN A 127.0.0.1; test string").group('domain')
    'test'
    >>> re_cname_record.match("test CNAME test1; test string").group('cname')
    'test'
    >>> re_cname_record.match("test CNAME test1; test string").group('domain')
    'test1'
    >>> re_cname_record.match(
    ... "test 600 IN CNAME test1; test string").group('domain')
    'test1'
    >>> re_cname_record.match(
    ... "test  IN CNAME test1; test string").group('domain')
    'test1'
    >>> re_ext_cname_record.match("test1.somedomain.org.").string
    'test1.somedomain.org.'
    '''


def parse_zones_conf(configuration):
    ''' list -> dict
        Get all zone names and related files.
        File should contain banch of zone definitions only.
        Dict: {'Zone Name':'Zone file name'}
    >>> parse_zones_conf([\
    'zone "star-conflict.com" {',\
    '    type master;',\
    '    file "master/star-conflict.com";',\
    '    allow-transfer { localhost; };',\
    '};',\
    'zone "star-conflict.ru" {',\
    '    type master;',\
    '    file "master/star-conflict.ru";',\
    '    allow-transfer { localhost; };',\
    '};'])
    {'star-conflict.ru': 'master/star-conflict.ru', \
'star-conflict.com': 'master/star-conflict.com'}
    '''
    for conf_line in configuration:
        result = re_zone_name.match(conf_line)
        if result:
            zone_name = result.group('zone')
        result = re_zone_file.match(conf_line)
        if result:
            zone_file = result.group('file')
            zones[zone_name] = zone_file
    return zones


def parse_named_conf(configuration, required_view):
    ''' list -> dict
        Get all zone names and related files in specified view
        Dict: {'Zone Name':'Zone file name'}
    >>> parse_named_conf ([\
    'options {',\
    '    version "surely you must be joking";',\
    '    allow-transfer {',\
    '        127.0.0.1/32;',\
    '    };',\
    '};',\
    '',\
    'view "offices" {',\
    '    match-clients {',\
    '        127.0.0.1/32;',\
    '        offices;',\
    '    };',\
    '};',\
    '',\
    'view "public" {',\
    '    match-clients {',\
    '        any;',\
    '    };',\
    '    notify-source 188.127.242.210;',\
    '',\
    '    allow-transfer {',\
    '        127.0.0.1/32;',\
    '    };',\
    '',\
    '    allow-recursion {',\
    '        gaijin_networks;',\
    '        127.0.0.1/32;',\
    '    };',\
    '    additional-from-auth no;',\
    '    additional-from-cache no;',\
    '',\
    '    zone "." {',\
    '        type hint;',\
    '        file "named.root";',\
    '    };',\
    'zone "star-conflict.com" {',\
    '    type master;',\
    '    file "master/star-conflict.com";',\
    '    allow-transfer { localhost; };',\
    '};',\
    'zone "star-conflict.ru" {',\
    '    type master;',\
    '    file "master/star-conflict.ru";',\
    '    allow-transfer { localhost; };',\
    '};',\
    '};'],"public")
    {'star-conflict.ru': 'master/star-conflict.ru', \
'star-conflict.com': 'master/star-conflict.com'}
    '''
    zones = dict()
    br_count = 0
    in_zone = False
    in_view = False
    for line in configuration:
        if not in_view:
            result = re_view.match(line)
            if result:
                in_view = True
                view = result.group('view')
                br_count = line.count('{') - line.count('}')
        elif not in_zone:
            result = re_zone_name.match(line)
            if result:
                in_zone = True
                zone = result.group('zone')
                br_zone_count = br_count
                br_count = br_count + line.count('{') - line.count('}')
            else:
                br_count = br_count + line.count('{') - line.count('}')
                if br_count == 0:
                    view = ''
                    in_view = False
        elif in_zone:
            result = re_zone_file.match(line)
            if result:
                file_name = result.group('file')
                if view == required_view:
                    # print "VIEW:%s ZONE:%s FILE:%s" % (view, zone, file_name)
                    if zone != '.':  # Skip root servers
                        zones[zone] = file_name
            br_count = br_count + line.count('{') - line.count('}')
            if br_count == br_zone_count:
                zone = ''
                in_zone = False
    return zones


def assemble_config_file(file_name):
    ''' str -> list
    Find all INCLUDE satatemens and resove them.
    Return: Full configuration file as a list of configuration lines.
    Exit with error in case of inclusion loop.
    '''
    global incl_vector
    file_path = os.path.realpath(file_name)
    if file_path in incl_vector:
        err_msg = 'Inclusion loop detected in "%s" (While include "%s")\n' \
            % (os.path.basename(incl_vector[-1]), file_name)
        if args.perform_tests_verbose:
            err_msg += 'Inclusion vector:\n'
            for i in incl_vector:
                err_msg += os.path.basename(i) + " -> "
            err_msg += os.path.basename(file_name) + "\n"
        sys.stderr.write(err_msg)
        sys.exit(1)
    else:
        incl_vector.append(file_path)

    config = list()
    with open(file_name, 'r') as fd:
        for line in (i.rstrip('\n') for i in fd):
            result = re_include.match(line)
            if result:
                config += assemble_config_file(result.group('file'))
            else:
                config.append(line)
    del incl_vector[-1]
    return config


def parse_zone(original_zone, zone_config):
    r''' str,list -> null
    Merge all record to hosts formated list (-> stdout)

    >>> parse_zone("somedomain.org",
    ... ('test A 127.0.0.1','test2 CNAME test','test3 CNAME test'))
    127.0.0.1 test.somedomain.org test2.somedomain.org test3.somedomain.org

    >>> parse_zone("somedomain.org",
    ... ('test4 CNAME gaijinent.com.\n','test5 CNAME test4',
    ... 'test A 127.0.0.1','test2 CNAME test','test3 CNAME test'))
    127.0.0.1 test.somedomain.org test2.somedomain.org test3.somedomain.org

    >>> parse_zone("somedomain.org",
    ... ('$ORIGIN test.somedomain.org.','test A 127.0.0.1\n','test2 CNAME test',
    ... '$ORIGIN somedomain.org.','test1 A 127.0.0.2'))
    127.0.0.1 test.test.somedomain.org test2.test.somedomain.org
    127.0.0.2 test1.somedomain.org

    >>> args.INCLUDE_E_CNAME = True
    >>> parse_zone("test.ru",('b CNAME a','a A 127.0.0.2','c CNAME localhost.',
    ... 'd CNAME c','e CNAME b'))
    127.0.0.1 c.test.ru d.test.ru localhost
    127.0.0.2 a.test.ru b.test.ru b.test.ru

    >>> args.INCLUDE_E_CNAME = False
    >>> parse_zone("test.ru",('b CNAME a','a A 127.0.0.2','c CNAME localhost.',
    ... 'd CNAME c','e CNAME b'))
    127.0.0.2 a.test.ru b.test.ru b.test.ru
    '''

    merge_d = dict()
    a_d = dict()
    cname_d = dict()
    zone = original_zone
    zone_origin_suffix = str()  # To add to CNAME in $ORIGIN

    for line in zone_config:
        # ORIGIN
        result = re_origin.match(line)
        if result:
            zone_origin_suffix = re.sub('\.?'+original_zone+'\.', "",
                                        result.group('domain'))
            if zone_origin_suffix:
                zone_origin_suffix = ".%s" % zone_origin_suffix
            # Remove last dot from ORIGIN domain definition
            zone = re.sub('\.$', "", result.group('domain'))
            continue
        # A
        result = re_a_record.match(line)
        if result:
            domain = result.group('domain')
            ip = result.group('ip')
            # @ Simbol
            if domain == "@":
                merge_d[zone] = ip
                if ip not in a_d:
                    a_d[ip] = list()
                a_d[ip].append("%s" % (zone))
            else:
                merge_d[domain] = ip
                if ip not in a_d:
                    a_d[ip] = list()
                a_d[ip].append("%s.%s" % (domain, zone))
        # CNAME
        result = re_cname_record.match(line)
        if result:
            domain = result.group('domain')
            cname = "%s%s" % (result.group('cname'), zone_origin_suffix)
            # External CNAME
            if re_ext_cname_record.match(domain):
                ip = socket.gethostbyname(domain)
                merge_d[domain] = ip
                merge_d[cname] = ip
                if ip not in a_d:
                    a_d[ip] = list()
                a_d[ip].append("%s" % domain)
            # Regular CNAME
            if domain == "@":
                domain = zone

            cname_d[cname] = domain

    # Merge
    for cname in cname_d:
        ip = None
        while ip is None:
            if cname_d[cname] in merge_d:
                ip = merge_d[cname_d[cname]]
            else:
                cname = cname_d[cname]
        a_d[ip].append("%s.%s" % (cname, zone))

    # OUTPUT
    for ip in sorted(a_d):
        # External CNAME's
        is_e_cname = False
        for index, domain in enumerate(a_d[ip]):
            if re_ext_cname_record.match(domain):
                is_e_cname = True
                # Remove trailing dot from CNAME
                a_d[ip][index] = domain[:-1]
        if is_e_cname and not args.INCLUDE_E_CNAME:
            continue
        print ip,
        print " ".join(sorted(a_d[ip]))


if __name__ == "__main__":
    # Parse cmd arguments
    args_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Convert BIND configuration into /etc/hosts file.',
        epilog=textwrap.dedent('''
            Examples:
                ./named.gen_hosts -o hosts ./zones.master.public
                ./named.gen_hosts -o hosts --view public dns/named.conf
                ./named.gen_hosts -o hosts --zone somedomain.org ./master/somedomain.org
                ./named.gen_hosts -t -v ''
                ./named.gen_hosts -a ./master/somedomain.org.public
                ./named.gen_hosts -a -v ./named.conf

            '''))
    args_parser.add_argument('-o', '--output',
                             nargs=1,
                             type=argparse.FileType('w'),
                             default=[sys.stdout, ],
                             help='output to a file (default: STDOUT)')
    args_group1 = args_parser.add_argument_group('Conversion')
    args_group1.add_argument('config_file',
                             help='configuration file name')
    args_group1.add_argument('--view',
                             nargs=1,
                             help='view name from named.conf to work with')
    args_group1.add_argument('--zone',
                             nargs=1,
                             help='FQDN of zone (convert single zone file)')
    args_group1.add_argument('-e',
                             dest='INCLUDE_E_CNAME',
                             action='store_true',
                             help='include external CNAMEs')
    args_group2 = args_parser.add_argument_group('Self Testing')
    args_group2.add_argument('-t',
                             dest='perform_tests',
                             action='store_true',
                             help='perform all unit tests')
    args_group2.add_argument('-v',
                             dest='perform_tests_verbose',
                             action='store_true',
                             help='verbose testing output')
    args_group2.add_argument('-a',
                             dest='test_assemble',
                             action='store_true',
                             help="assemble file with resolved $INCLUDE's")
    args = args_parser.parse_args()

    # Redirect output
    sys.stdout = args.output[0]

    # Global initial variables
    zones = dict()
    incl_vector = list()

    # Self test
    if args.perform_tests:
        import doctest
        # doctest.testmod(raise_on_error=True)
        doctest.testmod()
        sys.exit()
    if args.test_assemble:
        for i in assemble_config_file(args.config_file):
            print i
        sys.exit()

    # Parse named.conf with view
    if args.view:
        work_dir = os.path.dirname(os.path.realpath(args.config_file))
        config_file = os.path.basename(os.path.realpath(args.config_file))
        if os.getcwd() != work_dir:
            os.chdir(work_dir)
        zones = parse_named_conf(assemble_config_file(config_file),
                                 args.view[0])
    # Parse single zone configuration file
    elif args.zone:
        zones[args.zone[0]] = args.config_file
    # Parse all zones
    else:
        zones = parse_zones_conf(assemble_config_file(args.config_file))

    # Output
    for zone in zones:
        parse_zone(zone, assemble_config_file(zones[zone]))
