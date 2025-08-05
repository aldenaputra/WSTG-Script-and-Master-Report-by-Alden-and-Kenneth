# DVWA Configuration & Deployment Testing Report

**Target URL**: http://localhost:8080

## OTG-CONFIG-001
**Description**: Network/Infrastructure Configuration

**Status**: ✅ Completed

**Results**:
```json
{
  "command": "nmap -sS -sV --top-ports 1000 localhost",
  "stdout": "Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-28 23:32 SE Asia Standard Time\nNmap scan report for localhost (127.0.0.1)\nHost is up (0.00066s latency).\nOther addresses for localhost (not scanned): ::1\nrDNS record for 127.0.0.1: frontend.test\nNot shown: 995 closed tcp ports (reset)\nPORT     STATE SERVICE         VERSION\n135/tcp  open  msrpc           Microsoft Windows RPC\n445/tcp  open  microsoft-ds?\n902/tcp  open  ssl/vmware-auth VMware Authentication Daemon 1.10 (Uses VNC, SOAP)\n912/tcp  open  vmware-auth     VMware Authentication Daemon 1.0 (Uses VNC, SOAP)\n8080/tcp open  http            Apache httpd 2.4.25 ((Debian))\nService Info: OS: Windows; CPE: cpe:/o:microsoft:windows\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 15.24 seconds",
  "stderr": "",
  "returncode": 0,
  "timeout": false
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-001 – Network/Infrastructure Configuration
======================================================================
$ nmap -sS -sV --top-ports 1000 localhost
Returned: 0
-- stdout --
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-28 23:32 SE Asia Standard Time
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00066s latency).
Other addresses for localhost (not scanned): ::1
rDNS record for 127.0.0.1: frontend.test
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
135/tcp  open  msrpc           Microsoft Windows RPC
445/tcp  open  microsoft-ds?
902/tcp  open  ssl/vmware-auth VMware Authentication Daemon 1.10 (Uses VNC, SOAP)
912/tcp  open  vmware-auth     VMware Authentication Daemon 1.0 (Uses VNC, SOAP)
8080/tcp open  http            Apache httpd 2.4.25 ((Debian))
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.24 seconds

```

## OTG-CONFIG-002
**Description**: Application Platform Configuration

**Status**: ✅ Completed

**Results**:
```json
{
  "php_-i": {
    "command": "docker exec dvwa php -i",
    "stdout": "phpinfo()\nPHP Version => 7.0.30-0+deb9u1\n\nSystem => Linux d8d87a9dda55 5.15.153.1-microsoft-standard-WSL2 #1 SMP Fri Mar 29 23:14:13 UTC 2024 x86_64\nBuild Date => Jun 14 2018 13:50:25\nServer API => Command Line Interface\nVirtual Directory Support => disabled\nConfiguration File (php.ini) Path => /etc/php/7.0/cli\nLoaded Configuration File => /etc/php/7.0/cli/php.ini\nScan this dir for additional .ini files => /etc/php/7.0/cli/conf.d\nAdditional .ini files parsed => /etc/php/7.0/cli/conf.d/10-mysqlnd.ini,\n/etc/php/7.0/cli/conf.d/10-opcache.ini,\n/etc/php/7.0/cli/conf.d/10-pdo.ini,\n/etc/php/7.0/cli/conf.d/15-xml.ini,\n/etc/php/7.0/cli/conf.d/20-calendar.ini,\n/etc/php/7.0/cli/conf.d/20-ctype.ini,\n/etc/php/7.0/cli/conf.d/20-dom.ini,\n/etc/php/7.0/cli/conf.d/20-exif.ini,\n/etc/php/7.0/cli/conf.d/20-fileinfo.ini,\n/etc/php/7.0/cli/conf.d/20-ftp.ini,\n/etc/php/7.0/cli/conf.d/20-gd.ini,\n/etc/php/7.0/cli/conf.d/20-gettext.ini,\n/etc/php/7.0/cli/conf.d/20-iconv.ini,\n/etc/php/7.0/cli/conf.d/20-json.ini,\n/etc/php/7.0/cli/conf.d/20-mysqli.ini,\n/etc/php/7.0/cli/conf.d/20-pdo_mysql.ini,\n/etc/php/7.0/cli/conf.d/20-pdo_pgsql.ini,\n/etc/php/7.0/cli/conf.d/20-pgsql.ini,\n/etc/php/7.0/cli/conf.d/20-phar.ini,\n/etc/php/7.0/cli/conf.d/20-posix.ini,\n/etc/php/7.0/cli/conf.d/20-readline.ini,\n/etc/php/7.0/cli/conf.d/20-shmop.ini,\n/etc/php/7.0/cli/conf.d/20-simplexml.ini,\n/etc/php/7.0/cli/conf.d/20-sockets.ini,\n/etc/php/7.0/cli/conf.d/20-sysvmsg.ini,\n/etc/php/7.0/cli/conf.d/20-sysvsem.ini,\n/etc/php/7.0/cli/conf.d/20-sysvshm.ini,\n/etc/php/7.0/cli/conf.d/20-tokenizer.ini,\n/etc/php/7.0/cli/conf.d/20-wddx.ini,\n/etc/php/7.0/cli/conf.d/20-xmlreader.ini,\n/etc/php/7.0/cli/conf.d/20-xmlwriter.ini,\n/etc/php/7.0/cli/conf.d/20-xsl.ini\n\nPHP API => 20151012\nPHP Extension => 20151012\nZend Extension => 320151012\nZend Extension Build => API320151012,NTS\nPHP Extension Build => API20151012,NTS\nDebug Build => no\nThread Safety => disabled\nZend Signal Handling => disabled\nZend Memory Manager => enabled\nZend Multibyte Support => disabled\nIPv6 Support => enabled\nDTrace Support => available, disabled\n\nRegistered PHP Streams => https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar\nRegistered Stream Socket Transports => tcp, udp, unix, udg, ssl, sslv2, tls, tlsv1.0, tlsv1.1, tlsv1.2\nRegistered Stream Filters => zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, convert.iconv.*\n\nThis program makes use of the Zend Scripting Language Engine:\nZend Engine v3.0.0, Copyright (c) 1998-2017 Zend Technologies\n    with Zend OPcache v7.0.30-0+deb9u1, Copyright (c) 1999-2017, by Zend Technologies\n\n\n _______________________________________________________________________\n\n\nConfiguration\n\ncalendar\n\nCalendar support => enabled\n\nCore\n\nPHP Version => 7.0.30-0+deb9u1\n\nDirective => Local Value => Master Value\nallow_url_fopen => On => On\nallow_url_include => Off => Off\narg_separator.input => & => &\narg_separator.output => & => &\nauto_append_file => no value => no value\nauto_globals_jit => On => On\nauto_prepend_file => no value => no value\nbrowscap => no value => no value\ndefault_charset => UTF-8 => UTF-8\ndefault_mimetype => text/html => text/html\ndisable_classes => no value => no value\ndisable_functions => no value => no value\ndisplay_errors => Off => Off\ndisplay_startup_errors => Off => Off\ndoc_root => no value => no value\ndocref_ext => no value => no value\ndocref_root => no value => no value\nenable_dl => Off => Off\nenable_post_data_reading => On => On\nerror_append_string => no value => no value\nerror_log => no value => no value\nerror_prepend_string => no value => no value\nerror_reporting => 22527 => 22527\nexit_on_timeout => Off => Off\nexpose_php => On => On\nextension_dir => /usr/lib/php/20151012 => /usr/lib/php/20151012\nfile_uploads => On => On\nhighlight.comment => <font style=\"color: #FF8000\">#FF8000</font> => <font style=\"color: #FF8000\">#FF8000</font>\nhighlight.default => <font style=\"color: #0000BB\">#0000BB</font> => <font style=\"color: #0000BB\">#0000BB</font>\nhighlight.html => <font style=\"color: #000000\">#000000</font> => <font style=\"color: #000000\">#000000</font>\nhighlight.keyword => <font style=\"color: #007700\">#007700</font> => <font style=\"color: #007700\">#007700</font>\nhighlight.string => <font style=\"color: #DD0000\">#DD0000</font> => <font style=\"color: #DD0000\">#DD0000</font>\nhtml_errors => Off => Off\nignore_repeated_errors => Off => Off\nignore_repeated_source => Off => Off\nignore_user_abort => Off => Off\nimplicit_flush => On => On\ninclude_path => .:/usr/share/php => .:/usr/share/php\ninput_encoding => no value => no value\ninternal_encoding => no value => no value\nlog_errors => On => On\nlog_errors_max_len => 1024 => 1024\nmail.add_x_header => On => On\nmail.force_extra_parameters => no value => no value\nmail.log => no value => no value\nmax_execution_time => 0 => 0\nmax_file_uploads => 20 => 20\nmax_input_nesting_level => 64 => 64\nmax_input_time => -1 => -1\nmax_input_vars => 1000 => 1000\nmemory_limit => -1 => -1\nopen_basedir => no value => no value\noutput_buffering => 0 => 0\noutput_encoding => no value => no value\noutput_handler => no value => no value\npost_max_size => 8M => 8M\nprecision => 14 => 14\nrealpath_cache_size => 4096K => 4096K\nrealpath_cache_ttl => 120 => 120\nregister_argc_argv => On => On\nreport_memleaks => On => On\nreport_zend_debug => Off => Off\nrequest_order => GP => GP\nsendmail_from => no value => no value\nsendmail_path => /usr/sbin/sendmail -t -i  => /usr/sbin/sendmail -t -i \nserialize_precision => 17 => 17\nshort_open_tag => Off => Off\nSMTP => localhost => localhost\nsmtp_port => 25 => 25\nsql.safe_mode => Off => Off\nsys_temp_dir => no value => no value\ntrack_errors => Off => Off\nunserialize_callback_func => no value => no value\nupload_max_filesize => 2M => 2M\nupload_tmp_dir => no value => no value\nuser_dir => no value => no value\nuser_ini.cache_ttl => 300 => 300\nuser_ini.filename => .user.ini => .user.ini\nvariables_order => GPCS => GPCS\nxmlrpc_error_number => 0 => 0\nxmlrpc_errors => Off => Off\nzend.assertions => -1 => -1\nzend.detect_unicode => On => On\nzend.enable_gc => On => On\nzend.multibyte => Off => Off\nzend.script_encoding => no value => no value\n\nctype\n\nctype functions => enabled\n\ndate\n\ndate/time support => enabled\ntimelib version => 2016.02\n\"Olson\" Timezone Database Version => 0.system\nTimezone Database => internal\nDefault timezone => UTC\n\nDirective => Local Value => Master Value\ndate.default_latitude => 31.7667 => 31.7667\ndate.default_longitude => 35.2333 => 35.2333\ndate.sunrise_zenith => 90.583333 => 90.583333\ndate.sunset_zenith => 90.583333 => 90.583333\ndate.timezone => no value => no value\n\ndom\n\nDOM/XML => enabled\nDOM/XML API Version => 20031129\nlibxml Version => 2.9.4\nHTML Support => enabled\nXPath Support => enabled\nXPointer Support => enabled\nSchema Support => enabled\nRelaxNG Support => enabled\n\nexif\n\nEXIF Support => enabled\nEXIF Version => 7.0.30-0+deb9u1\nSupported EXIF Version => 0220\nSupported filetypes => JPEG,TIFF\n\nDirective => Local Value => Master Value\nexif.decode_jis_intel => JIS => JIS\nexif.decode_jis_motorola => JIS => JIS\nexif.decode_unicode_intel => UCS-2LE => UCS-2LE\nexif.decode_unicode_motorola => UCS-2BE => UCS-2BE\nexif.encode_jis => no value => no value\nexif.encode_unicode => ISO-8859-15 => ISO-8859-15\n\nfileinfo\n\nfileinfo support => enabled\nversion => 1.0.5\nlibmagic => 522\n\nfilter\n\nInput Validation and Filtering => enabled\nRevision => $Id: 28fcca4bfda9c9907588a64d245b49cb398249d8 $\n\nDirective => Local Value => Master Value\nfilter.default => unsafe_raw => unsafe_raw\nfilter.default_flags => no value => no value\n\nftp\n\nFTP support => enabled\nFTPS support => enabled\n\ngd\n\nGD Support => enabled\nGD headers Version => 2.2.4\nGD library Version => 2.2.4\nFreeType Support => enabled\nFreeType Linkage => with freetype\nFreeType Version => 2.6.3\nGIF Read Support => enabled\nGIF Create Support => enabled\nJPEG Support => enabled\nlibJPEG Version => 6b\nPNG Support => enabled\nlibPNG Version => 1.6.28\nWBMP Support => enabled\nXPM Support => enabled\nlibXpm Version => 30411\nXBM Support => enabled\nWebP Support => enabled\n\nDirective => Local Value => Master Value\ngd.jpeg_ignore_warning => 0 => 0\n\ngettext\n\nGetText Support => enabled\n\nhash\n\nhash support => enabled\nHashing Engines => md2 md4 md5 sha1 sha224 sha256 sha384 sha512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost gost-crypto adler32 crc32 crc32b fnv132 fnv1a32 fnv164 fnv1a64 joaat haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5 \n\nMHASH support => Enabled\nMHASH API Version => Emulated Support\n\niconv\n\niconv support => enabled\niconv implementation => glibc\niconv library version => 2.24\n\nDirective => Local Value => Master Value\niconv.input_encoding => no value => no value\niconv.internal_encoding => no value => no value\niconv.output_encoding => no value => no value\n\njson\n\njson support => enabled\njson version => 1.4.0\n\nlibxml\n\nlibXML support => active\nlibXML Compiled Version => 2.9.4\nlibXML Loaded Version => 20904\nlibXML streams => enabled\n\nmysqli\n\nMysqlI Support => enabled\nClient API library version => mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $\nActive Persistent Links => 0\nInactive Persistent Links => 0\nActive Links => 0\n\nDirective => Local Value => Master Value\nmysqli.allow_local_infile => On => On\nmysqli.allow_persistent => On => On\nmysqli.default_host => no value => no value\nmysqli.default_port => 3306 => 3306\nmysqli.default_pw => no value => no value\nmysqli.default_socket => no value => no value\nmysqli.default_user => no value => no value\nmysqli.max_links => Unlimited => Unlimited\nmysqli.max_persistent => Unlimited => Unlimited\nmysqli.reconnect => Off => Off\nmysqli.rollback_on_cached_plink => Off => Off\n\nmysqlnd\n\nmysqlnd => enabled\nVersion => mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $\nCompression => supported\ncore SSL => supported\nextended SSL => supported\nCommand buffer size => 4096\nRead buffer size => 32768\nRead timeout => 31536000\nCollecting statistics => Yes\nCollecting memory statistics => No\nTracing => n/a\nLoaded plugins => mysqlnd,debug_trace,auth_plugin_mysql_native_password,auth_plugin_mysql_clear_password,auth_plugin_sha256_password\nAPI Extensions => mysqli,pdo_mysql\n\nmysqlnd statistics =>  \nbytes_sent => 0\nbytes_received => 0\npackets_sent => 0\npackets_received => 0\nprotocol_overhead_in => 0\nprotocol_overhead_out => 0\nbytes_received_ok_packet => 0\nbytes_received_eof_packet => 0\nbytes_received_rset_header_packet => 0\nbytes_received_rset_field_meta_packet => 0\nbytes_received_rset_row_packet => 0\nbytes_received_prepare_response_packet => 0\nbytes_received_change_user_packet => 0\npackets_sent_command => 0\npackets_received_ok => 0\npackets_received_eof => 0\npackets_received_rset_header => 0\npackets_received_rset_field_meta => 0\npackets_received_rset_row => 0\npackets_received_prepare_response => 0\npackets_received_change_user => 0\nresult_set_queries => 0\nnon_result_set_queries => 0\nno_index_used => 0\nbad_index_used => 0\nslow_queries => 0\nbuffered_sets => 0\nunbuffered_sets => 0\nps_buffered_sets => 0\nps_unbuffered_sets => 0\nflushed_normal_sets => 0\nflushed_ps_sets => 0\nps_prepared_never_executed => 0\nps_prepared_once_executed => 0\nrows_fetched_from_server_normal => 0\nrows_fetched_from_server_ps => 0\nrows_buffered_from_client_normal => 0\nrows_buffered_from_client_ps => 0\nrows_fetched_from_client_normal_buffered => 0\nrows_fetched_from_client_normal_unbuffered => 0\nrows_fetched_from_client_ps_buffered => 0\nrows_fetched_from_client_ps_unbuffered => 0\nrows_fetched_from_client_ps_cursor => 0\nrows_affected_normal => 0\nrows_affected_ps => 0\nrows_skipped_normal => 0\nrows_skipped_ps => 0\ncopy_on_write_saved => 0\ncopy_on_write_performed => 0\ncommand_buffer_too_small => 0\nconnect_success => 0\nconnect_failure => 0\nconnection_reused => 0\nreconnect => 0\npconnect_success => 0\nactive_connections => 0\nactive_persistent_connections => 0\nexplicit_close => 0\nimplicit_close => 0\ndisconnect_close => 0\nin_middle_of_command_close => 0\nexplicit_free_result => 0\nimplicit_free_result => 0\nexplicit_stmt_close => 0\nimplicit_stmt_close => 0\nmem_emalloc_count => 0\nmem_emalloc_amount => 0\nmem_ecalloc_count => 0\nmem_ecalloc_amount => 0\nmem_erealloc_count => 0\nmem_erealloc_amount => 0\nmem_efree_count => 0\nmem_efree_amount => 0\nmem_malloc_count => 0\nmem_malloc_amount => 0\nmem_calloc_count => 0\nmem_calloc_amount => 0\nmem_realloc_count => 0\nmem_realloc_amount => 0\nmem_free_count => 0\nmem_free_amount => 0\nmem_estrndup_count => 0\nmem_strndup_count => 0\nmem_estndup_count => 0\nmem_strdup_count => 0\nproto_text_fetched_null => 0\nproto_text_fetched_bit => 0\nproto_text_fetched_tinyint => 0\nproto_text_fetched_short => 0\nproto_text_fetched_int24 => 0\nproto_text_fetched_int => 0\nproto_text_fetched_bigint => 0\nproto_text_fetched_decimal => 0\nproto_text_fetched_float => 0\nproto_text_fetched_double => 0\nproto_text_fetched_date => 0\nproto_text_fetched_year => 0\nproto_text_fetched_time => 0\nproto_text_fetched_datetime => 0\nproto_text_fetched_timestamp => 0\nproto_text_fetched_string => 0\nproto_text_fetched_blob => 0\nproto_text_fetched_enum => 0\nproto_text_fetched_set => 0\nproto_text_fetched_geometry => 0\nproto_text_fetched_other => 0\nproto_binary_fetched_null => 0\nproto_binary_fetched_bit => 0\nproto_binary_fetched_tinyint => 0\nproto_binary_fetched_short => 0\nproto_binary_fetched_int24 => 0\nproto_binary_fetched_int => 0\nproto_binary_fetched_bigint => 0\nproto_binary_fetched_decimal => 0\nproto_binary_fetched_float => 0\nproto_binary_fetched_double => 0\nproto_binary_fetched_date => 0\nproto_binary_fetched_year => 0\nproto_binary_fetched_time => 0\nproto_binary_fetched_datetime => 0\nproto_binary_fetched_timestamp => 0\nproto_binary_fetched_string => 0\nproto_binary_fetched_json => 0\nproto_binary_fetched_blob => 0\nproto_binary_fetched_enum => 0\nproto_binary_fetched_set => 0\nproto_binary_fetched_geometry => 0\nproto_binary_fetched_other => 0\ninit_command_executed_count => 0\ninit_command_failed_count => 0\ncom_quit => 0\ncom_init_db => 0\ncom_query => 0\ncom_field_list => 0\ncom_create_db => 0\ncom_drop_db => 0\ncom_refresh => 0\ncom_shutdown => 0\ncom_statistics => 0\ncom_process_info => 0\ncom_connect => 0\ncom_process_kill => 0\ncom_debug => 0\ncom_ping => 0\ncom_time => 0\ncom_delayed_insert => 0\ncom_change_user => 0\ncom_binlog_dump => 0\ncom_table_dump => 0\ncom_connect_out => 0\ncom_register_slave => 0\ncom_stmt_prepare => 0\ncom_stmt_execute => 0\ncom_stmt_send_long_data => 0\ncom_stmt_close => 0\ncom_stmt_reset => 0\ncom_stmt_set_option => 0\ncom_stmt_fetch => 0\ncom_deamon => 0\nbytes_received_real_data_normal => 0\nbytes_received_real_data_ps => 0\n\nopenssl\n\nOpenSSL support => enabled\nOpenSSL Library Version => OpenSSL 1.1.0f  25 May 2017\nOpenSSL Header Version => OpenSSL 1.1.0f  25 May 2017\nOpenssl default config => /usr/lib/ssl/openssl.cnf\n\nDirective => Local Value => Master Value\nopenssl.cafile => no value => no value\nopenssl.capath => no value => no value\n\npcntl\n\npcntl support => enabled\n\npcre\n\nPCRE (Perl Compatible Regular Expressions) Support => enabled\nPCRE Library Version => 8.39 2016-06-14\nPCRE JIT Support => enabled\n\nDirective => Local Value => Master Value\npcre.backtrack_limit => 1000000 => 1000000\npcre.jit => 1 => 1\npcre.recursion_limit => 100000 => 100000\n\nPDO\n\nPDO support => enabled\nPDO drivers => mysql, pgsql\n\npdo_mysql\n\nPDO Driver for MySQL => enabled\nClient API version => mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $\n\nDirective => Local Value => Master Value\npdo_mysql.default_socket => /var/run/mysqld/mysqld.sock => /var/run/mysqld/mysqld.sock\n\npdo_pgsql\n\nPDO Driver for PostgreSQL => enabled\nPostgreSQL(libpq) Version => 9.6.9\nModule version => 7.0.30-0+deb9u1\nRevision =>  $Id: cffaf82eabbf77d05dd06589b673fe0e69bc87ab $ \n\npgsql\n\nPostgreSQL Support => enabled\nPostgreSQL(libpq) Version => 9.6.9\nPostgreSQL(libpq)  => PostgreSQL 9.6.9 on x86_64-pc-linux-gnu, compiled by gcc (Debian 6.3.0-18+deb9u1) 6.3.0 20170516, 64-bit\nMultibyte character support => enabled\nSSL support => enabled\nActive Persistent Links => 0\nActive Links => 0\n\nDirective => Local Value => Master Value\npgsql.allow_persistent => On => On\npgsql.auto_reset_persistent => Off => Off\npgsql.ignore_notice => Off => Off\npgsql.log_notice => Off => Off\npgsql.max_links => Unlimited => Unlimited\npgsql.max_persistent => Unlimited => Unlimited\n\nPhar\n\nPhar: PHP Archive support => enabled\nPhar EXT version => 2.0.2\nPhar API version => 1.1.1\nSVN revision => $Id: 9d91fd26ae99260111b934cc25174387d4bd7059 $\nPhar-based phar archives => enabled\nTar-based phar archives => enabled\nZIP-based phar archives => enabled\ngzip compression => enabled\nbzip2 compression => disabled (install pecl/bz2)\nNative OpenSSL support => enabled\n\n\nPhar based on pear/PHP_Archive, original concept by Davey Shafik.\nPhar fully realized by Gregory Beaver and Marcus Boerger.\nPortions of tar implementation Copyright (c) 2003-2009 Tim Kientzle.\nDirective => Local Value => Master Value\nphar.cache_list => no value => no value\nphar.readonly => On => On\nphar.require_hash => On => On\n\nposix\n\nRevision => $Id: b691ca925e7a085e6929579c4eba8fed0732e0ef $\n\nreadline\n\nReadline Support => enabled\nReadline library => EditLine wrapper\n\nDirective => Local Value => Master Value\ncli.pager => no value => no value\ncli.prompt => \\b \\>  => \\b \\> \n\nReflection\n\nReflection => enabled\nVersion => $Id: e5303663dcb329e17818853ff223e5ee01481f2c $\n\nsession\n\nSession Support => enabled\nRegistered save handlers => files user \nRegistered serializer handlers => php_serialize php php_binary wddx \n\nDirective => Local Value => Master Value\nsession.auto_start => Off => Off\nsession.cache_expire => 180 => 180\nsession.cache_limiter => nocache => nocache\nsession.cookie_domain => no value => no value\nsession.cookie_httponly => Off => Off\nsession.cookie_lifetime => 0 => 0\nsession.cookie_path => / => /\nsession.cookie_secure => Off => Off\nsession.entropy_file => /dev/urandom => /dev/urandom\nsession.entropy_length => 32 => 32\nsession.gc_divisor => 1000 => 1000\nsession.gc_maxlifetime => 1440 => 1440\nsession.gc_probability => 0 => 0\nsession.hash_bits_per_character => 5 => 5\nsession.hash_function => 0 => 0\nsession.lazy_write => On => On\nsession.name => PHPSESSID => PHPSESSID\nsession.referer_check => no value => no value\nsession.save_handler => files => files\nsession.save_path => /var/lib/php/sessions => /var/lib/php/sessions\nsession.serialize_handler => php => php\nsession.upload_progress.cleanup => On => On\nsession.upload_progress.enabled => On => On\nsession.upload_progress.freq => 1% => 1%\nsession.upload_progress.min_freq => 1 => 1\nsession.upload_progress.name => PHP_SESSION_UPLOAD_PROGRESS => PHP_SESSION_UPLOAD_PROGRESS\nsession.upload_progress.prefix => upload_progress_ => upload_progress_\nsession.use_cookies => On => On\nsession.use_only_cookies => On => On\nsession.use_strict_mode => Off => Off\nsession.use_trans_sid => 0 => 0\n\nshmop\n\nshmop support => enabled\n\nSimpleXML\n\nSimplexml support => enabled\nRevision => $Id: 0637e06af859ca1d0dea9c2f1530e51b98f1970e $\nSchema support => enabled\n\nsockets\n\nSockets Support => enabled\n\nSPL\n\nSPL support => enabled\nInterfaces => Countable, OuterIterator, RecursiveIterator, SeekableIterator, SplObserver, SplSubject\nClasses => AppendIterator, ArrayIterator, ArrayObject, BadFunctionCallException, BadMethodCallException, CachingIterator, CallbackFilterIterator, DirectoryIterator, DomainException, EmptyIterator, FilesystemIterator, FilterIterator, GlobIterator, InfiniteIterator, InvalidArgumentException, IteratorIterator, LengthException, LimitIterator, LogicException, MultipleIterator, NoRewindIterator, OutOfBoundsException, OutOfRangeException, OverflowException, ParentIterator, RangeException, RecursiveArrayIterator, RecursiveCachingIterator, RecursiveCallbackFilterIterator, RecursiveDirectoryIterator, RecursiveFilterIterator, RecursiveIteratorIterator, RecursiveRegexIterator, RecursiveTreeIterator, RegexIterator, RuntimeException, SplDoublyLinkedList, SplFileInfo, SplFileObject, SplFixedArray, SplHeap, SplMinHeap, SplMaxHeap, SplObjectStorage, SplPriorityQueue, SplQueue, SplStack, SplTempFileObject, UnderflowException, UnexpectedValueException\n\nstandard\n\nDynamic Library Support => enabled\nPath to sendmail => /usr/sbin/sendmail -t -i \n\nDirective => Local Value => Master Value\nassert.active => 1 => 1\nassert.bail => 0 => 0\nassert.callback => no value => no value\nassert.exception => 0 => 0\nassert.quiet_eval => 0 => 0\nassert.warning => 1 => 1\nauto_detect_line_endings => 0 => 0\ndefault_socket_timeout => 60 => 60\nfrom => no value => no value\nurl_rewriter.tags => a=href,area=href,frame=src,input=src,form=fakeentry => a=href,area=href,frame=src,input=src,form=fakeentry\nuser_agent => no value => no value\n\nsysvmsg\n\nsysvmsg support => enabled\nRevision => $Id: dfb999763f95bfe9609fae60b4e07a492888ec7c $\n\nsysvsem\n\nVersion => 7.0.30-0+deb9u1\n\nsysvshm\n\nVersion => 7.0.30-0+deb9u1\n\ntokenizer\n\nTokenizer Support => enabled\n\nwddx\n\nWDDX Support => enabled\nWDDX Session Serializer => enabled\n\nxml\n\nXML Support => active\nXML Namespace Support => active\nlibxml2 Version => 2.9.4\n\nxmlreader\n\nXMLReader => enabled\n\nxmlwriter\n\nXMLWriter => enabled\n\nxsl\n\nXSL => enabled\nlibxslt Version => 1.1.29\nlibxslt compiled against libxml Version => 2.9.4\nEXSLT => enabled\nlibexslt Version => 1.1.29\n\nZend OPcache\n\nOpcode Caching => Disabled\nOptimization => Disabled\nSHM Cache => Enabled\nFile Cache => Disabled\nStartup Failed => Opcode Caching is disabled for CLI\n\nDirective => Local Value => Master Value\nopcache.blacklist_filename => no value => no value\nopcache.consistency_checks => 0 => 0\nopcache.dups_fix => Off => Off\nopcache.enable => On => On\nopcache.enable_cli => Off => Off\nopcache.enable_file_override => Off => Off\nopcache.error_log => no value => no value\nopcache.fast_shutdown => 0 => 0\nopcache.file_cache => no value => no value\nopcache.file_cache_consistency_checks => 1 => 1\nopcache.file_cache_only => 0 => 0\nopcache.file_update_protection => 2 => 2\nopcache.force_restart_timeout => 180 => 180\nopcache.huge_code_pages => Off => Off\nopcache.inherited_hack => On => On\nopcache.interned_strings_buffer => 4 => 4\nopcache.lockfile_path => /tmp => /tmp\nopcache.log_verbosity_level => 1 => 1\nopcache.max_accelerated_files => 2000 => 2000\nopcache.max_file_size => 0 => 0\nopcache.max_wasted_percentage => 5 => 5\nopcache.memory_consumption => 64 => 64\nopcache.optimization_level => 0x7FFFBFFF => 0x7FFFBFFF\nopcache.preferred_memory_model => no value => no value\nopcache.protect_memory => 0 => 0\nopcache.restrict_api => no value => no value\nopcache.revalidate_freq => 2 => 2\nopcache.revalidate_path => Off => Off\nopcache.save_comments => 1 => 1\nopcache.use_cwd => On => On\nopcache.validate_permission => Off => Off\nopcache.validate_root => Off => Off\nopcache.validate_timestamps => On => On\n\nzlib\n\nZLib Support => enabled\nStream Wrapper => compress.zlib://\nStream Filter => zlib.inflate, zlib.deflate\nCompiled Version => 1.2.8\nLinked Version => 1.2.8\n\nDirective => Local Value => Master Value\nzlib.output_compression => Off => Off\nzlib.output_compression_level => -1 => -1\nzlib.output_handler => no value => no value\n\nAdditional Modules\n\nModule Name\n\nEnvironment\n\nVariable => Value\nPATH => /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOSTNAME => d8d87a9dda55\nHOME => /root\n\nPHP Variables\n\nVariable => Value\n$_SERVER['PATH'] => /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n$_SERVER['HOSTNAME'] => d8d87a9dda55\n$_SERVER['HOME'] => /root\n$_SERVER['PHP_SELF'] => \n$_SERVER['SCRIPT_NAME'] => \n$_SERVER['SCRIPT_FILENAME'] => \n$_SERVER['PATH_TRANSLATED'] => \n$_SERVER['DOCUMENT_ROOT'] => \n$_SERVER['REQUEST_TIME_FLOAT'] => 1753720355.5192\n$_SERVER['REQUEST_TIME'] => 1753720355\n$_SERVER['argv'] => Array\n(\n)\n\n$_SERVER['argc'] => 0\n\nPHP License\nThis program is free software; you can redistribute it and/or modify\nit under the terms of the PHP License as published by the PHP Group\nand included in the distribution in the file:  LICENSE\n\nThis program is distributed in the hope that it will be useful,\nbut WITHOUT ANY WARRANTY; without even the implied warranty of\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\nIf you did not receive a copy of the PHP license, or have any\nquestions about PHP licensing, please contact license@php.net.",
    "stderr": "",
    "returncode": 0,
    "timeout": false
  },
  "apache2ctl_-S": {
    "command": "docker exec dvwa apache2ctl -S",
    "stdout": "VirtualHost configuration:\n*:80                   172.17.0.2 (/etc/apache2/sites-enabled/000-default.conf:1)\nServerRoot: \"/etc/apache2\"\nMain DocumentRoot: \"/var/www/html\"\nMain ErrorLog: \"/var/log/apache2/error.log\"\nMutex watchdog-callback: using_defaults\nMutex default: dir=\"/var/run/apache2/\" mechanism=default \nMutex mpm-accept: using_defaults\nPidFile: \"/var/run/apache2/apache2.pid\"\nDefine: DUMP_VHOSTS\nDefine: DUMP_RUN_CFG\nUser: name=\"www-data\" id=33\nGroup: name=\"www-data\" id=33",
    "stderr": "AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2. Set the 'ServerName' directive globally to suppress this message",
    "returncode": 0,
    "timeout": false
  }
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-002 – Application Platform Configuration
======================================================================
$ docker exec dvwa php -i
Returned: 0
-- stdout --
phpinfo()
PHP Version => 7.0.30-0+deb9u1

System => Linux d8d87a9dda55 5.15.153.1-microsoft-standard-WSL2 #1 SMP Fri Mar 29 23:14:13 UTC 2024 x86_64
Build Date => Jun 14 2018 13:50:25
Server API => Command Line Interface
Virtual Directory Support => disabled
Configuration File (php.ini) Path => /etc/php/7.0/cli
Loaded Configuration File => /etc/php/7.0/cli/php.ini
Scan this dir for additional .ini files => /etc/php/7.0/cli/conf.d
Additional .ini files parsed => /etc/php/7.0/cli/conf.d/10-mysqlnd.ini,
/etc/php/7.0/cli/conf.d/10-opcache.ini,
/etc/php/7.0/cli/conf.d/10-pdo.ini,
/etc/php/7.0/cli/conf.d/15-xml.ini,
/etc/php/7.0/cli/conf.d/20-calendar.ini,
/etc/php/7.0/cli/conf.d/20-ctype.ini,
/etc/php/7.0/cli/conf.d/20-dom.ini,
/etc/php/7.0/cli/conf.d/20-exif.ini,
/etc/php/7.0/cli/conf.d/20-fileinfo.ini,
/etc/php/7.0/cli/conf.d/20-ftp.ini,
/etc/php/7.0/cli/conf.d/20-gd.ini,
/etc/php/7.0/cli/conf.d/20-gettext.ini,
/etc/php/7.0/cli/conf.d/20-iconv.ini,
/etc/php/7.0/cli/conf.d/20-json.ini,
/etc/php/7.0/cli/conf.d/20-mysqli.ini,
/etc/php/7.0/cli/conf.d/20-pdo_mysql.ini,
/etc/php/7.0/cli/conf.d/20-pdo_pgsql.ini,
/etc/php/7.0/cli/conf.d/20-pgsql.ini,
/etc/php/7.0/cli/conf.d/20-phar.ini,
/etc/php/7.0/cli/conf.d/20-posix.ini,
/etc/php/7.0/cli/conf.d/20-readline.ini,
/etc/php/7.0/cli/conf.d/20-shmop.ini,
/etc/php/7.0/cli/conf.d/20-simplexml.ini,
/etc/php/7.0/cli/conf.d/20-sockets.ini,
/etc/php/7.0/cli/conf.d/20-sysvmsg.ini,
/etc/php/7.0/cli/conf.d/20-sysvsem.ini,
/etc/php/7.0/cli/conf.d/20-sysvshm.ini,
/etc/php/7.0/cli/conf.d/20-tokenizer.ini,
/etc/php/7.0/cli/conf.d/20-wddx.ini,
/etc/php/7.0/cli/conf.d/20-xmlreader.ini,
/etc/php/7.0/cli/conf.d/20-xmlwriter.ini,
/etc/php/7.0/cli/conf.d/20-xsl.ini

PHP API => 20151012
PHP Extension => 20151012
Zend Extension => 320151012
Zend Extension Build => API320151012,NTS
PHP Extension Build => API20151012,NTS
Debug Build => no
Thread Safety => disabled
Zend Signal Handling => disabled
Zend Memory Manager => enabled
Zend Multibyte Support => disabled
IPv6 Support => enabled
DTrace Support => available, disabled

Registered PHP Streams => https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar
Registered Stream Socket Transports => tcp, udp, unix, udg, ssl, sslv2, tls, tlsv1.0, tlsv1.1, tlsv1.2
Registered Stream Filters => zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, convert.iconv.*

This program makes use of the Zend Scripting Language Engine:
Zend Engine v3.0.0, Copyright (c) 1998-2017 Zend Technologies
    with Zend OPcache v7.0.30-0+deb9u1, Copyright (c) 1999-2017, by Zend Technologies


 _______________________________________________________________________


Configuration

calendar

Calendar support => enabled

Core

PHP Version => 7.0.30-0+deb9u1

Directive => Local Value => Master Value
allow_url_fopen => On => On
allow_url_include => Off => Off
arg_separator.input => & => &
arg_separator.output => & => &
auto_append_file => no value => no value
auto_globals_jit => On => On
auto_prepend_file => no value => no value
browscap => no value => no value
default_charset => UTF-8 => UTF-8
default_mimetype => text/html => text/html
disable_classes => no value => no value
disable_functions => no value => no value
display_errors => Off => Off
display_startup_errors => Off => Off
doc_root => no value => no value
docref_ext => no value => no value
docref_root => no value => no value
enable_dl => Off => Off
enable_post_data_reading => On => On
error_append_string => no value => no value
error_log => no value => no value
error_prepend_string => no value => no value
error_reporting => 22527 => 22527
exit_on_timeout => Off => Off
expose_php => On => On
extension_dir => /usr/lib/php/20151012 => /usr/lib/php/20151012
file_uploads => On => On
highlight.comment => <font style="color: #FF8000">#FF8000</font> => <font style="color: #FF8000">#FF8000</font>
highlight.default => <font style="color: #0000BB">#0000BB</font> => <font style="color: #0000BB">#0000BB</font>
highlight.html => <font style="color: #000000">#000000</font> => <font style="color: #000000">#000000</font>
highlight.keyword => <font style="color: #007700">#007700</font> => <font style="color: #007700">#007700</font>
highlight.string => <font style="color: #DD0000">#DD0000</font> => <font style="color: #DD0000">#DD0000</font>
html_errors => Off => Off
ignore_repeated_errors => Off => Off
ignore_repeated_source => Off => Off
ignore_user_abort => Off => Off
implicit_flush => On => On
include_path => .:/usr/share/php => .:/usr/share/php
input_encoding => no value => no value
internal_encoding => no value => no value
log_errors => On => On
log_errors_max_len => 1024 => 1024
mail.add_x_header => On => On
mail.force_extra_parameters => no value => no value
mail.log => no value => no value
max_execution_time => 0 => 0
max_file_uploads => 20 => 20
max_input_nesting_level => 64 => 64
max_input_time => -1 => -1
max_input_vars => 1000 => 1000
memory_limit => -1 => -1
open_basedir => no value => no value
output_buffering => 0 => 0
output_encoding => no value => no value
output_handler => no value => no value
post_max_size => 8M => 8M
precision => 14 => 14
realpath_cache_size => 4096K => 4096K
realpath_cache_ttl => 120 => 120
register_argc_argv => On => On
report_memleaks => On => On
report_zend_debug => Off => Off
request_order => GP => GP
sendmail_from => no value => no value
sendmail_path => /usr/sbin/sendmail -t -i  => /usr/sbin/sendmail -t -i 
serialize_precision => 17 => 17
short_open_tag => Off => Off
SMTP => localhost => localhost
smtp_port => 25 => 25
sql.safe_mode => Off => Off
sys_temp_dir => no value => no value
track_errors => Off => Off
unserialize_callback_func => no value => no value
upload_max_filesize => 2M => 2M
upload_tmp_dir => no value => no value
user_dir => no value => no value
user_ini.cache_ttl => 300 => 300
user_ini.filename => .user.ini => .user.ini
variables_order => GPCS => GPCS
xmlrpc_error_number => 0 => 0
xmlrpc_errors => Off => Off
zend.assertions => -1 => -1
zend.detect_unicode => On => On
zend.enable_gc => On => On
zend.multibyte => Off => Off
zend.script_encoding => no value => no value

ctype

ctype functions => enabled

date

date/time support => enabled
timelib version => 2016.02
"Olson" Timezone Database Version => 0.system
Timezone Database => internal
Default timezone => UTC

Directive => Local Value => Master Value
date.default_latitude => 31.7667 => 31.7667
date.default_longitude => 35.2333 => 35.2333
date.sunrise_zenith => 90.583333 => 90.583333
date.sunset_zenith => 90.583333 => 90.583333
date.timezone => no value => no value

dom

DOM/XML => enabled
DOM/XML API Version => 20031129
libxml Version => 2.9.4
HTML Support => enabled
XPath Support => enabled
XPointer Support => enabled
Schema Support => enabled
RelaxNG Support => enabled

exif

EXIF Support => enabled
EXIF Version => 7.0.30-0+deb9u1
Supported EXIF Version => 0220
Supported filetypes => JPEG,TIFF

Directive => Local Value => Master Value
exif.decode_jis_intel => JIS => JIS
exif.decode_jis_motorola => JIS => JIS
exif.decode_unicode_intel => UCS-2LE => UCS-2LE
exif.decode_unicode_motorola => UCS-2BE => UCS-2BE
exif.encode_jis => no value => no value
exif.encode_unicode => ISO-8859-15 => ISO-8859-15

fileinfo

fileinfo support => enabled
version => 1.0.5
libmagic => 522

filter

Input Validation and Filtering => enabled
Revision => $Id: 28fcca4bfda9c9907588a64d245b49cb398249d8 $

Directive => Local Value => Master Value
filter.default => unsafe_raw => unsafe_raw
filter.default_flags => no value => no value

ftp

FTP support => enabled
FTPS support => enabled

gd

GD Support => enabled
GD headers Version => 2.2.4
GD library Version => 2.2.4
FreeType Support => enabled
FreeType Linkage => with freetype
FreeType Version => 2.6.3
GIF Read Support => enabled
GIF Create Support => enabled
JPEG Support => enabled
libJPEG Version => 6b
PNG Support => enabled
libPNG Version => 1.6.28
WBMP Support => enabled
XPM Support => enabled
libXpm Version => 30411
XBM Support => enabled
WebP Support => enabled

Directive => Local Value => Master Value
gd.jpeg_ignore_warning => 0 => 0

gettext

GetText Support => enabled

hash

hash support => enabled
Hashing Engines => md2 md4 md5 sha1 sha224 sha256 sha384 sha512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost gost-crypto adler32 crc32 crc32b fnv132 fnv1a32 fnv164 fnv1a64 joaat haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5 

MHASH support => Enabled
MHASH API Version => Emulated Support

iconv

iconv support => enabled
iconv implementation => glibc
iconv library version => 2.24

Directive => Local Value => Master Value
iconv.input_encoding => no value => no value
iconv.internal_encoding => no value => no value
iconv.output_encoding => no value => no value

json

json support => enabled
json version => 1.4.0

libxml

libXML support => active
libXML Compiled Version => 2.9.4
libXML Loaded Version => 20904
libXML streams => enabled

mysqli

MysqlI Support => enabled
Client API library version => mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $
Active Persistent Links => 0
Inactive Persistent Links => 0
Active Links => 0

Directive => Local Value => Master Value
mysqli.allow_local_infile => On => On
mysqli.allow_persistent => On => On
mysqli.default_host => no value => no value
mysqli.default_port => 3306 => 3306
mysqli.default_pw => no value => no value
mysqli.default_socket => no value => no value
mysqli.default_user => no value => no value
mysqli.max_links => Unlimited => Unlimited
mysqli.max_persistent => Unlimited => Unlimited
mysqli.reconnect => Off => Off
mysqli.rollback_on_cached_plink => Off => Off

mysqlnd

mysqlnd => enabled
Version => mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $
Compression => supported
core SSL => supported
extended SSL => supported
Command buffer size => 4096
Read buffer size => 32768
Read timeout => 31536000
Collecting statistics => Yes
Collecting memory statistics => No
Tracing => n/a
Loaded plugins => mysqlnd,debug_trace,auth_plugin_mysql_native_password,auth_plugin_mysql_clear_password,auth_plugin_sha256_password
API Extensions => mysqli,pdo_mysql

mysqlnd statistics =>  
bytes_sent => 0
bytes_received => 0
packets_sent => 0
packets_received => 0
protocol_overhead_in => 0
protocol_overhead_out => 0
bytes_received_ok_packet => 0
bytes_received_eof_packet => 0
bytes_received_rset_header_packet => 0
bytes_received_rset_field_meta_packet => 0
bytes_received_rset_row_packet => 0
bytes_received_prepare_response_packet => 0
bytes_received_change_user_packet => 0
packets_sent_command => 0
packets_received_ok => 0
packets_received_eof => 0
packets_received_rset_header => 0
packets_received_rset_field_meta => 0
packets_received_rset_row => 0
packets_received_prepare_response => 0
packets_received_change_user => 0
result_set_queries => 0
non_result_set_queries => 0
no_index_used => 0
bad_index_used => 0
slow_queries => 0
buffered_sets => 0
unbuffered_sets => 0
ps_buffered_sets => 0
ps_unbuffered_sets => 0
flushed_normal_sets => 0
flushed_ps_sets => 0
ps_prepared_never_executed => 0
ps_prepared_once_executed => 0
rows_fetched_from_server_normal => 0
rows_fetched_from_server_ps => 0
rows_buffered_from_client_normal => 0
rows_buffered_from_client_ps => 0
rows_fetched_from_client_normal_buffered => 0
rows_fetched_from_client_normal_unbuffered => 0
rows_fetched_from_client_ps_buffered => 0
rows_fetched_from_client_ps_unbuffered => 0
rows_fetched_from_client_ps_cursor => 0
rows_affected_normal => 0
rows_affected_ps => 0
rows_skipped_normal => 0
rows_skipped_ps => 0
copy_on_write_saved => 0
copy_on_write_performed => 0
command_buffer_too_small => 0
connect_success => 0
connect_failure => 0
connection_reused => 0
reconnect => 0
pconnect_success => 0
active_connections => 0
active_persistent_connections => 0
explicit_close => 0
implicit_close => 0
disconnect_close => 0
in_middle_of_command_close => 0
explicit_free_result => 0
implicit_free_result => 0
explicit_stmt_close => 0
implicit_stmt_close => 0
mem_emalloc_count => 0
mem_emalloc_amount => 0
mem_ecalloc_count => 0
mem_ecalloc_amount => 0
mem_erealloc_count => 0
mem_erealloc_amount => 0
mem_efree_count => 0
mem_efree_amount => 0
mem_malloc_count => 0
mem_malloc_amount => 0
mem_calloc_count => 0
mem_calloc_amount => 0
mem_realloc_count => 0
mem_realloc_amount => 0
mem_free_count => 0
mem_free_amount => 0
mem_estrndup_count => 0
mem_strndup_count => 0
mem_estndup_count => 0
mem_strdup_count => 0
proto_text_fetched_null => 0
proto_text_fetched_bit => 0
proto_text_fetched_tinyint => 0
proto_text_fetched_short => 0
proto_text_fetched_int24 => 0
proto_text_fetched_int => 0
proto_text_fetched_bigint => 0
proto_text_fetched_decimal => 0
proto_text_fetched_float => 0
proto_text_fetched_double => 0
proto_text_fetched_date => 0
proto_text_fetched_year => 0
proto_text_fetched_time => 0
proto_text_fetched_datetime => 0
proto_text_fetched_timestamp => 0
proto_text_fetched_string => 0
proto_text_fetched_blob => 0
proto_text_fetched_enum => 0
proto_text_fetched_set => 0
proto_text_fetched_geometry => 0
proto_text_fetched_other => 0
proto_binary_fetched_null => 0
proto_binary_fetched_bit => 0
proto_binary_fetched_tinyint => 0
proto_binary_fetched_short => 0
proto_binary_fetched_int24 => 0
proto_binary_fetched_int => 0
proto_binary_fetched_bigint => 0
proto_binary_fetched_decimal => 0
proto_binary_fetched_float => 0
proto_binary_fetched_double => 0
proto_binary_fetched_date => 0
proto_binary_fetched_year => 0
proto_binary_fetched_time => 0
proto_binary_fetched_datetime => 0
proto_binary_fetched_timestamp => 0
proto_binary_fetched_string => 0
proto_binary_fetched_json => 0
proto_binary_fetched_blob => 0
proto_binary_fetched_enum => 0
proto_binary_fetched_set => 0
proto_binary_fetched_geometry => 0
proto_binary_fetched_other => 0
init_command_executed_count => 0
init_command_failed_count => 0
com_quit => 0
com_init_db => 0
com_query => 0
com_field_list => 0
com_create_db => 0
com_drop_db => 0
com_refresh => 0
com_shutdown => 0
com_statistics => 0
com_process_info => 0
com_connect => 0
com_process_kill => 0
com_debug => 0
com_ping => 0
com_time => 0
com_delayed_insert => 0
com_change_user => 0
com_binlog_dump => 0
com_table_dump => 0
com_connect_out => 0
com_register_slave => 0
com_stmt_prepare => 0
com_stmt_execute => 0
com_stmt_send_long_data => 0
com_stmt_close => 0
com_stmt_reset => 0
com_stmt_set_option => 0
com_stmt_fetch => 0
com_deamon => 0
bytes_received_real_data_normal => 0
bytes_received_real_data_ps => 0

openssl

OpenSSL support => enabled
OpenSSL Library Version => OpenSSL 1.1.0f  25 May 2017
OpenSSL Header Version => OpenSSL 1.1.0f  25 May 2017
Openssl default config => /usr/lib/ssl/openssl.cnf

Directive => Local Value => Master Value
openssl.cafile => no value => no value
openssl.capath => no value => no value

pcntl

pcntl support => enabled

pcre

PCRE (Perl Compatible Regular Expressions) Support => enabled
PCRE Library Version => 8.39 2016-06-14
PCRE JIT Support => enabled

Directive => Local Value => Master Value
pcre.backtrack_limit => 1000000 => 1000000
pcre.jit => 1 => 1
pcre.recursion_limit => 100000 => 100000

PDO

PDO support => enabled
PDO drivers => mysql, pgsql

pdo_mysql

PDO Driver for MySQL => enabled
Client API version => mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $

Directive => Local Value => Master Value
pdo_mysql.default_socket => /var/run/mysqld/mysqld.sock => /var/run/mysqld/mysqld.sock

pdo_pgsql

PDO Driver for PostgreSQL => enabled
PostgreSQL(libpq) Version => 9.6.9
Module version => 7.0.30-0+deb9u1
Revision =>  $Id: cffaf82eabbf77d05dd06589b673fe0e69bc87ab $ 

pgsql

PostgreSQL Support => enabled
PostgreSQL(libpq) Version => 9.6.9
PostgreSQL(libpq)  => PostgreSQL 9.6.9 on x86_64-pc-linux-gnu, compiled by gcc (Debian 6.3.0-18+deb9u1) 6.3.0 20170516, 64-bit
Multibyte character support => enabled
SSL support => enabled
Active Persistent Links => 0
Active Links => 0

Directive => Local Value => Master Value
pgsql.allow_persistent => On => On
pgsql.auto_reset_persistent => Off => Off
pgsql.ignore_notice => Off => Off
pgsql.log_notice => Off => Off
pgsql.max_links => Unlimited => Unlimited
pgsql.max_persistent => Unlimited => Unlimited

Phar

Phar: PHP Archive support => enabled
Phar EXT version => 2.0.2
Phar API version => 1.1.1
SVN revision => $Id: 9d91fd26ae99260111b934cc25174387d4bd7059 $
Phar-based phar archives => enabled
Tar-based phar archives => enabled
ZIP-based phar archives => enabled
gzip compression => enabled
bzip2 compression => disabled (install pecl/bz2)
Native OpenSSL support => enabled


Phar based on pear/PHP_Archive, original concept by Davey Shafik.
Phar fully realized by Gregory Beaver and Marcus Boerger.
Portions of tar implementation Copyright (c) 2003-2009 Tim Kientzle.
Directive => Local Value => Master Value
phar.cache_list => no value => no value
phar.readonly => On => On
phar.require_hash => On => On

posix

Revision => $Id: b691ca925e7a085e6929579c4eba8fed0732e0ef $

readline

Readline Support => enabled
Readline library => EditLine wrapper

Directive => Local Value => Master Value
cli.pager => no value => no value
cli.prompt => \b \>  => \b \> 

Reflection

Reflection => enabled
Version => $Id: e5303663dcb329e17818853ff223e5ee01481f2c $

session

Session Support => enabled
Registered save handlers => files user 
Registered serializer handlers => php_serialize php php_binary wddx 

Directive => Local Value => Master Value
session.auto_start => Off => Off
session.cache_expire => 180 => 180
session.cache_limiter => nocache => nocache
session.cookie_domain => no value => no value
session.cookie_httponly => Off => Off
session.cookie_lifetime => 0 => 0
session.cookie_path => / => /
session.cookie_secure => Off => Off
session.entropy_file => /dev/urandom => /dev/urandom
session.entropy_length => 32 => 32
session.gc_divisor => 1000 => 1000
session.gc_maxlifetime => 1440 => 1440
session.gc_probability => 0 => 0
session.hash_bits_per_character => 5 => 5
session.hash_function => 0 => 0
session.lazy_write => On => On
session.name => PHPSESSID => PHPSESSID
session.referer_check => no value => no value
session.save_handler => files => files
session.save_path => /var/lib/php/sessions => /var/lib/php/sessions
session.serialize_handler => php => php
session.upload_progress.cleanup => On => On
session.upload_progress.enabled => On => On
session.upload_progress.freq => 1% => 1%
session.upload_progress.min_freq => 1 => 1
session.upload_progress.name => PHP_SESSION_UPLOAD_PROGRESS => PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.prefix => upload_progress_ => upload_progress_
session.use_cookies => On => On
session.use_only_cookies => On => On
session.use_strict_mode => Off => Off
session.use_trans_sid => 0 => 0

shmop

shmop support => enabled

SimpleXML

Simplexml support => enabled
Revision => $Id: 0637e06af859ca1d0dea9c2f1530e51b98f1970e $
Schema support => enabled

sockets

Sockets Support => enabled

SPL

SPL support => enabled
Interfaces => Countable, OuterIterator, RecursiveIterator, SeekableIterator, SplObserver, SplSubject
Classes => AppendIterator, ArrayIterator, ArrayObject, BadFunctionCallException, BadMethodCallException, CachingIterator, CallbackFilterIterator, DirectoryIterator, DomainException, EmptyIterator, FilesystemIterator, FilterIterator, GlobIterator, InfiniteIterator, InvalidArgumentException, IteratorIterator, LengthException, LimitIterator, LogicException, MultipleIterator, NoRewindIterator, OutOfBoundsException, OutOfRangeException, OverflowException, ParentIterator, RangeException, RecursiveArrayIterator, RecursiveCachingIterator, RecursiveCallbackFilterIterator, RecursiveDirectoryIterator, RecursiveFilterIterator, RecursiveIteratorIterator, RecursiveRegexIterator, RecursiveTreeIterator, RegexIterator, RuntimeException, SplDoublyLinkedList, SplFileInfo, SplFileObject, SplFixedArray, SplHeap, SplMinHeap, SplMaxHeap, SplObjectStorage, SplPriorityQueue, SplQueue, SplStack, SplTempFileObject, UnderflowException, UnexpectedValueException

standard

Dynamic Library Support => enabled
Path to sendmail => /usr/sbin/sendmail -t -i 

Directive => Local Value => Master Value
assert.active => 1 => 1
assert.bail => 0 => 0
assert.callback => no value => no value
assert.exception => 0 => 0
assert.quiet_eval => 0 => 0
assert.warning => 1 => 1
auto_detect_line_endings => 0 => 0
default_socket_timeout => 60 => 60
from => no value => no value
url_rewriter.tags => a=href,area=href,frame=src,input=src,form=fakeentry => a=href,area=href,frame=src,input=src,form=fakeentry
user_agent => no value => no value

sysvmsg

sysvmsg support => enabled
Revision => $Id: dfb999763f95bfe9609fae60b4e07a492888ec7c $

sysvsem

Version => 7.0.30-0+deb9u1

sysvshm

Version => 7.0.30-0+deb9u1

tokenizer

Tokenizer Support => enabled

wddx

WDDX Support => enabled
WDDX Session Serializer => enabled

xml

XML Support => active
XML Namespace Support => active
libxml2 Version => 2.9.4

xmlreader

XMLReader => enabled

xmlwriter

XMLWriter => enabled

xsl

XSL => enabled
libxslt Version => 1.1.29
libxslt compiled against libxml Version => 2.9.4
EXSLT => enabled
libexslt Version => 1.1.29

Zend OPcache

Opcode Caching => Disabled
Optimization => Disabled
SHM Cache => Enabled
File Cache => Disabled
Startup Failed => Opcode Caching is disabled for CLI

Directive => Local Value => Master Value
opcache.blacklist_filename => no value => no value
opcache.consistency_checks => 0 => 0
opcache.dups_fix => Off => Off
opcache.enable => On => On
opcache.enable_cli => Off => Off
opcache.enable_file_override => Off => Off
opcache.error_log => no value => no value
opcache.fast_shutdown => 0 => 0
opcache.file_cache => no value => no value
opcache.file_cache_consistency_checks => 1 => 1
opcache.file_cache_only => 0 => 0
opcache.file_update_protection => 2 => 2
opcache.force_restart_timeout => 180 => 180
opcache.huge_code_pages => Off => Off
opcache.inherited_hack => On => On
opcache.interned_strings_buffer => 4 => 4
opcache.lockfile_path => /tmp => /tmp
opcache.log_verbosity_level => 1 => 1
opcache.max_accelerated_files => 2000 => 2000
opcache.max_file_size => 0 => 0
opcache.max_wasted_percentage => 5 => 5
opcache.memory_consumption => 64 => 64
opcache.optimization_level => 0x7FFFBFFF => 0x7FFFBFFF
opcache.preferred_memory_model => no value => no value
opcache.protect_memory => 0 => 0
opcache.restrict_api => no value => no value
opcache.revalidate_freq => 2 => 2
opcache.revalidate_path => Off => Off
opcache.save_comments => 1 => 1
opcache.use_cwd => On => On
opcache.validate_permission => Off => Off
opcache.validate_root => Off => Off
opcache.validate_timestamps => On => On

zlib

ZLib Support => enabled
Stream Wrapper => compress.zlib://
Stream Filter => zlib.inflate, zlib.deflate
Compiled Version => 1.2.8
Linked Version => 1.2.8

Directive => Local Value => Master Value
zlib.output_compression => Off => Off
zlib.output_compression_level => -1 => -1
zlib.output_handler => no value => no value

Additional Modules

Module Name

Environment

Variable => Value
PATH => /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME => d8d87a9dda55
HOME => /root

PHP Variables

Variable => Value
$_SERVER['PATH'] => /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$_SERVER['HOSTNAME'] => d8d87a9dda55
$_SERVER['HOME'] => /root
$_SERVER['PHP_SELF'] => 
$_SERVER['SCRIPT_NAME'] => 
$_SERVER['SCRIPT_FILENAME'] => 
$_SERVER['PATH_TRANSLATED'] => 
$_SERVER['DOCUMENT_ROOT'] => 
$_SERVER['REQUEST_TIME_FLOAT'] => 1753720355.5192
$_SERVER['REQUEST_TIME'] => 1753720355
$_SERVER['argv'] => Array
(
)

$_SERVER['argc'] => 0

PHP License
This program is free software; you can redistribute it and/or modify
it under the terms of the PHP License as published by the PHP Group
and included in the distribution in the file:  LICENSE

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

If you did not receive a copy of the PHP license, or have any
questions about PHP licensing, please contact license@php.net.
$ docker exec dvwa apache2ctl -S
Returned: 0
-- stdout --
VirtualHost configuration:
*:80                   172.17.0.2 (/etc/apache2/sites-enabled/000-default.conf:1)
ServerRoot: "/etc/apache2"
Main DocumentRoot: "/var/www/html"
Main ErrorLog: "/var/log/apache2/error.log"
Mutex watchdog-callback: using_defaults
Mutex default: dir="/var/run/apache2/" mechanism=default 
Mutex mpm-accept: using_defaults
PidFile: "/var/run/apache2/apache2.pid"
Define: DUMP_VHOSTS
Define: DUMP_RUN_CFG
User: name="www-data" id=33
Group: name="www-data" id=33
-- stderr --
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2. Set the 'ServerName' directive globally to suppress this message

```

## OTG-CONFIG-003
**Description**: File Extensions Handling

**Status**: ✅ Completed

**Results**:
```json
{
  "status": "ffuf not found"
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-003 – File Extensions Handling
======================================================================

```

## OTG-CONFIG-004
**Description**: Old/Backup/Unreferenced Files

**Status**: ✅ Completed

**Results**:
```json
{
  "status": "gobuster not found"
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-004 – Old/Backup/Unreferenced Files
======================================================================

```

## OTG-CONFIG-005
**Description**: Enumerate Admin Interfaces

**Status**: ✅ Completed

**Results**:
```json
[]
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-005 – Enumerate Admin Interfaces
======================================================================
Possible admin links: []

```

## OTG-CONFIG-006
**Description**: Test HTTP Methods

**Status**: ✅ Completed

**Results**:
```json
{
  "GET": {
    "status": 200,
    "len": 1523
  },
  "POST": {
    "status": 200,
    "len": 1523
  },
  "PUT": {
    "status": 200,
    "len": 1523
  },
  "DELETE": {
    "status": 200,
    "len": 1523
  },
  "PATCH": {
    "status": 200,
    "len": 1523
  },
  "TRACE": {
    "status": 405,
    "len": 300
  },
  "TRACK": {
    "status": 200,
    "len": 1523
  },
  "CONNECT": {
    "status": 400,
    "len": 302
  },
  "DEBUG": {
    "status": 200,
    "len": 1523
  }
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-006 – Test HTTP Methods
======================================================================
GET: 200 (Length: 1523)
POST: 200 (Length: 1523)
PUT: 200 (Length: 1523)
DELETE: 200 (Length: 1523)
PATCH: 200 (Length: 1523)
TRACE: 405 (Length: 300)
TRACK: 200 (Length: 1523)
CONNECT: 400 (Length: 302)
DEBUG: 200 (Length: 1523)

```

## OTG-CONFIG-007
**Description**: HTTP Strict Transport Security

**Status**: ✅ Completed

**Results**:
```json
{
  "present": false,
  "value": null
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-007 – HTTP Strict Transport Security
======================================================================
HSTS header: None

```

## OTG-CONFIG-008
**Description**: RIA Cross-Domain Policy

**Status**: ✅ Completed

**Results**:
```json
{
  "/crossdomain.xml": {
    "status": "error"
  },
  "/clientaccesspolicy.xml": {
    "status": "error"
  }
}
```

**Console Output**:
```

======================================================================
  OTG-CONFIG-008 – RIA Cross-Domain Policy
======================================================================
/crossdomain.xml: Request failed
/clientaccesspolicy.xml: Request failed

```

