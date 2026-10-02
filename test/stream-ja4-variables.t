# vi:filetype=perl
# Test::Nginx cases for ngx_stream_ssl_ja4_module.
#
# Each block gets a stream server on TEST_NGINX_SSL_PORT that terminates TLS
# and returns a bare HTTP/1.0 response, so the curlu `curl` wrapper can be
# the client (see test/tls-ja4-variables.t). Goldens are the HTTP ones from
# tls-ja4-variables.t: the same ClientHello must fingerprint the same way
# whichever module reads it.
#
# Requires nginx with stream + stream_ssl_module, both nginx patches, and
# test/certs/server.{crt,key}.
#
# Run:
#   export TEST_NGINX_BINARY=/path/to/nginx
#   export PERL5LIB=$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}
#   prove -v test/stream-ja4-variables.t

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
    $ENV{TEST_NGINX_USE_HTTP2} = 1;
}

use Test::Nginx::Socket 'no_plan';

no_root_location();

$ENV{TEST_NGINX_SSL_PORT} ||= server_port() + 10;
server_port_for_client($ENV{TEST_NGINX_SSL_PORT});

my $crt = File::Spec->rel2abs('test/certs/server.crt');
my $key = File::Spec->rel2abs('test/certs/server.key');
my $ssl_port = $ENV{TEST_NGINX_SSL_PORT};

add_block_preprocessor(sub {
    my $block = shift;
    my $body = $block->stream_return;
    my $plain = defined $block->stream_plain;
    my $ssl = $plain ? '' : <<"_EOC_";
        ssl_certificate     $crt;
        ssl_certificate_key $key;
        ssl_session_cache   off;
_EOC_
    my $listen = $plain ? '' : ' ssl';

    $block->set_value(main_config => <<"_EOC_");
stream {
    log_format ja4 "\$stream_ssl_ja4 \$stream_ssl_ja4one \$stream_ssl_ja4t";

    server {
        listen 127.0.0.1:$ssl_port$listen;
        tcp_save_syn on;
$ssl
        access_log logs/stream.log ja4;
        return "HTTP/1.0 200 OK\\r\\n\\r\\n$body\\n";
    }
}
_EOC_
    $block->set_value(config => "location / { return 200; }\n");

    my $opts = $plain ? '' : '-k ';
    $opts .= $block->curl_options // '';
    my $target_addr = $block->server_addr_for_client;
    if (defined $target_addr && $target_addr ne '127.0.0.1') {
        $opts .= " --resolve $target_addr:$ssl_port:127.0.0.1";
    }
    $block->set_value(curl_options => $opts);
    $block->set_value(curl_protocol => $plain ? 'http' : 'https');
    # stream `return` never reads, so the raw (non-curl) client sends nothing
    if ($plain) {
        $block->set_value(raw_request => '');
    } else {
        $block->set_value(request => "GET /t");
    }
});

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: firefox_55_ja4
# Same golden as tls-ja4-variables.t TEST 1.
--- stream_return: ja4=$stream_ssl_ja4
--- curl_options: --utls-hello HelloFirefox_55
--- response_body_like chomp
^ja4=t12i1508h2_073e58a039a6_e70312a1ce2c$
--- no_error_log
[error]



=== TEST 2: golang_default_ja4
# tls-ja4-variables.t TEST 3: ALPN http/1.1 only.
--- stream_return: ja4=$stream_ssl_ja4
--- response_body_like chomp
^ja4=t13i1310h1_f57a46bbacb6_e7c285222651$
--- no_error_log
[error]



=== TEST 3: chrome_120_ja4one
# tls-ja4-variables.t TEST 5.
--- stream_return: ja4one=$stream_ssl_ja4one
--- curl_options: --utls-hello HelloChrome_120
--- response_body_like chomp
^ja4one=t13i1514h2_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 4: chrome_120_ja4_string
# tls-ja4-variables.t TEST 4: raw cipher list is stable.
--- stream_return: ja4_string=$stream_ssl_ja4_string
--- curl_options: --utls-hello HelloChrome_120
--- response_body_like chomp
^ja4_string=t13i15[0-9]{2}h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_
--- no_error_log
[error]



=== TEST 5: tls12_h1_sni
# tls-ja4-variables.t TEST 16: SNI (d) and offered ALPN http/1.1 (h1).
--- stream_return: ja4=$stream_ssl_ja4
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloFirefox_55 --utls-alpn-hex 687474702f312e31
--- response_body_like chomp
^ja4=t12d1509h1_073e58a039a6_e70312a1ce2c$
--- no_error_log
[error]



=== TEST 6: all_variables_twice
# Second read of each variable comes from the session cache.
--- stream_return: $stream_ssl_ja4 $stream_ssl_ja4 $stream_ssl_ja4one $stream_ssl_ja4one
--- curl_options: --utls-hello HelloFirefox_55
--- response_body_like chomp
^(t12i1508h2_073e58a039a6_e70312a1ce2c) \1 (t12i1507h2_073e58a039a6_8ebfdaddfa31) \2$
--- no_error_log
[error]



=== TEST 7: ja4t_on_tls
# Kernel SYN from the loopback client; values depend on the host stack.
--- stream_return: ja4t=$stream_ssl_ja4t ja4t_string=$stream_ssl_ja4t_string
--- response_body_like chomp
^ja4t=(\d+_[0-9-]+_\d+_\d+) ja4t_string=\1$
--- no_error_log
[error]



=== TEST 8: plain_tcp
# No TLS: JA4 variables are empty, JA4T still works.
--- stream_plain
--- no_http2
--- stream_return: ja4=[$stream_ssl_ja4] ja4one=[$stream_ssl_ja4one] ja4t=[$stream_ssl_ja4t]
--- response_body_like chomp
^ja4=\[\] ja4one=\[\] ja4t=\[\d+_[0-9-]+_\d+_\d+\]$
--- no_error_log
[error]
