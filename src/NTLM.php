<?php namespace davelip\ntlm;

use Psr\Log\LoggerInterface;

class NTLM
{
    private $logger;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    public function auth()
    {
        if ($this->logger) {
            $this->logger->info('Doing work');
        }

        $auth_header = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : null;
        if ($auth_header == null && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        }
        else if ($auth_header == null && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
        }

        if ($this->logger && ! empty($auth_header)) {
            $this->logger->info($auth_header);
        }

        if (!$auth_header) {
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: NTLM');
            print $failmsg;
            exit;
        }

/*
var_dump($auth_header);
var_dump(substr($auth_header, 0, 5));
var_dump(substr($auth_header, 4, 1));
var_dump(unpack('I', (substr($auth_header, 4, 1))));
var_dump(unpack('I', $auth_header));
die();
*/

        if (substr($auth_header,0,5) == 'NTLM ') {
            $msg = base64_decode(substr($auth_header, 5));
            if (substr($msg, 0, 8) != "NTLMSSP\x00") {
                unset($_SESSION['_ntlm_post_data']);
                die('NTLM error header not recognised');
            }

            if ($msg[8] == "\x01") {
                $_SESSION['_ntlm_server_challenge'] = ntlm_get_random_bytes(8);
                header('HTTP/1.1 401 Unauthorized');
                $msg2 = ntlm_get_challenge_msg($msg, $_SESSION['_ntlm_server_challenge'], $targetname, $domain, $computer, $dnsdomain, $dnscomputer);
                header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
                //print bin2hex($msg2);
                exit;
            }
            else if ($msg[8] == "\x03") {
                $auth = ntlm_parse_response_msg($msg, $_SESSION['_ntlm_server_challenge'], $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback);
                unset($_SESSION['_ntlm_server_challenge']);

                if (!$auth['authenticated']) {
                    header('HTTP/1.1 401 Unauthorized');
                    header('WWW-Authenticate: NTLM');
                    //unset($_SESSION['_ntlm_post_data']);
                    print $failmsg;
                    print $auth['error'];
                    exit;
                }

                // post data retention looks like not needed
                /*if (isset($_SESSION['_ntlm_post_data'])) {
                    foreach ($_SESSION['_ntlm_post_data'] as $k => $v) {
                        $_REQUEST[$k] = $v;
                        $_POST[$k] = $v;
                    }
                    $_SERVER['REQUEST_METHOD'] = 'POST';
                    unset($_SESSION['_ntlm_post_data']);
                }*/

                $_SESSION['_ntlm_auth'] = $auth;
                return $auth;
            }
        }
    }
}
