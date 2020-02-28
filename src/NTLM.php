<?php namespace davelip\ntlm;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class NTLM
{
    /**
     * Logger
     * @object LoggerInterface
     */
    private $_logger;

    /**
     * Session
     * @object SessionInterface
     */
    private $_session;

    private $targetname;
    private $domain;
    private $computer;
    private $dnsdomain;
    private $dnscomputer;

    public function __construct(SessionInterface $session, LoggerInterface $logger = null)
    {
        $this->_logger = $logger;
        $this->_session = $session;

        $this->targetname = 'ROADHOUSE';
        $this->domain = 'CAFIN_DOM';
        $this->computer = 'COMPUTER';
        $this->dnsdomain = 'CREMONINI.LOCAL';
        $this->dnscomputer = 'CREMONINI.LOCAL';
    }

    public function auth()
    {
        $failmsg = '<h1>Unauthorized</h1>';

        if ($this->_logger) {
            $this->_logger->info('Doing work');
        }

        $auth_header = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : null;
        if ($auth_header == null && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        }
        else if ($auth_header == null && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
        }

        if ($this->_logger && ! empty($auth_header)) {
            $this->_logger->info($auth_header);
        }

        if (!$auth_header) {
            if ($this->_logger) {
                $this->_logger->debug(__LINE__ . ' Auth Header is not present. I send to client an NTLM auth request and a 401 Unauthorized status');
            }
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: NTLM');
            print $failmsg;
            die();
        }

/*
var_dump($auth_header);
var_dump(substr($auth_header, 0, 5));
var_dump(substr($auth_header, 4, 1));
var_dump(unpack('I', (substr($auth_header, 4, 1))));
var_dump(unpack('I', $auth_header));
die();
if (substr($auth_header,0,5) == 'NTLM ') {
  $msg = base64_decode(substr($auth_header, 5));
  if (substr($msg, 0, 8) != "NTLMSSP\x00")
    die('error header not recognised');

  if ($msg[8] == "\x01") {
    $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
        "\x00\x00\x00\x00". // target name len/alloc
      "\x00\x00\x00\x00". // target name offset
      "\x01\x02\x81\x00". // flags
      "\x00\x00\x00\x00\x00\x00\x00\x00". // challenge
      "\x00\x00\x00\x00\x00\x00\x00\x00". // context
      "\x00\x00\x00\x00\x00\x00\x00\x00"; // target info len/alloc/offset
    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
    exit;
  }
  else if ($msg[8] == "\x03") {
    function get_msg_str($msg, $start, $unicode = true) {
      $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
      $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
      if ($unicode)
        return str_replace("\0", '', substr($msg, $off, $len));
      else
        return substr($msg, $off, $len);
    }
    $user = get_msg_str($msg, 36);
    $domain = get_msg_str($msg, 28);
    $workstation = get_msg_str($msg, 44);
    print "You are $user from $domain/$workstation";
    die();
  }
}
*/

        // I have got a NTLM header from client
        if (substr($auth_header,0,5) == 'NTLM ') {

            if ($this->_logger) {
                $this->_logger->debug(__LINE__ . ' ' . $auth_header);
            }

            $msg = substr($auth_header, 5);
            if ($this->_logger) {
                $this->_logger->debug(__LINE__ . ' ' . $msg);
            }
            $msg = base64_decode($msg);

            if (substr($msg, 0, 8) != "NTLMSSP\x00") {
                $error = 'NTLM error header not recognised';
                if ($this->_logger) {
                    $this->_logger->error(__LINE__ . ' ' . $error);
                }
                die($error);
            }

            if ($this->_logger) {
                $this->_logger->debug(__LINE__ . ' "' . $msg[8] . '"');
            }

            if ($msg[8] == "\x01") {
                $random = $this->ntlm_get_random_bytes(8);

                $this->_session->set('_ntlm_server_challenge', $random);

                if ($this->_logger) {
                    $this->_logger->debug(__LINE__ . ' "' . base64_encode($random) . '"');
                }

                $msg2 = $this->ntlm_get_challenge_msg(
                    $msg
                    , $random
                    );

                if ($this->_logger) {
                    $this->_logger->debug(__LINE__ . ' "' . base64_encode($msg2) . '"');
                }

                header('HTTP/1.1 401 Unauthorized');
                header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
                //print bin2hex($msg2);
                die('a');
            }
            else if ($msg[8] == "\x03") {
                $auth = $this->ntlm_parse_response_msg($msg);
                var_dump($auth);
                $this->_session->remove('_ntlm_server_challenge');

    function get_msg_str($msg, $start, $unicode = true) {
      $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
      $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
      if ($unicode)
        return str_replace("\0", '', substr($msg, $off, $len));
      else
        return substr($msg, $off, $len);
    }
    $user = get_msg_str($msg, 36);
    $domain = get_msg_str($msg, 28);
    $workstation = get_msg_str($msg, 44);
    print "You are $user from $domain/$workstation";
    die();

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

    /**
     *
     */
    private function ntlm_get_random_bytes($length)
    {
        $result = "";
        for ($i = 0; $i < $length; $i++) {
            $result .= chr(rand(0, 255));
        }
        return $result;
    }

    private function ntlm_field_value($msg, $start, $decode_utf16 = true)
    {
        $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
        $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
        $result = substr($msg, $off, $len);
        if ($decode_utf16) {
            //$result = str_replace("\0", '', $result);
            $result = iconv('UTF-16LE', 'UTF-8', $result);
        }
        return $result;
    }

    private function ntlm_av_pair($type, $utf16) {
        return pack('v', $type).pack('v', strlen($utf16)).$utf16;
    }

    private function ntlm_utf8_to_utf16le($str) {
        return iconv('UTF-8', 'UTF-16LE', $str);
    }

    private function ntlm_get_challenge_msg($msg, $challenge, $targetname="", $domain="", $computer="", $dnsdomain="", $dnscomputer="")
    {
        /*
        $domain = $this->ntlm_field_value($msg, 16);
        $ws = $this->ntlm_field_value($msg, 24);
        $tdata = $this->ntlm_av_pair(2, $this->ntlm_utf8_to_utf16le($domain)).$this->ntlm_av_pair(1, $this->ntlm_utf8_to_utf16le($computer)).$this->ntlm_av_pair(4, $this->ntlm_utf8_to_utf16le($dnsdomain)).$this->ntlm_av_pair(3, $this->ntlm_utf8_to_utf16le($dnscomputer))."\0\0\0\0\0\0\0\0";
        $tname = $this->ntlm_utf8_to_utf16le($targetname);

        $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
            pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
            "\x01\x02\x81\x00". // flags
            $challenge. // challenge
            "\x00\x00\x00\x00\x00\x00\x00\x00". // context
            pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
            $tname.$tdata;
         */

        $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
            "\x00\x00\x00\x00". // target name len/alloc
            "\x00\x00\x00\x00". // target name offset
            "\x01\x02\x81\x00". // flags
            $challenge .
            "\x00\x00\x00\x00\x00\x00\x00\x00". // context
            "\x00\x00\x00\x00\x00\x00\x00\x00"; // target info len/alloc/offset

        return $msg2;
    }

    private function ntlm_parse_response_msg($msg)
    {
        $user = $this->ntlm_field_value($msg, 36);
        $domain = $this->ntlm_field_value($msg, 28);
        $workstation = $this->ntlm_field_value($msg, 44);
        $ntlmresponse = $this->ntlm_field_value($msg, 20, false);
        //$blob = "\x01\x01\x00\x00\x00\x00\x00\x00".$timestamp.$nonce."\x00\x00\x00\x00".$tdata;
        $clientblob = substr($ntlmresponse, 16);
        $clientblobhash = substr($ntlmresponse, 0, 16);

        if (substr($clientblob, 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
            return array('authenticated' => false, 'error' => 'NTLMv2 response required. Please force your client to use NTLMv2.');
        }

        // print bin2hex($msg)."<br>";

        return array('authenticated' => true, 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
    }

}
