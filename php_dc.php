<?php
ini_set("display_errors", 1);
ini_set("error_reporting", E_ALL);

class GSSAPI
{
	private $ntlm_oid = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";

	private function makeoctstr($payload)
	{
	    return $this->maketlv("\x04", $payload);
	}

	private function makeseq($payload)
	{
	    return $this->maketlv("\x30", $payload);
	}

	private function maketlv($dertype, $payload) 
	{
	    	if (strlen($payload)<128) {
			return $dertype . chr(strlen($payload)) . $payload;
		}
	    	if (strlen($payload)<256) {
			return $dertype . "\x81" . chr(strlen($payload)) . $payload;
		}
		# 				 >H
	    	return $dertype . "\x82" . pack("n",strlen($payload)) . $payload;
	}

	private function xrange($start, $limit, $step = 1) {
		if ($start <= $limit) {
			if ($step <= 0) {
				throw new LogicException('Step must be positive');
			}

			for ($i = $start; $i < $limit; $i += $step) {
				yield $i;
			}
		} else {
			if ($step >= 0) {
				throw new LogicException('Step must be negative');
			}

			for ($i = $start; $i >= $limit; $i += $step) {
				yield $i;
			}
		}
	}

	private function parselen($berobj)
	{
var_dump(__METHOD__);
var_dump(base64_encode($berobj));
var_dump('strlen ' . strlen($berobj) . "\n");
		$length = ord(substr($berobj, 1, 1));
var_dump("ord " . ord(substr($berobj, 1,1)) . "\n");
var_dump("length " . $length . "\n");

		# Short
		if ($length<128) {
			return [$length, 2];
		}

		# Long
		$nlength = $length & 0x7F;
var_dump("nlength " . $nlength . "\n");

		$length = 0;

		foreach ($this->xrange(2, 2+$nlength) as $i) {
var_dump('i ' . $i . "\n");
var_dump("length " . $length . "\n");
var_dump("ord " . ord(substr($berobj, $i, 1)) . "\n");
			$length = $length*256 + ord(substr($berobj, $i, 1));
		}

var_dump("length " . $length . "\n");
var_dump("nlength " . (2+$nlength) . "\n");
		return [$length, (2 + $nlength)];
	}

	private function  parsetlv($dertype, $derobj, $partial=false)
	{
var_dump(__METHOD__);
		if (substr($derobj, 0, 1)!=$dertype) {
			throw new Exception(printf('BER element %s does not start with type 0x%s.', bin2hex($derobj), bin2hex($dertype)));
		}

		$aOut = $this->parselen($derobj);
		$length = $aOut[0];
		$pstart = $aOut[1];

var_dump(printf("length %d pstart %d", $length, $pstart));

if (strlen($derobj)!=($length+$pstart)) {
	die('errore');
}

		if ($partial) {
			if (strlen($derobj)<$length+$pstart) {
			    throw new Exception(printf('BER payload %s is shorter than expected (%d bytes, type %X).', bin2hex($derobj), $length, ord($derobj[0])));
			}
			return [substr($derobj, $pstart, $pstart+$length), substr($derobj, $pstart+$length)];
		}
		if (strlen($derobj)!=($length+$pstart)) {
			throw new Exception(printf('BER payload %s is not %d bytes long (type %X).', bin2hex($derobj), $length, ord($derobj[0])));
		}
		return substr($derobj, $pstart);
	}

	private function parseoctstr($payload, $partial=false)
	{
var_dump(__METHOD__);
		return $this->parsetlv("\04", $payload, $partial);
	}

	private function parseseq($payload, $partial=false)
	{
var_dump(__METHOD__);
	    	return $this->parsetlv("\x30", $payload, $partial);
	}

	public function makeToken($ntlm_token, $type1=true)
	{
var_dump(__METHOD__);
		if (! $type1) {
		$mechToken = $this->maketlv("\xa2", $this->makeoctstr($ntlm_token));
		$negTokenResp = $this->maketlv("\xa1", $this->makeseq($mechToken));
		return $negTokenResp;
		}

		# NegTokenInit (rfc4178)
		$mechlist = $this->makeseq($this->ntlm_oid);
		#var_dump(base64_encode($mechlist)); # VERIFIED
		$mechTypes = $this->maketlv("\xa0", $mechlist);
		#var_dump(base64_encode($mechTypes)); # VERIFIED
		$mechToken = $this->maketlv("\xa2", $this->makeoctstr($ntlm_token));
		#var_dump(base64_encode($mechToken)); #VERIFIED

		# NegotiationToken (rfc4178)
		$negTokenInit = $this->makeseq($mechTypes . $mechToken ); # + mechListMIC)
		#var_dump(base64_encode($negTokenInit));#VERIFIED
		$innerContextToken = $this->maketlv("\xa0", $negTokenInit);
		#var_dump(base64_encode($innerContextToken));#VERIFIED

		# MechType + innerContextToken (rfc2743)
		$thisMech = "\x06\x06\x2b\x06\x01\x05\x05\x02"; # SPNEGO OID 1.3.6.1.5.5.2
		#var_dump(base64_encode($thisMech));#VERIFIED
		$spnego = $thisMech . $innerContextToken;
		#var_dump(base64_encode($spnego));#VERIFIED

		# InitialContextToken (rfc2743)
		$msg = $this->maketlv("\x60", $spnego);
		#var_dump(base64_encode($msg));#VERIFIED
		return $msg;
	}

	public function extractToken($msg)
	{
var_dump(__METHOD__);
		# Extract negTokenResp from NegotiationToken
		$spnego = $this->parseseq($this->parsetlv("\xa1", $msg, false));

		# Extract negState
		$aOut = $this->parsetlv("\xa0", $spnego, True);
		$negState = $aOut[0];
		$msg = $aOut[1];
		$status = $this->parseenum($negState);
		if ($status != 1) {
			throw new Exception(printf("Unexpected SPNEGO negotiation status (%d).", $status));
		}

		# Extract supportedMech
		$aOut = $this->parsetlv("\xa1", $msg, True);
		$supportedMech = $aOut[0];
		$msg = $aOut[1];
		if ($supportedMech!=$ntlm_oid) {
			throw new Exception("Unexpected SPNEGO mechanism in GSSAPI response.");
		}

		# Extract Challenge, and forget about the rest
		$aOut = $this->parsetlv("\xa2", $msg, True);
		$token = $aOut[0];
		$msg = $aOut[1];
		return $this->parseoctstr($token);
	}
}
	

class phpDB
{
	private $socket;
	private $gssapi;
	private $userId = 0;

	private $sessionKey = "\x00\x00\x00\x00";

	const SMB_Header_Length               = 32;
	const SMB_COM_NEGOTIATE               = 0x72;
	const SMB_COM_SESSION_SETUP_ANDX      = 0x73;

	const SMB_FLAGS2_EXTENDED_SECURITY    = 0x0800;
	const SMB_FLAGS2_NT_STATUS            = 0x4000;
	const SMB_FLAGS2_UNICODE              = 0x8000;

	const CAP_UNICODE                     = 0x00000004;
	const CAP_NT_SMBS                     = 0x00000010;
	const CAP_STATUS32                    = 0x00000040;
	const CAP_EXTENDED_SECURITY           = 0x80000000;

	public function __construct()
	{
		$this->gssapi = new GSSAPI();

		$this->socket = socket_create(AF_INET, SOCK_STREAM, 0);
		if (!$this->socket) {
			throw new Exception("Unable to create socket to PDC");
			exit;
		}
		$bRv = socket_connect($this->socket, "192.168.1.7", 445);
		if (!$bRv) {
			throw new Exception("Unable to create stream to PDC");
			exit;
		}
		$timeout = array("sec"=>100,"usec"=>500000);
  		socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, $timeout);
	}

	public function __destruct() 
	{
		$this->close();
	}


 	private function removeTransport($msg)
	{
		$data = substr($msg, 4);
		#                >H
		$length = unpack('n', substr($msg, 2, 2))[1];
		if (substr($msg, 0, 2)!="\x00\x00" || $length!=strlen($data)) {
		    throw new Exception(printf('Error while parsing Direct TCP transport Direct (%d, expected %d).', $length, strlen($data)));
		}
		return $data;
	}

 	private function parseSessionSetupResp($resp)
	{
var_dump(__METHOD__);
		$smb_data = $this->removeTransport($resp);
		$hdr = substr($smb_data, 0, self::SMB_Header_Length);
		$msg = substr($smb_data, self::SMB_Header_Length);

		# <I little-endian unsigned int
		$status = unpack('V', substr($hdr, 5, 9))[1];
		if ($status==0) {
		    return [true, ''];
		}
		if ($status!=0xc0000016) {
		    return [false, ''];
		}

		# User ID
		# <H little-endian unsigned short
		$this->userId = unpack('v', substr($hdr, 28, 30))[1];
#var_dump('userId ' . $this->userId); #VERIFIED
		# WordCount
		$idx = 0;
		if ($msg[$idx]!="\x04") {
		    throw new Exception('Incorrect WordCount');
		}
		# SecurityBlobLength
		$idx += 7;
		# <H little-endian unsigned short
		$length = unpack('v', substr($msg, $idx, $idx+2))[1];
#var_dump('length ' . $length); #VERIFIED
		# Security Blob
		$idx += 4;
var_dump('idx ' . $idx);
var_dump('idx+length ' . ($idx+$length));
		$blob = substr($msg, $idx, $idx+$length);
var_dump('blob ' . base64_encode($blob));
		$aRv =  [true, $this->gssapi->extractToken($blob)];
		return $aRv;
	}

	public function negotiate($data)
	{
		$msg = $this->makeNegotiateProtocolRequest();
		#var_dump(base64_encode($msg)); #VERIFIED
		if ($msg) {
			$msg = $this->transaction($msg);
			#var_dump(base64_encode($msg)); #VERIFIED
			// TODO
			//$this->parseNegotiateProtocolResp($msg);
		}

		#var_dump(base64_encode($data)); #VERIFIED
		$msg = $this->makeSessionSetupRequest($data, true);
		#var_dump(base64_encode($msg)); #VERIFIED

		$resp = $this->transaction($msg);
		var_dump(base64_encode($resp));
die();

		$aOut = $this->parseSessionSetupResp($resp);
var_dump('aOut');
var_dump($aOut);
die();
		if (!$aOut[0]) {
		    return false;
		}
		return $aOut[1];
	}

	private function getTransportLength($data)
	{
		#              >H
		return unpack("n", substr($data, 2, 2))[1];
	}

	public function transaction($msg)
	{
		if ($this->socket==false) {
			throw new Exception("Socket has gone away");
			exit;
		}
		$sent = socket_send($this->socket, $msg, strlen($msg), 0);
		$data = socket_read($this->socket, 4);
var_dump('transaction ' . base64_encode($data));
		if ($data!==false) {
			$length = $this->getTransportLength($data);
var_dump('getTransportLength ' . $length);
			$data .= socket_read($this->socket, $length);
var_dump('transaction ' . base64_encode($data));
		}
		return $data;
	}

	private function createSMBHeader($command)
	{
		# See 2.2.3.1 in [MS-CIFS]
		$hdr =  "\xFFSMB";
		$hdr .= chr($command);
		# <I little-endian unsigned int
		$hdr .= pack("V", 0);    # Status
		$hdr .= "\x00";           # Flags
		# <H little-endian unsigned short
		$hdr .= pack("v",       # Flags2
		    self::SMB_FLAGS2_EXTENDED_SECURITY   | 
		    self::SMB_FLAGS2_NT_STATUS           |
		    self::SMB_FLAGS2_UNICODE
		    );
		# PID high, SecurityFeatures, Reserved, TID, PID low, UID, MUX ID
		# "<H8sHHHHH" little endian ushort 8char ushort ushort ushort ushort ushort
		$hdr .= pack("va8vvvvv", 0, "", 0, 0, 0, $this->userId, 0);
		return $hdr;
	}

	private function addTransport($msg)
	{
		# ">H" big endian unsigned short
        	return "\x00\x00" . pack("n", strlen($msg)) . $msg;
	}
	
	private function makeNegotiateProtocolRequest()
	{
        	$this->userId = 0;
		$hdr = $this->createSMBHeader(self::SMB_COM_NEGOTIATE);
		$params = "\x00"; 
		$dialects = "\x02NT LM 0.12\x00";
		$data = pack("v", strlen($dialects)) . $dialects;
		return $this->addTransport($hdr.$params.$data);
	}
	private function makeSessionSetupRequest($ntlm_token, $type1=true)
	{
        	//$this->userId = 0;
		$hdr = $this->createSMBHeader(self::SMB_COM_SESSION_SETUP_ANDX);
		#var_Dump(base64_encode($hdr)); # VERIFIED

		# Start building SMB_Data, excluding ByteCount
		$data = $this->gssapi->makeToken($ntlm_token, $type1); 
		#var_dump(base64_encode($data)); #VERIFIED

		# See 2.2.4.53.1 in MS-CIFS and 2.2.4.6.1 in MS-SMB
		$params = "\x0C\xFF\x00";             # WordCount, AndXCommand, AndXReserved
		# AndXOffset, MaxBufferSize, MaxMpxCount,VcNumber, SessionKey
		# "<HHHH4s" little endian ushort ushort ushort 4char
		$params .= pack("vvvva4", 0, 1024, 2, 1, "\x00");

		# "<H" little endian ushort
		$params .= pack("v", strlen($data));     # SecurityBlobLength
		# "<I" little endian uint
		$params .= pack("V",0);              # Reserved
		# "<I" little endian uint
		$params .= pack("V",                # Capabilities
		      self::CAP_UNICODE  |
		      self::CAP_NT_SMBS  |
		      self::CAP_STATUS32 |
		      self::CAP_EXTENDED_SECURITY);
		#var_Dump(base64_encode($params)); # VERIFIED
		
		if ((strlen($data)+strlen($params))%2==1) {
			$data .= "\x00";
		}
		$data .= iconv("UTF-8", "UTF-16LE", "Python\0");  # NativeOS
		$data .= iconv("UTF-8", "UTF-16LE", "Python\0");  # NativeLanMan
		#var_Dump(base64_encode($data)); #VERIFIED
		#var_Dump(strlen($data)); #VERIFIED

		# "<H" little endian unsigned short
		$rv = $this->addTransport($hdr.$params.pack("v", strlen($data)).$data);
		#var_Dump(base64_encode($rv));#VERIFIED
		return $rv;
	}


	private function close()
	{
		socket_close($this->socket);
	}
}

/*
var_dump("DC");
var_dump(pack("I", "\x00"));
var_dump(base64_encode(pack("L", "\x00")));
*/

// NTLM specs http://davenport.sourceforge.net/ntlm.html
if (empty($_SERVER["HTTP_AUTHORIZATION"]) && empty($_SERVER["REDIRECT_HTTP_AUTHORIZATION"])){
	header("HTTP/1.1 401 Unauthorized");
	header("WWW-Authenticate: NTLM");
	exit;
}

if (!empty($_SERVER["REDIRECT_HTTP_AUTHORIZATION"])){
	$auth = $_SERVER["REDIRECT_HTTP_AUTHORIZATION"];
} else {
	$auth = $_SERVER["HTTP_AUTHORIZATION"];
}

if (substr($auth,0,5) == "NTLM ") {
	$msg = base64_decode(substr($auth, 5));
	if (substr($msg, 0, 8) != "NTLMSSP\x00") {
		die("error header not recognized");
	}
	if ($msg[8] == "\x01") {
		$a = new phpDB();
		$a->negotiate($msg);
die();

		$msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
			"\x00\x00\x00\x00". // target name len/alloc
			"\x00\x00\x00\x00". // target name offset
			"\x01\x02\x81\x00". // flags
			"\x00\x00\x00\x00\x00\x00\x00\x00". // challenge
			"\x00\x00\x00\x00\x00\x00\x00\x00". // context
			"\x00\x00\x00\x00\x00\x00\x00\x00"; // target info len/alloc/offset
		header("HTTP/1.1 401 Unauthorized");
		header("WWW-Authenticate: NTLM ".trim(base64_encode($msg2)));
		exit;
  	}
  	else if ($msg[8] == "\x03") {
		function get_msg_str($msg, $start, $unicode = true) {
			$len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
			$off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
			if ($unicode)
				return str_replace("\0", "", substr($msg, $off, $len));
			else
				return substr($msg, $off, $len);
		}
		$user = get_msg_str($msg, 36);
		$domain = get_msg_str($msg, 28);
		$workstation = get_msg_str($msg, 44);
		print "You are $user from $domain/$workstation";
	}
}

