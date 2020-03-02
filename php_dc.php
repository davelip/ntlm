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

	private function parselen($berobj)
	{
		$length = ord($berobj[1]);

		# Short
		if ($length<128) {
			return ($length, 2);
		}

		# Long
		$nlength = $length & 0x7F;

		$length = 0;

		for (i in xrange(2, 2+$nlength)) {
			$length = $length*256 + ord(berobj[i]);
		}

		return ($length, 2 + $nlength);
	}

	private function  parsetlv($dertype, $derobj, $partial=false)
	{
		if ($derobj[0]!=$dertype) {
			raise ASN1_Parse_Exception('BER element %s does not start with type 0x%s.' % (hexlify(derobj), hexlify(dertype)))
		}

		length, pstart = parselen(derobj)
		if partial:
		if len(derobj)<length+pstart:
		    raise ASN1_Parse_Exception('BER payload %s is shorter than expected (%d bytes, type %X).' % (hexlify(derobj), length, ord(derobj[0])))
		return derobj[pstart:pstart+length], derobj[pstart+length:]
		if len(derobj)!=length+pstart:
		raise ASN1_Parse_Exception('BER payload %s is not %d bytes long (type %X).' % (hexlify(derobj), length, ord(derobj[0])))
		return derobj[pstart:]
	}

	private function parseseq($payload, $partial=false)
	{
	    return parsetlv('\x30', payload, partial)
	}

	public function makeToken($ntlm_token, $type1=true)
	{
	    # NegTokenInit (rfc4178)
	    $mechlist = $this->makeseq($this->ntlm_oid);
	    $mechTypes = $this->maketlv("\xa0", $mechlist);
	    $mechToken = $this->maketlv("\xa2", $this->makeoctstr($ntlm_token));

	    # NegotiationToken (rfc4178)
	    $negTokenInit = $this->makeseq($mechTypes . $mechToken ); # + mechListMIC)
	    $innerContextToken = $this->maketlv("\xa0", $negTokenInit);

	    # MechType + innerContextToken (rfc2743)
	    $thisMech = "\x06\x06\x2b\x06\x01\x05\x05\x02"; # SPNEGO OID 1.3.6.1.5.5.2
	    $spnego = $thisMech . $innerContextToken;

	    # InitialContextToken (rfc2743)
	    $msg = $this->maketlv("\x60", $spnego);
	    return $msg;
	}

	public function extractToken($msg)
	{
		# Extract negTokenResp from NegotiationToken
		$spnego = $this->parseseq(parsetlv('\xa1', $msg))

		# Extract negState
		negState, msg = parsetlv('\xa0', $spnego, True)
		status = parseenum(negState)
		if (status != 1) {
			raise GSSAPI_Parse_Exception("Unexpected SPNEGO negotiation status (%d)." % status)
		}

		# Extract supportedMech
		supportedMech, msg = parsetlv('\xa1', msg, True)
		if (supportedMech!=ntlm_oid) {
			raise GSSAPI_Parse_Exception("Unexpected SPNEGO mechanism in GSSAPI response.")
		}

		# Extract Challenge, and forget about the rest
		token, msg = parsetlv('\xa2', msg, True)
		return parseoctstr(token)
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
		if (substr($msg, 0, 2)!='\x00\x00' || $length!=strlen($data)) {
		    throw new Exception(printf('Error while parsing Direct TCP transport Direct (%d, expected %d).',  ($length,strlen($data))));
		}
		return $data;
	}

 	private function parseSessionSetupResp($resp, &$challenge)
	{
		$smb_data = $this->removeTransport($resp);
		$hdr = substr($smb_data, 0, self::SMB_Header_Length]);
		$msg = substr($smb_data, self.SMB_Header_Length]);

		$challenge = '';

		# <I little-endian unsigned int
		$status = unpack('V', substr($hdr, 5, 9)[1];
		if ($status==0) {
		    return true;
		}
		if ($status!=0xc0000016) {
		    return false;
		}

		# User ID
		# <H little-endian unsigned short
		$this->userId = unpack('v', substr($hdr, 28, 30))[1];
		# WordCount
		$idx = 0
		if ($msg[$idx]!='\x04') {
		    throw new Exception('Incorrect WordCount');
		}
		# SecurityBlobLength
		$idx += 7;
		# <H little-endian unsigned short
		$length = unpack('v', substr($msg, $idx, $idx+2))[1];
		# Security Blob
		$idx += 4
		$blob = substr($msg, $idx, $idx+$length);
		$challenge = $this->gssapi->extractToken(blob);
		return true;
	}

	public function negotiate($data)
	{
		$msg = $this->makeNegotiateProtocolRequest($data);
		//var_dump(base64_encode($msg));

		$resp = $this->transaction($msg);
		//var_dump($resp);

		$msg = $this->makeSessionSetupRequest($data, true);
		//var_dump(base64_encode($msg));

		$resp = $this->transaction($msg);
		var_dump($resp);

		$result = $this->parse_session_setup_resp($resp, $challenge);
		if (!$result) {
		    return false;
		}
		return $challenge;
	}

	private function getTransportLength($data)
	{
		return unpack("S", substr($data, 2, 2))[1];
	}

	public function transaction($msg)
	{
		if ($this->socket==false) {
			throw new Exception("Socket has gone away");
			exit;
		}
		$sent = socket_send($this->socket, $msg, strlen($msg), 0);
		$data = socket_read($this->socket, 4);
		if ($data!==false) {
			$data .= socket_read($this->socket, $this->getTransportLength($data));
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
        	$this->userId = 0;
		$hdr = $this->createSMBHeader(self::SMB_COM_SESSION_SETUP_ANDX);

		# Start building SMB_Data, excluding ByteCount
		$data = $this->gssapi->makeToken($ntlm_token, $type1);

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
		
		if ((strlen($data)+strlen($params))%2==1) {
			$data .= "\x00";
		}
		$data .= iconv("UTF-8", "UTF-16", "PHP\0");  # NativeOS
		$data .= iconv("UTF-8", "UTF-16", "PHP\0");  # NativeLanMan

		# "<H" little endian unsigned short
		return $this->addTransport($hdr.$params.pack("v", strlen($data)).$data);
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
if (empty($_SERVER["REDIRECT_HTTP_AUTHORIZATION"])){
	header("HTTP/1.1 401 Unauthorized");
	header("WWW-Authenticate: NTLM");
	exit;
}
$auth = $_SERVER["REDIRECT_HTTP_AUTHORIZATION"];
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

