<?php

$msg = new MintChipMessage();
$msg->parse('YE0wS6ADCgEBoRIWEENyZWF0ZWQgd2l0aCBQSFCiMKEuMCwEBBERIiIEAQEEAwAAAQEB/xYVaHR0cDovL3d3dy5nb29nbGUuY29tgAIRIg==');
var_dump($msg);
exit;
$msg->parse('YIIDYjCCA16gAwoBAaE5FjdQYXltZW50IGNyZWF0ZWQgYnkgdGhlIE1pbnRDaGlwIGFwcGxpY2F0
aW9uIGZvciBBbmRyb2lkooIDGquCAxYwggMSMIHHBAEmBAgDEAAAAAAAEwQIAxAAAAAAAAUEAQEE
AwAAMgQEAAAAAAQDGzquBBjJtYyjW71Q0haEN0PQa4Ojpno9Ghd70rEEgYAvADwwl75lBm5SG5uz
Pujgqb26cQVS5bgElI3Gmi5C95G3jwmWiQWw30tF7tHio1q5DvTMVMMOM0yQ95xVzjf/FoJSyBi7
09EOiV6GVX510T8z4KzmMlfBa1edYN38mRGn5owmDStm3cFm8nmy0hEDoKO6rcsTbvTiigCcrqVG
46CCAkQwggGtoAMCAQICAQEwDQYJKoZIhvcNAQEFBQAwbjEfMB0GA1UEAwwWU1MgQ3ljbGUgMSBT
UyBOdW1iZXIgMDEgMB4GA1UECwwXZUNvaW4gU2lnbmluZyBBdXRob3JpdHkxHDAaBgNVBAoME1Jv
eWFsIENhbmFkaWFuIE1pbnQxCzAJBgNVBAYTAkNBMB4XDTExMDkyNjE0MzEzNloXDTIxMDkyNjE0
MzEzNlowYjELMAkGA1UEBhMCQ0ExHDAaBgNVBAoME1JveWFsIENhbmFkaWFuIE1pbnQxGjAYBgNV
BAsMEWVDb2luIEFzc2V0IFN0b3JlMRkwFwYDVQQDDBAwMzEwMDAwMDAwMDAwMDEzMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQCR5GQ/ls4ciZOfDSX+er4DurI2R3ztTYRlYemRepueZkd2tXXh
z05YbxG2w3LVFEAzc6RxMdwHjPLtTqVVhHeSZISzYw7OZlR4zRb6JSUSU4xStlN2H3COk9H+7Pvk
KEZ78QHTjj+C7ycAZpfoqKX1nIiwEe6VHvcfjfqfjgE42wIDAQABMA0GCSqGSIb3DQEBBQUAA4GB
AD7e+vjbHJVT+h01TlFv34bUbCN/CxjnRWAMyC/7e40vkvmd26ZYvh/y3bij32aGy1++ndYq1Pda
sn3jgvxo9sKDiLyUK9qi++WxQ2ovh3xh9EpWLGvKi7TxHTsTDBAh4tkvGlFB5eCu3aowF9HeM++t
eEn/Y0qsg8FxzETbVa+L');

var_dump($msg);

class MintChipMessage {
	private $version = 1;
	private $annotation = null;
	private $type = 0;
	private $attrs;

	const TYPE_UNSET = 0;
	const TYPE_AUTH_REQ = 1;
	const TYPE_VM_REQ = 2;
	const TYPE_AUTH_RESP = 3;
	const TYPE_VM_RESP = 4;

	public function __construct() {
	}

	public function parse($str) {
		$str = base64_decode($str);
		if (strlen($str) < 3) throw new \Exception('Invalid MintChip Message');

		$tlv = $this->readTLV($str);
		if ($tlv[0] != 0x60) throw new \Exception('Malformed TLV packet, root should have type 0x60');
		if ($tlv[3] !== '') throw new \Exception('Malformed TLV packet, trailing data found');
		$tlv = $this->readTLV($tlv[2]);
		if ($tlv[0] != 0x30) throw new \Exception('Malformed TLV packet, first child should have type 0x30');
		if ($tlv[3] !== '') throw new \Exception('Malformed TLV packet, trailing data found');
		$tlv = $this->readTLV($tlv[2]);
		if ($tlv[0] != 0xa0) throw new \Exception('Malformed TLV packet, second child should have type 0xa0');
		$version_tlv = $this->readTLV($tlv[2]);
		if ($version_tlv[0] != 0x0a) throw new \Exception('Malformed TLV packet, version packet should have tag 0x0a');
		if ($version_tlv[3] !== '') throw new \Exception('Malformed TLV packet, trailing data found in version packet');
		$this->version = hexdec(bin2hex($version_tlv[2]));
		$tlv = $this->readTLV($tlv[3]);
		if ($tlv[0] == 0xa1) {
			// annotation
			$a_tlv = $this->readTLV($tlv[2]);
			if ($a_tlv[0] != 0x16) throw new \Exception('Malformed TLV packet, annotation packet should have tag 0x16');
			$this->annotation = $a_tlv[2];
			$tlv = $this->readTLV($tlv[3]);
		}

		if ($tlv[0] != 0xa2) throw new \Exception('Malformed TLV packet, inner packet should have tag 0xa2');
		if ($tlv[3] !== '') throw new \Exception('Malformed TLV packet, trailing data found');
		$tlv = $this->readTLV($tlv[2]);

		switch($tlv[0]) {
			case 0xa0: $this->type = self::TYPE_AUTH_REQ; break;
			case 0xa1: $this->type = self::TYPE_VM_REQ; return $this->_parse_vm_req($tlv);
			case 0xaa: $this->type = self::TYPE_AUTH_RESP; break;
			case 0xab: $this->type = self::TYPE_VM_RESP; return $this->_parse_vm_resp($tlv);
			default:
				throw new \Exception('Invalid MintChip Message type');
		}

		return true;
	}

	private function _parse_vm_req($tlv) {
		// Decode value message request

		$tlv = $this->readTLV($tlv[2]);
		if ($tlv[0] != 0x30) throw new \Exception('Malformed TLV packet, vm_req first child should have type 0x30');

		$data_list = array(
			'payee-id' => 0x04,
			'currency' => 0x04,
			'value' => 0x04,
			'include-cert' => 0x01,
			'response-url' => 0x16,
		);

		$tlv[3] = $tlv[2]; // hack for oncoming loop
		foreach($data_list as $tmp => $tmp_id) {
			$tlv = $this->readTLV($tlv[3]);
			if ($tlv[0] != $tmp_id) throw new \Exception('Malformed TLV packet, vm_req '.$tmp.' expects type '.dechex($tmp_id));
			if ($tmp_id == 0x01) { // BOOL
				switch($tlv[2]) {
					case 0xff: $tlv[2] = true; break;
					case 0x00: $tlv[2] = false; break;
				}
			}
			$this->attrs['vm-req'][$tmp] = $tlv[2];
		}

		// Read challenge
		if ($tlv[3] !== '') {
			$tlv = $this->readTLV($tlv[3]);
			if ($tlv[0] != 0x80) throw new \Exception('Malformed TLV packet, vm_req challenge expects type 0x80');
			$this->attrs['vm-req']['challenge'] = $tlv[2];
		}
		return true;
	}

	private function _parse_vm_resp($tlv) {
		// Read ValueMessageResponse
		$this->attrs['vm-resp'] = array('value-message' => array());

		$tlv = $this->readTLV($tlv[2]);
		if ($tlv[0] != 0x30) throw new \Exception('Malformed TLV packet, vm_resp first child should have type 0x30');
		$tlv = $this->readTLV($tlv[2]);
		if ($tlv[0] != 0x30) throw new \Exception('Malformed TLV packet, vm_resp second child should have type 0x30');
		
		//Check if Certificate is trailing
		if ($tlv[3] !== '') {
			$cert_tlv = $this->readTLV($tlv[3]);
			if ($cert_tlv[0] != 0xa0) throw new \Exception('Malformed TLV packet, vm_resp certificate should have type 0xa0');
			if ($cert_tlv[3] !== '') throw new \Exception('Malformed TLV packet, trailing data found after vm_resp certificate');

			$cert = $tlv[3];
			$cert[0] = chr(0x30); // god knows why
			$this->attrs['vm-resp']['payer-cert'] = $cert;
		}

		// Read data
		$data_list = array(
			'secure-element-version', 'payer-id', 'payee-id', 'currency',
			'value', 'challenge', 'datetime', 'tac', 'signature',
		);

		$tlv[3] = $tlv[2]; // hack to initialize the loop to come
		foreach($data_list as $tmp) {
			$tlv = $this->readTLV($tlv[3]);
			if ($tlv[0] != 0x04) throw new \Exception('Malformed TLV packet, vm_resp '.$tmp.' should have type 0x04');
			$this->attrs['vm-resp']['value-message'][$tmp] = $tlv[2];
		}
		if ($tlv[3] != '') throw new \Exception('Malformed TLV packet, trailing data found after vm_resp');

		return true;
	}

	private function readTLV($data) {
		$LongLength = 0;

		//Read Tag
		$Tag = ord($data[0]);

		//Read Length, if greater than 127 then Length long format is used
		$Length = ord($data[1]);
		if ($Length & 0x80) {
			//$LongLength, the number of bytes of Length
			$LongLength = $Length & 0x7f;

			// trick php into transforming arbitrary long binary integer to regular integer
			$Length = hexdec(bin2hex(substr($data, 2, $LongLength)));
		}

		$Value = substr($data, 2+$LongLength, $Length);

		//Remaining is any trailing data
		$TLVLen = 2+$LongLength+$Length;
		$Trailing = (string)substr($data, $TLVLen);

		return array($Tag, $Length, $Value, $Trailing);
	}
}

