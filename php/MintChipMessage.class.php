<?php

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

	const CURRENCY_CHF = 0;
	const CURRENCY_CAD = 1;
	const CURRENCY_USD = 2;
	const CURRENCY_EUR = 3;
	const CURRENCY_GBP = 4;
	const CURRENCY_JPY = 5;
	const CURRENCY_AUD = 6;
	const CURRENCY_INR = 7;
	const CURRENCY_RUB = 8;

	public function __construct() {
	}

	public function initVmReq($payee, $amount, $currency, $response_url, $include_cert = true) {
		$this->version = 1;
		$this->annotation = null;
		$this->type = self::TYPE_VM_REQ;
		$this->attrs = array(
			'vm-req' => array(
				'payee-id' => pack('H*', $payee),
				'currency' => chr($currency),
				'value' => substr(pack('N', $amount*100), 1), // big endian?
				'include-cert' => $include_cert,
				'response-url' => $response_url,
			),
		);
	}

	public function getVmReqValue() {
		if ($this->type != self::TYPE_VM_REQ) throw new \Exception('Cannot use this method on this message');
		list(,$value) = unpack('N', "\0".$this->attrs['vm-req']['value']);
		return $value / 100;
	}

	public function setAnnotation($msg) {
		$this->annotation = $msg;
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

	public function getPayerCert() {
		if ($this->type != self::TYPE_VM_RESP) throw new \Exception('Not a VM resp');
		if (!isset($this->attrs['vm-resp']['payer-cert'])) throw new \Exception('No payer certificate found');

		$cert_info = openssl_x509_read(self::der2pem($this->attrs['vm-resp']['payer-cert']));
		return $cert_info;
	}

	public function validatePayerCert() {
		// code from http://developer.mintchipchallenge.com/devguide/developing/common/message-validation.html
		$cert = $this->getPayerCert();
		$pubkey = openssl_pkey_get_public($cert);

		$CA = array('../cert/RCMSS0.pem', '../cert/RCMSS1.pem', '../cert/RCMSS2.pem');
		$res = openssl_x509_checkpurpose(openssl_x509_parse($cert), X509_PURPOSE_ANY, $CA);
		if (!$res) throw new \Exception('Invalid certificate found');

		$signature = $this->attrs['vm-resp']['value-message']['signature'];

		$fields = array(
			'secure-element-version', 'payer-id', 'payee-id', 'currency',
			'value', 'challenge', 'datetime', 'tac',
		);

		$VTMPF = '';
		foreach($fields as $f) $VTMPF .= $this->attrs['vm-resp']['value-message'][$f];

		$ok = openssl_verify($VTMPF, $signature, $pubkey);
		if (!$ok) throw new \Exception('Invalid signature, message rejected');

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

		$has_cert = false;

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
			$has_cert = true;
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

		if ($has_cert) $this->validatePayerCert();

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

	private static function der2pem($data) {
		$res = "-----BEGIN CERTIFICATE-----\r\n".chunk_split(base64_encode($data))."-----END CERTIFICATE-----\r\n";
		return $res;
	}

	public function export() {
		// product output format
		switch($this->type) {
			case self::TYPE_VM_REQ: return $this->_export_vm_req();
			default:
				throw new \Exception('Unsupported format or uninitialized message');
		}
	}

	private function writeTLV($tag, $data) {
		$len = strlen($data);

		if ($len > 127) {
			$len_hex = dechex($len);
			if (strlen($len_hex) % 1) $len_hex = '0'.$len_hex;
			$len_len = strlen($len_hex)/2;
			$len_bin = chr(0x80 | $len_len) . pack('H*', $len_hex);
		} else {
			$len_bin = chr($len);
		}
		return chr($tag).$len_bin.$data;
	}

	private function _export_vm_req() {
		// Decode value message request

		$data_list = array(
			'payee-id' => 0x04,
			'currency' => 0x04,
			'value' => 0x04,
			'include-cert' => 0x01,
			'response-url' => 0x16,
		);

		$tlv_attrs = '';

		foreach($data_list as $tmp => $tmp_id) {
			$value = $this->attrs['vm-req'][$tmp];
			if (($tmp_id == 0x01) && (is_bool($value))) { // BOOL
				$value = chr($value ? 0xff : 0x00);
			}
			$tlv_attrs .= $this->writeTLV($tmp_id, $value);
		}

		if (isset($this->attrs['vm-req']['challenge'])) {
			$tlv_attrs .= $this->writeTLV(0x80, $this->attrs['vm-req']['challenge']);
		}

		// Write ValueMessageRequest
		$vm_req = $this->writeTLV(0x30, $tlv_attrs);
		$vm_req_tlv = $this->writeTLV(0xa1, $vm_req);
		$packet_tlv = $this->writeTLV(0xa2, $vm_req_tlv);

		$version_tlv = $this->writeTLV(0x0a, chr($this->version)); // TODO: support >255
		$version_tlv = $this->writeTLV(0xa0, $version_tlv);

		if (!is_null($this->annotation)) {
			$annotation_tlv = $this->writeTLV(0x16, $this->annotation);
			$annotation_tlv = $this->writeTLV(0xa1, $annotation_tlv);

			$message_packet = $this->writeTLV(0x30, $version_tlv . $annotation_tlv . $packet_tlv);
		} else {
			$message_packet = $this->writeTLV(0x30, $version_tlv . $packet_tlv);
		}

		$mintchipreq = $this->writeTLV(0x60, $message_packet);

		return base64_encode($mintchipreq);
	}
}

