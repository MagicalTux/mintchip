<?php
/*
 * File: mintchip_create.php 
 * Date: 20/11/11
 * 
 * mintchip_create - Create a MintChip request message
 * 
 * Description: string mintchip_create(array $mintchip_request)
 * 
 * Parameters:
 * 		string: An MintChip Request Array as formatted below.
 * 
 * Notes: Be aware of length constraints and binary string datatype.
 * 
 * 		An MintChip Request:
 * 			Array
 *			(
 *			    [version] =>
 *			    [annotation] =>
 *			    [vm-req] => Array
 *			        (
 *			            [payee-id] =>
 *			            [currency] =>
 *			            [value] =>
 *			            [include-cert] =>
 *			            [response-url] =>
 *			            [challenge] =>
 *			        )
 *
 *			)
 *
 */

function writeTLV($Tag,$data)
{
	$dataLen = mb_strlen($data);
	
	if ($dataLen > 127) {
		$binStr = decbin($dataLen);
			
		$binStrLen = strlen($binStr);
		$r = $binStrLen % 8;
		$a = 8 - $r;
		$binStr = str_pad($binStr, ($binStrLen+$a), "0", STR_PAD_LEFT);
				
		$numOfBytes = strlen($binStr)/8;
		
		$Length = chr($numOfBytes)^ chr(128);
		for($i=0; $i < $numOfBytes; $i ++){
			$Length = $Length . chr(bindec(substr($binStr, ($i*8) , 8)));
		}
		
	
	} else {
		$Length = chr($dataLen);
	}
	
	return $Tag . $Length . $data;
}

function mintchip_create($mintchipAttributes){
	
	if(isset($mintchipAttributes["vm-req"])) {
		
		//Write payee-id
		$payeeidTLV = writeTLV(chr(0x04), $mintchipAttributes["vm-req"]["payee-id"]);
		
		//Write currency
		$currencyTLV = writeTLV(chr(0x04), $mintchipAttributes["vm-req"]["currency"]);
		
		//Write value
		$valueTLV = writeTLV(chr(0x04), $mintchipAttributes["vm-req"]["value"]);
		
		//Write include-cert
		$includecertTLV = writeTLV(chr(0x01), $mintchipAttributes["vm-req"]["include-cert"]);
		
		//Write response-url
		$responseurlTLV = writeTLV(chr(0x16), $mintchipAttributes["vm-req"]["response-url"]);
		
		$reqData = $payeeidTLV . $currencyTLV .  $valueTLV. $includecertTLV . $responseurlTLV;
		
		//Write challenge
		if(isset($mintchipAttributes["vm-req"]["challenge"])) {
			$challengeTLV = writeTLV(chr(0x80), $mintchipAttributes["vm-req"]["challenge"]);
			$reqData = $reqData . $challengeTLV;
		}
		
		//Write ValueMessageRequest
		$ValueMessageRequestTLV = writeTLV(chr(0x30), $reqData);
		$vmreqTLV = writeTLV(chr(0xA1), $ValueMessageRequestTLV);
		$packetTLV = writeTLV(chr(0xA2), $vmreqTLV);
		
		$versionTLV = writeTLV(chr(0x0A), $mintchipAttributes["version"]);
		$versionTLV = writeTLV(chr(0xA0), $versionTLV);
		
		if(isset($mintchipAttributes["annotation"])) {
			$annotationTLV = writeTLV(chr(0x16), $mintchipAttributes["annotation"]);
			$annotationTLV = writeTLV(chr(0xA1), $annotationTLV);
			//Write Message Packet Sequence
			$MessagePacketTLV = writeTLV(chr(0x30), ($versionTLV . $annotationTLV . $packetTLV ));
		} else {
			//Write Message Packet Sequence
			$MessagePacketTLV = writeTLV(chr(0x30), ($versionTLV . $packetTLV));
		}
				
		//Write Message Packet Application
		$mintchipreq = writeTLV(chr(0x60), $MessagePacketTLV);
		//return $mintchipreq;
		return base64_encode($mintchipreq);
	}
	
	
}

// Uncomment below to test

/*
$mintchipreqArray = array();
$mintchipreqArray["version"] = chr(0x01);
$mintchipreqArray["annotation"] = "Created with PHP";
$mintchipreqArray["vm-req"]["payee-id"] = pack("H*" , "1111222233334444");
$mintchipreqArray["vm-req"]["currency"] = chr(0x01);
$value = str_pad(dechex(intval("522")), 6 , "0", STR_PAD_LEFT);
$mintchipreqArray["vm-req"]["value"] = pack("H*" , $value);
$mintchipreqArray["vm-req"]["include-cert"] = chr(0xFF);
$mintchipreqArray["vm-req"]["response-url"] = "http://www.google.com";
$mintchipreqArray["vm-req"]["challenge"] = pack("H*" , "11223344");

echo mintchip_create($mintchipreqArray) . "<br />";

*/
?>