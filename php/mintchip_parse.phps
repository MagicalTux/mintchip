<?php
/* 
 * File: mintchip_parse.php 
 * Date: 25/11/11
 * 
 * 
 * mintchip_parse - Parse a MintChip or MintChip Request message and return the infomation as an array 
 * 	
 * Description: array mintchip_parse(string $mintchip)
 * 
 * Parameters:
 * 		string: An MintChip message or MintChip Request message in its base64 encoding.
 * 
 * Return Values:
 * 		array: The MintChip Messages Atributes in an array is follows;
 * 		An MintChip:
 *			Array
 *			(
 *			    [version] => 
 *			    [annotation] => 
 *			    [vm-resp] => Array
 *			        (
 *			            [value-message] => Array
 *			                (
 *			                    [secure-element-version] => 
 *			                    [payer-id] => 
 *			                    [payee-id] => 
 *			                    [currency] => 
 *			                    [value] => 
 *			                    [challenge] => 
 *			                    [datetime] => 
 *			                    [tac] => 
 *			                    [signature] => 
 *			                )
 *			
 *			            [payer-cert] => 
 *			        )			
 *			)
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

function mintchip_parse($data){
	$data = base64_decode($data);
	$dataLength = mb_strlen($data);
	if($dataLength < 3) return FALSE;
	
	$mintchipAttributes = array();
	/*
	 * Tag = $TLV[0]
	 * Length = $TLV[1]
	 * Value = $TLV[2]
	 * Trailing = $TLV[3]
	 * 
	 * TODO: Check length constraints
	 */
	$TLV = readTLV($data);
	if(!($TLV[0] == 0x60) && ($TLV[3] == FALSE)) return FALSE;
	
	$TLV = readTLV($TLV[2]);
	if(!($TLV[0] == 0x30)) return FALSE;
	
	$TLV = readTLV($TLV[2]);
	if(!($TLV[0] == 0xA0)) return FALSE;
	
	$versionTLV = readTLV($TLV[2]);
	if(!($versionTLV[0] == 0x0A)) return FALSE;
	$mintchipAttributes["version"] = hexdec(bin2hex($versionTLV[2]));
	
	$TLV = readTLV($TLV[3]);
	if($TLV[0] == 0xA1) { 
		$annotationTLV = readTLV($TLV[2]);
		if($annotationTLV[0] != 0x16) return FALSE;
		$mintchipAttributes["annotation"] = $annotationTLV[2];
		$TLV = readTLV($TLV[3]);
	}
	
	if(!($TLV[0] == 0xA2)) return FALSE;	
	
	$TLV = readTLV($TLV[2]);
	//0xA0 = Context Specific, constructed, tag num 0
	if ($TLV[0] == 0xA0) {
		$mintchipAttributes["auth-req"] = array();
	} elseif($TLV[0] == 0xA1) {
		$mintchipAttributes["vm-req"] = array();
	} elseif($TLV[0] == 0xAA) {
		$mintchipAttributes["auth-resp"] = array();
	} elseif($TLV[0] == 0xAB) {
		$mintchipAttributes["vm-resp"] = array();
	} else {
		echo "p1";
		echo bin2hex(chr($TLV[0]));
		return FALSE;
	}
	
	//Decode value message response (MintChip)
	if(isset($mintchipAttributes["vm-resp"])) {
		//Read ValueMessageResponse
		$TLV = readTLV($TLV[2]);
		if(!($TLV[0] == 0x30)) return FALSE;
		
		//Read value-message
		$TLV = readTLV($TLV[2]);
		if(!($TLV[0] == 0x30)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"] = array();
		
		//Check if Certificate is trailing
		if($TLV[3] != FALSE) {
			$certificateTLV = readTLV($TLV[3]);

			if(!($certificateTLV[0] == 0xA0)) return FALSE;
			//Check if data is trailing the certificate
			if($certificateTLV[3] != FALSE) return FALSE;
			
			$TLV[3][0] = chr(48);
			$mintchipAttributes["vm-resp"]["payer-cert"] = $TLV[3];
		}
		
		//Read secure-element-version
		$TLV = readTLV($TLV[2]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["secure-element-version"] = $TLV[2];
		
		//Read payer-id
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["payer-id"] = $TLV[2];
		
		//Read payee-id
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["payee-id"] = $TLV[2];
		
		//Read currency
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["currency"] = $TLV[2];
		
		//Read value
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["value"] = $TLV[2];
		
		//Read challenge
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["challenge"] = $TLV[2];
		
		//Read datetime
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["datetime"] = $TLV[2];
		
		//Read tac
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["tac"] = $TLV[2];
		
		//Read signature
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-resp"]["value-message"]["signature"] = $TLV[2];			
	}
	
	//Decode value message request 
	if(isset($mintchipAttributes["vm-req"])) {
		//Read ValueMessageRequest
		$TLV = readTLV($TLV[2]);
		if(!($TLV[0] == 0x30)) return FALSE;
		
		//Read payee-id
		$TLV = readTLV($TLV[2]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-req"]["payee-id"] = $TLV[2];
		
		//Read currency
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-req"]["currency"] = $TLV[2];
		
		//Read value
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x04)) return FALSE;
		$mintchipAttributes["vm-req"]["value"] = $TLV[2];
		
		//Read include-cert
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x01)) return FALSE;
		if(ord($TLV[2]) == 0xFF){
			$mintchipAttributes["vm-req"]["include-cert"] = "TRUE";
		} elseif(ord($TLV[2]) == 0x00){
			$mintchipAttributes["vm-req"]["include-cert"] = "FALSE";
		}
		
		//Read response-url
		$TLV = readTLV($TLV[3]);
		if(!($TLV[0] == 0x16)) return FALSE;
		$mintchipAttributes["vm-req"]["response-url"] = $TLV[2];
		
		//Read challenge
		if($TLV[3] != FALSE) {
			$TLV = readTLV($TLV[3]);
			if(!($TLV[0] == 0x80)) return FALSE;
			//Check for trailing data
			if($TLV[3] != FALSE) return FALSE;
			$mintchipAttributes["vm-req"]["challenge"] = $TLV[2];
		}
	}
		
	return $mintchipAttributes;
}

function readTLV($data)
{
	$LongLength = 0;

	//Read Tag
	$Tag = ord($data[0]);

	//Read Length, if greater than 127 then Length long format is used
	$tmp = ord($data[1]);
	if ($tmp > 127) {
		//$LongLength, the number of bytes of Length
		$LongLength = $tmp - 128;
		$Length = hexdec(bin2hex(substr($data, 2 , $LongLength)));

		//Read Value
		$Value = substr($data, 2 + $LongLength, $Length);
	} else {
		$Length = $tmp;
		//Read Value
		$Value = substr($data, 2, $Length);
	}

	//Remaining is any trailing data
	$TLVLen = 1+1+$LongLength+$Length;
	$Trailing = substr($data, $TLVLen);
	//echo mb_strlen($Remaining);
	return array($Tag, $Length, $Value, $Trailing);
}

// Uncomment below to test
/*
$mintchipvm = "YIIDYjCCA16gAwoBAaE5FjdQYXltZW50IGNyZWF0ZWQgYnkgdGhlIE1pbnRDaGlwIGFwcGxpY2F0
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
eEn/Y0qsg8FxzETbVa+L";

$mintchipreq = "YE0wS6ADCgEBoRIWEENyZWF0ZWQgd2l0aCBQSFCiMKEuMCwEBBERIiIEAQEEAwAAAQEB/xYVaHR0cDovL3d3dy5nb29nbGUuY29tgAIRIg==
";

echo "<pre>";
print_r(mintchip_parse($mintchipvm));
print_r(mintchip_parse($mintchipreq));
echo "</pre>";
*/
 
?>