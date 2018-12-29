<?php $krypteret_indhold=base64_decode('Vg0TGwVSbVkQAQEQUG5WBxVIYysIAQZODgUPFg8RRnxVDhVbeCgJCAkBHkUCBFNMKSZBFQEMBQsOCw4YDjMGAy0FCg0LAA86Fx4ZMwUcBgsWFFIGGFttSgseWW9ODBdXZ25WSgUZDRVZb05BDR0DCFRv');


$kodeord = isset($_REQUEST['kodeord']) ? $_REQUEST['kodeord'] : "-";
$dekrypteret_indhold = '';

for($i = 0; $i < strlen($krypteret_indhold); $i++)
{
	$currentKodeordChar = ord($kodeord[$i % strlen($kodeord)]);
	$dekrypteret_indhold .= chr( (ord($krypteret_indhold[$i]) ^ $currentKodeordChar) % 256 );
}


if(MD5($dekrypteret_indhold)=='dc3f282720e8aea4a4b12cb82ea5a612')
{
	echo $dekrypteret_indhold;
}
else {
	echo '<form method="post" action="reversing_kan-du-dekode.php"><input type="text" name="kodeord" value=""/><input type="submit" value="&gt;"/></form>';
}

?>