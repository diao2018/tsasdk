<?php
include_once('TrustedTimestamps.php');

$TSA_URL = 'http://tsademo:tsademo@test1.tsa.cn/tsa';
$sha256 = hash_file('sha256', 'test.txt');
//echo $sha256 ;
$requestFile = TrustedTimestamps::createRequestfile($sha256, 'sha256');
$signature = TrustedTimestamps::signRequestfile($requestFile, $TSA_URL);
print_r($signature);

?>