<?php
include_once('TrustedTimestamps.php');

// SHA-256 demo
$TSA_URL = 'http://test1.tsa.cn/tsa';
$TSA_USERNAME = 'tsademo';
$TSA_PASSWORD = 'tsademo';

$sha256 = hash('sha256', 'hello tsa');
echo "SHA-256 hash: " . $sha256 . "\n";
$requestFile = TrustedTimestamps::createRequestfile($sha256, 'sha256');
$signature = TrustedTimestamps::signRequestfile($requestFile, $TSA_URL, $TSA_USERNAME, $TSA_PASSWORD);
echo "SHA-256 signature length: " . strlen($signature) . "\n";

// SM3 demo
echo "\n--- SM3 Demo ---\n";
$sm3 = TrustedTimestamps::hash('hello tsa sm3', 'sm3');
echo "SM3 hash: " . $sm3 . "\n";
$sm3RequestFile = TrustedTimestamps::createRequestfile($sm3, 'sm3');
$sm3Signature = TrustedTimestamps::signRequestfile($sm3RequestFile, $TSA_URL, $TSA_USERNAME, $TSA_PASSWORD);
echo "SM3 signature length: " . strlen($sm3Signature) . "\n";
