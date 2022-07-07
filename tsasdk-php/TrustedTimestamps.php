<?php

class TrustedTimestamps
{
    /**
     * 生成时间戳请求
     *
     * @param string $hash : The hashed data
     * @param string $hash_algo
     * @return string: 时间戳请求文件
     * @throws Exception
     */
    public static function createRequestfile($hash, $hash_algo = 'sha1')
    {
        if (strlen($hash) !== 40 && $hash_algo === 'sha1') {
            throw new Exception("Invalid Hash.");
        }
            
        $outfilepath = self::createTempFile();
        $cmd = "openssl ts -query -digest ".escapeshellarg($hash);
        if ($hash_algo !== 'sha1') {
            $cmd .= " -".addslashes($hash_algo);
        }
        $cmd .= " -cert -out ".escapeshellarg($outfilepath);

        $retarray = array();
        exec($cmd." 2>&1", $retarray, $retcode);

        if ($retcode !== 0) {
            throw new Exception("OpenSSL does not seem to be installed: ".implode(", ", $retarray));
        }
        
        if (isset($retarray[0]) && stripos($retarray[0], "openssl:Error") !== false) {
            throw new Exception("There was an error with OpenSSL. Is version >= 0.99 installed?: ".implode(", ", $retarray));
        }

        return $outfilepath;
    }

    /**
     * Signs a timestamp requestfile at a TSA using CURL
     *
     * @param string $requestfile_path : 时间戳请求文件
     * @param string $tsa_url : 时间戳服务地址
     * @return 时间戳证书
     * @throws Exception
     */
    public static function signRequestfile($requestFile_path, $tsa_url, array $curlOpts = array())
    {
        
		$outfilepath = self::createTempFile();
		if (!file_exists($requestFile_path)) {
            throw new Exception("The Requestfile was not found");
        }

        $curlOpts += array(
            CURLOPT_URL => $tsa_url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_POST => 1,
            CURLOPT_BINARYTRANSFER => 1,
            CURLOPT_POSTFIELDS => file_get_contents($requestFile_path),
            CURLOPT_HTTPHEADER => array('Content-Type: application/timestamp-query'),
            CURLOPT_USERAGENT => "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)",
        );

        $ch = curl_init();
        foreach ($curlOpts as $option => $value) {
            curl_setopt($ch, $option, $value);
        }
        $binary_response_string = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($status != 200 || !strlen($binary_response_string)) {
            throw new Exception("The request failed");
        }
        


        $responsefile = self::createTempFile($binary_response_string);
        $cmd = "openssl ts -reply -in ".escapeshellarg($responsefile)." -out ".escapeshellarg($outfilepath)." -token_out";
        $retarray = array();
        exec($cmd." 2>&1", $retarray, $retcode);
        
        if ($retcode !== 0) {
            throw new Exception("The reply failed: ".implode(", ", $retarray));
        }
		
		
		return file_get_contents($outfilepath);
    }

    /**
     * Extracts the unix timestamp from the base64-encoded response string as returned by signRequestfile
     *
     * @param string $base64_response_string : Response string as returned by signRequestfile
     * @param null|string $timestamp_format
     * @return int: unix timestamp
     * @throws Exception
     */
    public static function getTimestampFromAnswer($base64_response_string, $timestamp_format = null)
    {
        $binary_response_string = base64_decode($base64_response_string);

        $responsefile = self::createTempFile($binary_response_string);
		//print_r($responsefile);
        $cmd = "openssl ts -reply -in ".escapeshellarg($responsefile)." -out test.tsa -token_out";
        $retarray = array();
        exec($cmd." 2>&1", $retarray, $retcode);
        
        if ($retcode !== 0) {
            throw new Exception("The reply failed: ".implode(", ", $retarray));
        }
    }


    /**
     * Create a tempfile in the systems temp path
     *
     * @param string $str : Content which should be written to the newly created tempfile
     * @return string: filepath of the created tempfile
     * @throws Exception
     */
    public static function createTempFile($str = "")
    {
        $tempfilename = tempnam(sys_get_temp_dir(), rand());

        if (!file_exists($tempfilename)) {
            throw new Exception("Tempfile could not be created");
        }
            
        if (!empty($str) && !file_put_contents($tempfilename, $str)) {
            throw new Exception("Could not write to tempfile");
        }

        return $tempfilename;
    }
}
