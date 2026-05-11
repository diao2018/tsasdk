<?php

class TrustedTimestamps
{
    /**
     * Supported hash algorithms
     */
    const ALGO_SHA1   = 'sha1';
    const ALGO_SHA256 = 'sha256';
    const ALGO_SHA384 = 'sha384';
    const ALGO_SHA512 = 'sha512';
    const ALGO_SM3    = 'sm3';

    /**
     * Map of algorithm name to expected hash length (hex chars)
     */
    private static $algoLengths = array(
        'sha1'   => 40,
        'sha256' => 64,
        'sha384' => 96,
        'sha512' => 128,
        'sm3'    => 64,
    );

    /**
     * 生成时间戳请求
     *
     * @param string $hash : The hashed data
     * @param string $hash_algo : Hash algorithm (sha1, sha256, sha384, sha512, sm3)
     * @return string: 时间戳请求文件
     * @throws Exception
     */
    public static function createRequestfile($hash, $hash_algo = 'sha1')
    {
        $algo = strtolower($hash_algo);

        // Validate hash length
        if (isset(self::$algoLengths[$algo]) && strlen($hash) !== self::$algoLengths[$algo]) {
            throw new Exception("Invalid hash length for {$algo}. Expected " . self::$algoLengths[$algo] . " hex chars, got " . strlen($hash));
        }

        $outfilepath = self::createTempFile();
        $cmd = "openssl ts -query -digest " . escapeshellarg($hash);
        if ($algo !== 'sha1') {
            $cmd .= " -" . self::escapeAlgo($algo);
        }
        $cmd .= " -cert -out " . escapeshellarg($outfilepath);

        $retarray = array();
        exec($cmd . " 2>&1", $retarray, $retcode);

        if ($retcode !== 0) {
            throw new Exception("OpenSSL does not seem to be installed: " . implode(", ", $retarray));
        }

        if (isset($retarray[0]) && stripos($retarray[0], "openssl:Error") !== false) {
            throw new Exception("There was an error with OpenSSL. Is version >= 0.99 installed?: " . implode(", ", $retarray));
        }

        return $outfilepath;
    }

    /**
     * Signs a timestamp requestfile at a TSA using CURL
     *
     * @param string $requestFile_path : 时间戳请求文件
     * @param string $tsa_url : 时间戳服务地址
     * @param string $tsa_username : TSA username (optional)
     * @param string $tsa_password : TSA password (optional)
     * @param array $curlOpts : Additional cURL options
     * @return string: 时间戳令牌
     * @throws Exception
     */
    public static function signRequestfile($requestFile_path, $tsa_url, $tsa_username = '', $tsa_password = '', array $curlOpts = array())
    {
        if (is_array($tsa_username)) {
            $curlOpts = $tsa_username;
            $tsa_username = '';
            $tsa_password = '';
        }

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
        );

        if (!empty($tsa_username) && !empty($tsa_password)) {
            $curlOpts[CURLOPT_USERPWD] = $tsa_username . ':' . $tsa_password;
        }

        $ch = curl_init();
        foreach ($curlOpts as $option => $value) {
            curl_setopt($ch, $option, $value);
        }
        $binary_response_string = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($status != 200 || !strlen($binary_response_string)) {
            throw new Exception("The request failed (HTTP {$status}): " . $curl_error);
        }

        $responsefile = self::createTempFile($binary_response_string);
        $cmd = "openssl ts -reply -in " . escapeshellarg($responsefile) . " -out " . escapeshellarg($outfilepath) . " -token_out";
        $retarray = array();
        exec($cmd . " 2>&1", $retarray, $retcode);

        self::cleanupTempFile($responsefile);

        if ($retcode !== 0) {
            throw new Exception("The reply failed: " . implode(", ", $retarray));
        }

        $result = file_get_contents($outfilepath);
        self::cleanupTempFile($outfilepath);

        return $result;
    }

    /**
     * Extracts the unix timestamp from the base64-encoded response string as returned by signRequestfile
     *
     * @param string $base64_response_string : Response string as returned by signRequestfile
     * @param string|null $timestamp_format : Output format (null for unix timestamp, or date format string)
     * @return int|string: unix timestamp or formatted date string
     * @throws Exception
     */
    public static function getTimestampFromAnswer($base64_response_string, $timestamp_format = null)
    {
        $binary_response_string = base64_decode($base64_response_string);

        $responsefile = self::createTempFile($binary_response_string);
        $textoutfile = self::createTempFile();

        $cmd = "openssl ts -reply -in " . escapeshellarg($responsefile) . " -text_out " . escapeshellarg($textoutfile);
        $retarray = array();
        exec($cmd . " 2>&1", $retarray, $retcode);

        self::cleanupTempFile($responsefile);

        if ($retcode !== 0) {
            throw new Exception("The reply failed: " . implode(", ", $retarray));
        }

        $text = file_get_contents($textoutfile);
        self::cleanupTempFile($textoutfile);

        // Parse the time from the text output
        if (preg_match('/Time\s*stamp:\s*(.+)/i', $text, $matches)) {
            $timeStr = trim($matches[1]);
            $timestamp = strtotime($timeStr);
            if ($timestamp === false) {
                throw new Exception("Failed to parse timestamp: " . $timeStr);
            }
            if ($timestamp_format !== null) {
                return date($timestamp_format, $timestamp);
            }
            return $timestamp;
        }

        throw new Exception("Could not extract timestamp from response");
    }

    /**
     * Compute hash for data using the specified algorithm
     *
     * @param string $data : Data to hash
     * @param string $algo : Hash algorithm (sha1, sha256, sha384, sha512, sm3)
     * @return string: Hex-encoded hash
     * @throws Exception
     */
    public static function hash($data, $algo = 'sha256')
    {
        $algo = strtolower($algo);
        if ($algo === 'sm3') {
            // SM3 requires OpenSSL 1.1.1+
            $dataFile = self::createTempFile($data);
            try {
                $cmd = "openssl dgst -sm3 -hex " . escapeshellarg($dataFile);
                $retarray = array();
                exec($cmd . " 2>&1", $retarray, $retcode);
                if ($retcode !== 0) {
                    throw new Exception("SM3 digest failed (requires OpenSSL 1.1.1+): " . implode(", ", $retarray));
                }
                if (preg_match('/=\s*([a-f0-9]+)$/i', implode("\n", $retarray), $matches)) {
                    return $matches[1];
                }
                throw new Exception("Failed to parse SM3 digest output");
            } finally {
                self::cleanupTempFile($dataFile);
            }
        }

        if (!in_array($algo, array('sha1', 'sha256', 'sha384', 'sha512'))) {
            throw new Exception("Unsupported hash algorithm: " . $algo);
        }

        return hash($algo, $data);
    }

    /**
     * Compute hash for a file using the specified algorithm
     *
     * @param string $filepath : Path to file
     * @param string $algo : Hash algorithm
     * @return string: Hex-encoded hash
     * @throws Exception
     */
    public static function hashFile($filepath, $algo = 'sha256')
    {
        $algo = strtolower($algo);
        if ($algo === 'sm3') {
            $cmd = "openssl dgst -sm3 -hex " . escapeshellarg($filepath);
            $retarray = array();
            exec($cmd . " 2>&1", $retarray, $retcode);
            if ($retcode !== 0) {
                throw new Exception("SM3 digest failed (requires OpenSSL 1.1.1+): " . implode(", ", $retarray));
            }
            if (preg_match('/=\s*([a-f0-9]+)$/i', implode("\n", $retarray), $matches)) {
                return $matches[1];
            }
            throw new Exception("Failed to parse SM3 digest output");
        }

        if (!in_array($algo, array('sha1', 'sha256', 'sha384', 'sha512'))) {
            throw new Exception("Unsupported hash algorithm: " . $algo);
        }

        return hash_file($algo, $filepath);
    }

    /**
     * Escape algorithm name for OpenSSL CLI (whitelist approach)
     */
    private static function escapeAlgo($algo)
    {
        $allowed = array('sha1', 'sha256', 'sha384', 'sha512', 'sm3');
        if (!in_array($algo, $allowed)) {
            throw new Exception("Unsupported hash algorithm: " . $algo);
        }
        return $algo;
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
        $tempfilename = tempnam(sys_get_temp_dir(), "tsasdk_");

        if (!file_exists($tempfilename)) {
            throw new Exception("Tempfile could not be created");
        }

        if ($str !== "" && file_put_contents($tempfilename, $str) === false) {
            throw new Exception("Could not write to tempfile");
        }

        return $tempfilename;
    }

    /**
     * Cleanup a temporary file
     *
     * @param string $filepath
     */
    private static function cleanupTempFile($filepath)
    {
        if (file_exists($filepath)) {
            @unlink($filepath);
        }
    }
}
