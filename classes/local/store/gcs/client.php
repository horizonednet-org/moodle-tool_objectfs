<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Keyless Google Cloud Storage client for tool_objectfs.
 *
 * Authenticates via the GCE / Cloud Run Metadata Server (or Application Default Credentials
 * fallback) using short-lived OAuth2 access tokens against the GCS JSON REST API, with zero
 * static HMAC keys and zero object-level ACL headers (Uniform Bucket-Level Access compliant).
 *
 * @package   tool_objectfs
 * @copyright 2026 Horizon Education Network
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace tool_objectfs\local\store\gcs;

use coding_exception;
use RuntimeException;
use stdClass;
use Throwable;
use tool_objectfs\local\manager;
use tool_objectfs\local\store\object_client_base;
use tool_objectfs\local\store\signed_url;

/**
 * Google Cloud Storage client.
 */
class client extends object_client_base {
    /** @var int Threshold above which php://temp spills to disk (2 MiB). */
    public const MAX_TEMP_LIMIT = 2097152;

    /** @var int Threshold above which uploads switch from single-part media to resumable (8 MiB). */
    public const RESUMABLE_THRESHOLD = 8388608;

    /** @var int Chunk size for resumable uploads (8 MiB, multiple of 256 KiB). */
    public const CHUNK_SIZE = 8388608;

    /** @var int Maximum GCS object size (5 TiB). */
    public const MAX_UPLOAD_SIZE = 5497558138880;

    /** @var string GCS JSON REST API base URL. */
    private const GCS_API_BASE = 'https://storage.googleapis.com/storage/v1';

    /** @var string GCS Upload REST API base URL. */
    private const GCS_UPLOAD_BASE = 'https://storage.googleapis.com/upload/storage/v1';

    /** @var string GCE Metadata Server OAuth2 token endpoint. */
    private const METADATA_TOKEN_URL = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';

    /** @var string GCE Metadata Server service account email endpoint. */
    private const METADATA_EMAIL_URL = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email';

    /** @var int Refresh cached OAuth2 tokens 120 seconds before expiry. */
    private const TOKEN_EXPIRY_BUFFER = 120;

    /** @var string|null Process-cached OAuth2 access token. */
    private static ?string $cachedtoken = null;

    /** @var int Unix timestamp when $cachedtoken expires. */
    private static int $cachedtokenexpiry = 0;

    /** @var string|null Process-cached service account email for V4 URL signing. */
    private static ?string $cachedsaemail = null;

    /** @var string GCS bucket name. */
    protected string $bucket = '';

    /** @var string Normalized object key prefix (either '' or ending with '/'). */
    protected string $bucketkeyprefix = '';

    /**
     * Construct the GCS client.
     *
     * @param mixed $config
     */
    public function __construct($config) {
        $this->config = $config;
        $this->maxupload = self::MAX_UPLOAD_SIZE;

        if ($this->get_availability() && !empty($config) && is_object($config)) {
            $this->configure_from_object($config);
        } else {
            parent::__construct($config);
        }
    }

    /**
     * Populate client properties from config object.
     *
     * @param object $config
     * @return void
     */
    private function configure_from_object(object $config): void {
        $bucket = '';
        if (!empty($config->gcs_bucket)) {
            $bucket = trim((string)$config->gcs_bucket);
        } else if (!empty($config->bucket)) {
            $bucket = trim((string)$config->bucket);
        }
        $this->bucket = $bucket;

        $rawprefix = '';
        if (isset($config->gcs_key_prefix) && $config->gcs_key_prefix !== '') {
            $rawprefix = (string)$config->gcs_key_prefix;
        } else if (isset($config->prefix) && $config->prefix !== '') {
            $rawprefix = (string)$config->prefix;
        }
        $rawprefix = ltrim(trim($rawprefix), '/');
        if ($rawprefix !== '' && substr($rawprefix, -1) !== '/') {
            $rawprefix .= '/';
        }
        $this->bucketkeyprefix = $rawprefix;

        $this->expirationtime = $config->expirationtime ?? (2 * HOURSECS);
        $this->presignedminfilesize = $config->presignedminfilesize ?? 0;
        $this->enablepresignedurls = $config->enablepresignedurls ?? 0;
    }

    /**
     * Pure PHP cURL implementation requires only ext-curl.
     *
     * @return bool
     */
    public function get_availability() {
        return function_exists('curl_init');
    }

    /**
     * Serialize only non-sensitive bucket routing state.
     *
     * @return array
     */
    public function __sleep() {
        return ['bucket', 'bucketkeyprefix'];
    }

    /**
     * Re-hydrate client configuration and stream wrapper after unserialization.
     *
     * @return void
     */
    public function __wakeup() {
        $config = manager::get_objectfs_config();
        $this->config = $config;
        $this->maxupload = self::MAX_UPLOAD_SIZE;
        if (is_object($config)) {
            $this->configure_from_object($config);
        }
        if ($this->is_functional()) {
            $this->register_stream_wrapper();
        }
    }

    /**
     * Whether a target GCS bucket is configured.
     *
     * @return bool
     */
    public function is_functional(): bool {
        return $this->bucket !== '';
    }

    /**
     * Check whether client config contains required GCS settings.
     *
     * @param mixed $config
     * @return bool
     */
    public function is_configured($config) {
        if (empty($config) || !is_object($config)) {
            return false;
        }
        $bucket = !empty($config->gcs_bucket) ? trim((string)$config->gcs_bucket) :
            (!empty($config->bucket) ? trim((string)$config->bucket) : '');
        return $bucket !== '';
    }

    /**
     * Get configured bucket name.
     *
     * @return string
     */
    public function get_bucket(): string {
        return $this->bucket;
    }

    /**
     * Get normalized object key prefix.
     *
     * @return string
     */
    public function get_key_prefix(): string {
        return $this->bucketkeyprefix;
    }

    /**
     * Register the gcs:// stream wrapper.
     *
     * @return void
     */
    public function register_stream_wrapper() {
        if ($this->get_availability() && $this->is_functional()) {
            stream_wrapper::register($this);
        } else {
            parent::register_stream_wrapper();
        }
    }

    /**
     * Return gcs:// URI for a Moodle contenthash.
     *
     * @param string $contenthash
     * @return string
     */
    public function get_fullpath_from_hash($contenthash) {
        $filepath = $this->get_filepath_from_hash($contenthash);
        return 'gcs://' . $this->bucket . '/' . $this->bucketkeyprefix . $filepath;
    }

    /**
     * Return bucket-relative object key for a Moodle contenthash.
     *
     * @param string $contenthash
     * @return string
     */
    public function get_object_key_from_hash(string $contenthash): string {
        return $this->bucketkeyprefix . $this->get_filepath_from_hash($contenthash);
    }

    /**
     * Map SHA-1 contenthash to sharded path (aa/bb/aabb...).
     *
     * @param string $contenthash
     * @return string
     */
    protected function get_filepath_from_hash($contenthash): string {
        $l1 = $contenthash[0] . $contenthash[1];
        $l2 = $contenthash[2] . $contenthash[3];
        return "$l1/$l2/$contenthash";
    }

    /**
     * Delete a file via gcs:// stream wrapper or direct API.
     *
     * @param string $fullpath
     * @return bool
     */
    public function delete_file($fullpath) {
        return unlink($fullpath);
    }

    /**
     * Rename/move an external GCS object.
     *
     * @param string $currentpath
     * @param string $destinationpath
     * @return bool
     */
    public function rename_file($currentpath, $destinationpath) {
        return rename($currentpath, $destinationpath);
    }

    /**
     * Return a seekable stream context for gcs:// handles.
     *
     * @return resource
     */
    public function get_seekable_stream_context() {
        return stream_context_create([
            'gcs' => [
                'seekable' => true,
            ],
        ]);
    }

    /**
     * Verify that an uploaded object exists in GCS and matches local size/MD5.
     *
     * @param string $contenthash
     * @param string $localpath
     * @return bool
     */
    public function verify_object($contenthash, $localpath) {
        if (!$this->is_functional()) {
            return false;
        }

        try {
            $objectkey = $this->get_object_key_from_hash($contenthash);
            $meta = $this->get_object_metadata($this->bucket, $objectkey);
            if ($meta === null) {
                return false;
            }

            if (is_readable($localpath)) {
                $localsize = filesize($localpath);
                if ($localsize !== false && isset($meta['size']) && (int)$meta['size'] !== (int)$localsize) {
                    return false;
                }
                if (!empty($meta['md5Hash'])) {
                    $rawmd5 = md5_file($localpath, true);
                    if ($rawmd5 !== false && base64_encode($rawmd5) !== $meta['md5Hash']) {
                        return false;
                    }
                }
            }

            return true;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * Obtain a valid OAuth2 bearer token from GCE Metadata Server (or ADC fallback).
     *
     * @param bool $forcerefresh
     * @return string
     * @throws RuntimeException
     */
    public function get_access_token(bool $forcerefresh = false): string {
        $now = time();

        if (!$forcerefresh && self::$cachedtoken !== null && ($now + self::TOKEN_EXPIRY_BUFFER) < self::$cachedtokenexpiry) {
            return self::$cachedtoken;
        }

        $cachefile = $this->get_token_cache_path();
        if (!$forcerefresh && is_readable($cachefile)) {
            $raw = @file_get_contents($cachefile);
            if ($raw !== false) {
                $cached = json_decode($raw, true);
                if (
                    is_array($cached) &&
                    !empty($cached['access_token']) &&
                    !empty($cached['expires_at']) &&
                    ($now + self::TOKEN_EXPIRY_BUFFER) < (int)$cached['expires_at']
                ) {
                    self::$cachedtoken = (string)$cached['access_token'];
                    self::$cachedtokenexpiry = (int)$cached['expires_at'];
                    return self::$cachedtoken;
                }
            }
        }

        if ($forcerefresh) {
            self::$cachedtoken = null;
            self::$cachedtokenexpiry = 0;
            @unlink($cachefile);
        }

        $tokendata = $this->fetch_metadata_server_token();
        if ($tokendata === null) {
            $tokendata = $this->fetch_adc_token();
        }

        if ($tokendata === null || empty($tokendata['access_token'])) {
            throw new RuntimeException(
                'Unable to obtain Google Cloud OAuth2 token from GCE Metadata Server or GOOGLE_APPLICATION_CREDENTIALS.'
            );
        }

        $expiresin = isset($tokendata['expires_in']) ? max(60, (int)$tokendata['expires_in']) : 3600;
        self::$cachedtoken = (string)$tokendata['access_token'];
        self::$cachedtokenexpiry = $now + $expiresin;

        $this->write_token_cache($cachefile, self::$cachedtoken, self::$cachedtokenexpiry);

        return self::$cachedtoken;
    }

    /**
     * Path to per-UID local ephemeral token cache file.
     *
     * @return string
     */
    private function get_token_cache_path(): string {
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();
        return sys_get_temp_dir() . '/tool_objectfs_gcs_token_' . (int)$uid . '.json';
    }

    /**
     * Atomically persist token cache with 0600 permissions.
     *
     * @param string $cachefile
     * @param string $token
     * @param int $expiresat
     * @return void
     */
    private function write_token_cache(string $cachefile, string $token, int $expiresat): void {
        $tmpfile = $cachefile . '.tmp.' . getmypid() . '.' . mt_rand(1000, 9999);
        $payload = json_encode([
            'access_token' => $token,
            'expires_at' => $expiresat,
        ]);
        if ($payload === false) {
            return;
        }
        if (@file_put_contents($tmpfile, $payload, LOCK_EX) !== false) {
            @chmod($tmpfile, 0600);
            if (!@rename($tmpfile, $cachefile)) {
                @unlink($tmpfile);
            }
        }
    }

    /**
     * Query the GCE / Cloud Run metadata server for the attached SA access token.
     *
     * @return array|null
     */
    private function fetch_metadata_server_token(): ?array {
        $ch = curl_init(self::METADATA_TOKEN_URL);
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Metadata-Flavor: Google'],
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
        ]);

        $body = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $httpcode !== 200) {
            return null;
        }

        $decoded = json_decode((string)$body, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Optional fallback to Application Default Credentials JSON file if set.
     *
     * @return array|null
     */
    private function fetch_adc_token(): ?array {
        $credspath = getenv('GOOGLE_APPLICATION_CREDENTIALS');
        if (empty($credspath) || !is_readable($credspath)) {
            return null;
        }

        $creds = json_decode((string)file_get_contents($credspath), true);
        if (!is_array($creds) || empty($creds['type'])) {
            return null;
        }

        $tokenuri = $creds['token_uri'] ?? 'https://oauth2.googleapis.com/token';

        if ($creds['type'] === 'service_account' && !empty($creds['client_email']) && !empty($creds['private_key'])) {
            $now = time();
            $header = $this->base64url_encode((string)json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
            $claims = $this->base64url_encode((string)json_encode([
                'iss' => $creds['client_email'],
                'scope' => 'https://www.googleapis.com/auth/devstorage.full_control https://www.googleapis.com/auth/cloud-platform',
                'aud' => $tokenuri,
                'iat' => $now,
                'exp' => $now + 3600,
            ]));
            $signinginput = $header . '.' . $claims;
            $signature = '';
            $pkey = openssl_pkey_get_private($creds['private_key']);
            if ($pkey === false || !openssl_sign($signinginput, $signature, $pkey, OPENSSL_ALGO_SHA256)) {
                return null;
            }
            self::$cachedsaemail = (string)$creds['client_email'];
            $jwt = $signinginput . '.' . $this->base64url_encode($signature);
            $postfields = http_build_query([
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $jwt,
            ]);
        } else if (
            $creds['type'] === 'authorized_user' &&
            !empty($creds['client_id']) &&
            !empty($creds['client_secret']) &&
            !empty($creds['refresh_token'])
        ) {
            $postfields = http_build_query([
                'grant_type' => 'refresh_token',
                'client_id' => $creds['client_id'],
                'client_secret' => $creds['client_secret'],
                'refresh_token' => $creds['refresh_token'],
            ]);
        } else {
            return null;
        }

        $ch = curl_init($tokenuri);
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postfields,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 15,
        ]);
        $this->apply_proxy_options($ch);
        $body = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $httpcode !== 200) {
            return null;
        }
        $decoded = json_decode((string)$body, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Resolve attached service account email for IAM signBlob V4 signed URLs.
     *
     * @return string
     * @throws RuntimeException
     */
    private function get_service_account_email(): string {
        if (self::$cachedsaemail !== null && self::$cachedsaemail !== '') {
            return self::$cachedsaemail;
        }

        if (!empty($this->config->gcs_service_account_email)) {
            self::$cachedsaemail = trim((string)$this->config->gcs_service_account_email);
            return self::$cachedsaemail;
        }

        $ch = curl_init(self::METADATA_EMAIL_URL);
        if ($ch !== false) {
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => ['Metadata-Flavor: Google'],
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_PROXY => '',
                CURLOPT_NOPROXY => '*',
            ]);
            $body = curl_exec($ch);
            $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($body !== false && $httpcode === 200 && trim((string)$body) !== '') {
                self::$cachedsaemail = trim((string)$body);
                return self::$cachedsaemail;
            }
        }

        $credspath = getenv('GOOGLE_APPLICATION_CREDENTIALS');
        if (!empty($credspath) && is_readable($credspath)) {
            $creds = json_decode((string)file_get_contents($credspath), true);
            if (is_array($creds) && !empty($creds['client_email'])) {
                self::$cachedsaemail = trim((string)$creds['client_email']);
                return self::$cachedsaemail;
            }
        }

        throw new RuntimeException('Unable to determine Google Cloud service account email for V4 URL signing.');
    }

    /**
     * Apply optional Moodle outbound HTTP proxy settings to GCS API cURL handle.
     *
     * @param \CurlHandle $ch
     * @return void
     */
    private function apply_proxy_options($ch): void {
        global $CFG;
        if (empty($this->config->useproxy) || empty($CFG->proxyhost)) {
            return;
        }
        if (!empty($CFG->proxytype) && $CFG->proxytype === 'SOCKS5') {
            return;
        }
        curl_setopt($ch, CURLOPT_PROXY, $CFG->proxyhost);
        if (!empty($CFG->proxyport)) {
            curl_setopt($ch, CURLOPT_PROXYPORT, (int)$CFG->proxyport);
        }
        if (!empty($CFG->proxyuser) && !empty($CFG->proxypassword)) {
            curl_setopt($ch, CURLOPT_PROXYUSERPWD, $CFG->proxyuser . ':' . $CFG->proxypassword);
        }
    }

    /**
     * Execute an authenticated GCS HTTP request with automatic 401 refresh and transient retry.
     *
     * @param string $method
     * @param string $url
     * @param array $headers
     * @param string|null $body
     * @param int $timeout
     * @return array{status:int, headers:array<string,string>, body:string}
     * @throws RuntimeException
     */
    public function request(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $timeout = 120
    ): array {
        $maxattempts = 3;
        $refreshed401 = false;

        for ($attempt = 1; $attempt <= $maxattempts; $attempt++) {
            $token = $this->get_access_token(false);
            $reqheaders = array_merge(
                [
                    'Authorization: Bearer ' . $token,
                    'Expect:',
                ],
                $headers
            );

            $respheaders = [];
            $ch = curl_init($url);
            if ($ch === false) {
                throw new RuntimeException('Failed to initialize cURL handle for GCS request.');
            }

            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $reqheaders,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_HEADERFUNCTION => static function ($curl, string $headerline) use (&$respheaders): int {
                    $len = strlen($headerline);
                    $parts = explode(':', $headerline, 2);
                    if (count($parts) === 2) {
                        $respheaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                    return $len;
                },
            ]);

            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }

            $this->apply_proxy_options($ch);

            $respbody = curl_exec($ch);
            $curlerr = curl_error($ch);
            $curlerrno = curl_errno($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($respbody === false) {
                if ($attempt < $maxattempts) {
                    usleep($attempt * 250000);
                    continue;
                }
                throw new RuntimeException("GCS cURL transport error ({$curlerrno}): {$curlerr}");
            }

            if ($status === 401 && !$refreshed401) {
                $refreshed401 = true;
                $this->get_access_token(true);
                $attempt--;
                continue;
            }

            if (in_array($status, [429, 500, 502, 503, 504], true) && $attempt < $maxattempts) {
                usleep($attempt * 300000);
                continue;
            }

            return [
                'status' => $status,
                'headers' => $respheaders,
                'body' => (string)$respbody,
            ];
        }

        throw new RuntimeException('Exhausted retries communicating with Google Cloud Storage.');
    }

    /**
     * Upload a local file to GCS by Moodle contenthash (UBLA-safe, MD5-verified).
     *
     * @param string $localpath
     * @param string $contenthash
     * @param string $mimetype
     * @return void
     * @throws RuntimeException
     */
    public function upload_to_gcs(string $localpath, string $contenthash, string $mimetype = ''): void {
        if (!$this->is_functional()) {
            throw new RuntimeException('GCS client is not configured: missing bucket.');
        }
        if (!is_readable($localpath)) {
            throw new RuntimeException('Cannot open local file for reading: ' . $localpath);
        }

        $objectkey = $this->get_object_key_from_hash($contenthash);
        $this->upload_file_to_object($this->bucket, $objectkey, $localpath, $mimetype);
    }

    /**
     * Upload any local file path to an explicit GCS bucket/object key.
     *
     * @param string $bucket
     * @param string $objectkey
     * @param string $localpath
     * @param string $mimetype
     * @return array Decoded GCS object metadata
     * @throws RuntimeException
     */
    public function upload_file_to_object(
        string $bucket,
        string $objectkey,
        string $localpath,
        string $mimetype = ''
    ): array {
        $filesize = filesize($localpath);
        if ($filesize === false) {
            throw new RuntimeException('Unable to determine file size for: ' . $localpath);
        }

        $rawmd5 = md5_file($localpath, true);
        $expectedmd5 = ($rawmd5 !== false) ? base64_encode($rawmd5) : null;
        $contenttype = ($mimetype !== '') ? $mimetype : 'application/octet-stream';

        if ($filesize <= self::RESUMABLE_THRESHOLD) {
            $payload = file_get_contents($localpath);
            if ($payload === false) {
                throw new RuntimeException('Failed reading local file payload: ' . $localpath);
            }
            $url = self::GCS_UPLOAD_BASE . '/b/' . rawurlencode($bucket) .
                '/o?uploadType=media&name=' . rawurlencode($objectkey);
            $resp = $this->request(
                'POST',
                $url,
                [
                    'Content-Type: ' . $contenttype,
                    'Content-Length: ' . strlen($payload),
                ],
                $payload,
                300
            );
            if ($resp['status'] !== 200 && $resp['status'] !== 201) {
                throw new RuntimeException(
                    "GCS media upload failed for {$bucket}/{$objectkey} (HTTP {$resp['status']}): " .
                    substr($resp['body'], 0, 500)
                );
            }
            $meta = json_decode($resp['body'], true);
        } else {
            $meta = $this->upload_file_resumable($bucket, $objectkey, $localpath, $filesize, $contenttype);
        }

        if (!is_array($meta)) {
            throw new RuntimeException("GCS upload returned invalid JSON metadata for {$bucket}/{$objectkey}.");
        }

        if ($expectedmd5 !== null && !empty($meta['md5Hash']) && $meta['md5Hash'] !== $expectedmd5) {
            try {
                $this->delete_object($bucket, $objectkey);
            } catch (Throwable $ignore) {
                // Best-effort cleanup of corrupted upload.
            }
            throw new RuntimeException(
                "GCS MD5 checksum mismatch after uploading {$bucket}/{$objectkey}: expected {$expectedmd5}, got {$meta['md5Hash']}."
            );
        }

        return $meta;
    }

    /**
     * Stream a large local file (> 8 MiB) to GCS using the Resumable Upload protocol.
     *
     * @param string $bucket
     * @param string $objectkey
     * @param string $localpath
     * @param int $filesize
     * @param string $contenttype
     * @return array Decoded GCS object metadata
     * @throws RuntimeException
     */
    private function upload_file_resumable(
        string $bucket,
        string $objectkey,
        string $localpath,
        int $filesize,
        string $contenttype
    ): array {
        $initurl = self::GCS_UPLOAD_BASE . '/b/' . rawurlencode($bucket) .
            '/o?uploadType=resumable&name=' . rawurlencode($objectkey);
        $initbody = (string)json_encode([
            'name' => $objectkey,
            'contentType' => $contenttype,
        ]);

        $initresp = $this->request(
            'POST',
            $initurl,
            [
                'Content-Type: application/json; charset=UTF-8',
                'Content-Length: ' . strlen($initbody),
                'X-Upload-Content-Type: ' . $contenttype,
                'X-Upload-Content-Length: ' . $filesize,
            ],
            $initbody,
            60
        );

        if ($initresp['status'] !== 200 || empty($initresp['headers']['location'])) {
            throw new RuntimeException(
                "Failed initiating GCS resumable upload for {$bucket}/{$objectkey} (HTTP {$initresp['status']}): " .
                substr($initresp['body'], 0, 500)
            );
        }

        $sessionuri = $initresp['headers']['location'];
        $fh = fopen($localpath, 'rb');
        if ($fh === false) {
            throw new RuntimeException('Cannot open local file for resumable upload: ' . $localpath);
        }

        try {
            $offset = 0;
            while ($offset < $filesize) {
                $chunk = fread($fh, self::CHUNK_SIZE);
                if ($chunk === false || $chunk === '') {
                    throw new RuntimeException("Unexpected EOF at byte {$offset}/{$filesize} reading {$localpath}");
                }
                $chunklen = strlen($chunk);
                $rangeend = $offset + $chunklen - 1;

                $resp = $this->request(
                    'PUT',
                    $sessionuri,
                    [
                        'Content-Type: ' . $contenttype,
                        'Content-Length: ' . $chunklen,
                        "Content-Range: bytes {$offset}-{$rangeend}/{$filesize}",
                    ],
                    $chunk,
                    600
                );

                if ($resp['status'] === 308) {
                    $offset += $chunklen;
                    continue;
                }

                if ($resp['status'] === 200 || $resp['status'] === 201) {
                    $decoded = json_decode($resp['body'], true);
                    if (!is_array($decoded)) {
                        throw new RuntimeException('Invalid JSON metadata at completion of GCS resumable upload.');
                    }
                    return $decoded;
                }

                throw new RuntimeException(
                    "GCS resumable chunk failed at offset {$offset} (HTTP {$resp['status']}): " .
                    substr($resp['body'], 0, 500)
                );
            }
        } finally {
            fclose($fh);
        }

        throw new RuntimeException("GCS resumable upload finished loop without completion response for {$bucket}/{$objectkey}.");
    }

    /**
     * Upload in-memory string bytes directly to GCS.
     *
     * @param string $bucket
     * @param string $objectkey
     * @param string $content
     * @param string $contenttype
     * @return array
     * @throws RuntimeException
     */
    public function put_object_content(
        string $bucket,
        string $objectkey,
        string $content,
        string $contenttype = 'application/octet-stream'
    ): array {
        $url = self::GCS_UPLOAD_BASE . '/b/' . rawurlencode($bucket) .
            '/o?uploadType=media&name=' . rawurlencode($objectkey);
        $resp = $this->request(
            'POST',
            $url,
            [
                'Content-Type: ' . $contenttype,
                'Content-Length: ' . strlen($content),
            ],
            $content,
            120
        );
        if ($resp['status'] !== 200 && $resp['status'] !== 201) {
            throw new RuntimeException(
                "GCS put_object_content failed for {$bucket}/{$objectkey} (HTTP {$resp['status']}): " .
                substr($resp['body'], 0, 500)
            );
        }
        $decoded = json_decode($resp['body'], true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Retrieve GCS object metadata. Returns null when confirmed absent (HTTP 404).
     *
     * @param string $bucket
     * @param string $objectkey
     * @return array|null
     * @throws RuntimeException On transient, auth, or permission errors.
     */
    public function get_object_metadata(string $bucket, string $objectkey): ?array {
        $url = self::GCS_API_BASE . '/b/' . rawurlencode($bucket) . '/o/' . rawurlencode($objectkey) .
            '?fields=name,size,updated,md5Hash,etag,contentType,metadata';
        $resp = $this->request('GET', $url, [], null, 30);

        if ($resp['status'] === 404) {
            return null;
        }

        if ($resp['status'] !== 200) {
            throw new RuntimeException(
                "GCS metadata lookup failed for {$bucket}/{$objectkey} (HTTP {$resp['status']}): " .
                substr($resp['body'], 0, 300)
            );
        }

        $decoded = json_decode($resp['body'], true);
        if (!is_array($decoded)) {
            throw new RuntimeException("Malformed JSON metadata from GCS for {$bucket}/{$objectkey}.");
        }
        return $decoded;
    }

    /**
     * Download an object (or byte range) as a string.
     *
     * @param string $bucket
     * @param string $objectkey
     * @param int|null $startbyte
     * @param int|null $endbyte
     * @return string
     * @throws RuntimeException
     */
    public function download_object_bytes(
        string $bucket,
        string $objectkey,
        ?int $startbyte = null,
        ?int $endbyte = null
    ): string {
        $url = self::GCS_API_BASE . '/b/' . rawurlencode($bucket) . '/o/' . rawurlencode($objectkey) . '?alt=media';
        $headers = [];
        if ($startbyte !== null) {
            $rangespec = ($endbyte !== null) ? "bytes={$startbyte}-{$endbyte}" : "bytes={$startbyte}-";
            $headers[] = 'Range: ' . $rangespec;
        }

        $resp = $this->request('GET', $url, $headers, null, 300);
        if ($resp['status'] !== 200 && $resp['status'] !== 206) {
            throw new RuntimeException(
                "GCS media download failed for {$bucket}/{$objectkey} (HTTP {$resp['status']}): " .
                substr($resp['body'], 0, 300)
            );
        }
        return $resp['body'];
    }

    /**
     * Stream an object from GCS into a writable PHP stream resource.
     *
     * @param string $bucket
     * @param string $objectkey
     * @param resource $targetstream
     * @return bool
     * @throws RuntimeException
     */
    public function download_object_to_stream(string $bucket, string $objectkey, $targetstream): bool {
        $token = $this->get_access_token(false);
        $url = self::GCS_API_BASE . '/b/' . rawurlencode($bucket) . '/o/' . rawurlencode($objectkey) . '?alt=media';

        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('Failed to initialize cURL handle for GCS stream download.');
        }

        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token],
            CURLOPT_FILE => $targetstream,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 600,
        ]);
        $this->apply_proxy_options($ch);

        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($ok === false || ($status !== 200 && $status !== 206)) {
            throw new RuntimeException("GCS stream download failed for {$bucket}/{$objectkey} (HTTP {$status}): {$err}");
        }

        return true;
    }

    /**
     * Stream an object by Moodle contenthash directly to PHP output (for file_system::readfile).
     *
     * @param string $contenthash
     * @return bool
     */
    public function stream_object_to_output(string $contenthash): bool {
        if (!$this->is_functional()) {
            return false;
        }

        try {
            $token = $this->get_access_token(false);
            $objectkey = $this->get_object_key_from_hash($contenthash);
            $url = self::GCS_API_BASE . '/b/' . rawurlencode($this->bucket) .
                '/o/' . rawurlencode($objectkey) . '?alt=media';

            $status = 0;
            $ch = curl_init($url);
            if ($ch === false) {
                return false;
            }

            $headersok = false;
            curl_setopt_array($ch, [
                CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token],
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT => 600,
                CURLOPT_HEADERFUNCTION => static function ($curl, string $headerline) use (&$status, &$headersok): int {
                    if (preg_match('#^HTTP/\S+\s+(\d+)#', $headerline, $m)) {
                        $status = (int)$m[1];
                        $headersok = ($status === 200 || $status === 206);
                    }
                    return strlen($headerline);
                },
                CURLOPT_WRITEFUNCTION => static function ($curl, string $data) use (&$headersok): int {
                    if (!$headersok) {
                        return strlen($data);
                    }
                    echo $data;
                    return strlen($data);
                },
            ]);
            $this->apply_proxy_options($ch);

            $ok = curl_exec($ch);
            curl_close($ch);

            return ($ok !== false && $headersok);
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * Delete an object from GCS (idempotent: 204 and 404 both return true).
     *
     * @param string $bucket
     * @param string $objectkey
     * @return bool
     * @throws RuntimeException
     */
    public function delete_object(string $bucket, string $objectkey): bool {
        $url = self::GCS_API_BASE . '/b/' . rawurlencode($bucket) . '/o/' . rawurlencode($objectkey);
        $resp = $this->request('DELETE', $url, [], null, 60);
        if ($resp['status'] === 204 || $resp['status'] === 200 || $resp['status'] === 404) {
            return true;
        }
        throw new RuntimeException(
            "GCS delete failed for {$bucket}/{$objectkey} (HTTP {$resp['status']}): " .
            substr($resp['body'], 0, 300)
        );
    }

    /**
     * Copy/rewrite an object within or across GCS buckets.
     *
     * @param string $srcbucket
     * @param string $srckey
     * @param string $dstbucket
     * @param string $dstkey
     * @return bool
     * @throws RuntimeException
     */
    public function copy_object(string $srcbucket, string $srckey, string $dstbucket, string $dstkey): bool {
        $rewritetoken = null;
        do {
            $url = self::GCS_API_BASE . '/b/' . rawurlencode($srcbucket) . '/o/' . rawurlencode($srckey) .
                '/rewriteTo/b/' . rawurlencode($dstbucket) . '/o/' . rawurlencode($dstkey);
            if ($rewritetoken !== null) {
                $url .= '?rewriteToken=' . rawurlencode($rewritetoken);
            }

            $resp = $this->request(
                'POST',
                $url,
                ['Content-Type: application/json', 'Content-Length: 0'],
                '',
                120
            );
            if ($resp['status'] !== 200) {
                throw new RuntimeException(
                    "GCS rewrite failed from {$srcbucket}/{$srckey} to {$dstbucket}/{$dstkey} (HTTP {$resp['status']}): " .
                    substr($resp['body'], 0, 300)
                );
            }
            $data = json_decode($resp['body'], true);
            $done = !empty($data['done']);
            $rewritetoken = $data['rewriteToken'] ?? null;
        } while (!$done && !empty($rewritetoken));

        return true;
    }

    /**
     * Test connectivity to the configured GCS bucket using storage.objects.list (maxResults=1).
     *
     * Uses storage.objects.list rather than storage.buckets.get so that least-privilege
     * service accounts with roles/storage.objectAdmin succeed without extra bucket-metadata IAM.
     *
     * @return stdClass
     * @throws coding_exception
     */
    public function test_connection() {
        $connection = new stdClass();
        $connection->success = true;
        $connection->details = '';

        if (!$this->is_functional()) {
            $connection->success = false;
            $connection->details = get_string('settings:notconfigured', 'tool_objectfs');
            return $connection;
        }

        try {
            $url = self::GCS_API_BASE . '/b/' . rawurlencode($this->bucket) .
                '/o?maxResults=1&prefix=' . rawurlencode($this->bucketkeyprefix);
            $resp = $this->request('GET', $url, [], null, 30);
            if ($resp['status'] !== 200) {
                $connection->success = false;
                $connection->details = "HTTP {$resp['status']}: " . substr($resp['body'], 0, 300);
            }
        } catch (Throwable $e) {
            $connection->success = false;
            $connection->details = $e->getMessage();
        }

        return $connection;
    }

    /**
     * Test write, read, and optional delete permissions in the configured GCS bucket/prefix.
     *
     * @param bool $testdelete
     * @return stdClass
     * @throws coding_exception
     */
    public function test_permissions($testdelete) {
        $permissions = new stdClass();
        $permissions->success = true;
        $permissions->messages = [];

        if (!$this->is_functional()) {
            $permissions->success = false;
            $permissions->messages[get_string('settings:notconfigured', 'tool_objectfs')] = 'notifyproblem';
            return $permissions;
        }

        $testkey = $this->bucketkeyprefix . 'permissions_check_file';
        $payload = 'tool_objectfs gcs permissions check';

        try {
            $this->put_object_content($this->bucket, $testkey, $payload, 'text/plain');
        } catch (Throwable $e) {
            $permissions->messages[get_string('settings:writefailure', 'tool_objectfs') . $e->getMessage()] = 'notifyproblem';
            $permissions->success = false;
            return $permissions;
        }

        try {
            $readback = $this->download_object_bytes($this->bucket, $testkey);
            if ($readback !== $payload) {
                $permissions->messages[get_string('settings:permissionreadfailure', 'tool_objectfs')] = 'notifyproblem';
                $permissions->success = false;
            }
        } catch (Throwable $e) {
            $msg = get_string('settings:permissionreadfailure', 'tool_objectfs') . $e->getMessage();
            $permissions->messages[$msg] = 'notifyproblem';
            $permissions->success = false;
        }

        if ($testdelete) {
            try {
                $this->delete_object($this->bucket, $testkey);
            } catch (Throwable $e) {
                $permissions->messages[get_string('settings:deleteerror', 'tool_objectfs') . $e->getMessage()] = 'notifyproblem';
                $permissions->success = false;
            }
        }

        if ($permissions->success) {
            $permissions->messages[get_string('settings:permissioncheckpassed', 'tool_objectfs')] = 'notifysuccess';
        }

        return $permissions;
    }

    /**
     * Define admin settings section for Google Cloud Storage.
     *
     * @param \admin_settingpage $settings
     * @param object $config
     * @return \admin_settingpage
     */
    public function define_client_section($settings, $config) {
        $settings->add(new \admin_setting_heading(
            'tool_objectfs/gcs',
            new \lang_string('settings:gcs:header', 'tool_objectfs'),
            new \lang_string('settings:gcs:header_desc', 'tool_objectfs')
        ));

        $settings->add(new \admin_setting_configtext(
            'tool_objectfs/gcs_bucket',
            new \lang_string('settings:gcs:bucket', 'tool_objectfs'),
            new \lang_string('settings:gcs:bucket_help', 'tool_objectfs'),
            ''
        ));

        $settings->add(new \admin_setting_configtext(
            'tool_objectfs/gcs_key_prefix',
            new \lang_string('settings:gcs:prefix', 'tool_objectfs'),
            new \lang_string('settings:gcs:prefix_help', 'tool_objectfs'),
            ''
        ));

        return $settings;
    }

    /**
     * Whether pre-signed URLs are supported.
     *
     * @return bool
     */
    public function support_presigned_urls() {
        return true;
    }

    /**
     * Generate a GCS V4 Signed URL keylessly using the IAM Credentials signBlob API.
     *
     * @param string $contenthash
     * @param array $headers
     * @return signed_url
     * @throws RuntimeException
     */
    public function generate_presigned_url($contenthash, $headers = []) {
        if (!$this->is_functional()) {
            throw new RuntimeException('GCS client is not configured: missing bucket.');
        }

        $now = time();
        $expires = $this->get_expiration_time($now, manager::get_header($headers, 'Expires'));
        $ttl = max(60, min(604740, $expires - $now));

        $saemail = $this->get_service_account_email();
        $objectkey = $this->get_object_key_from_hash($contenthash);

        $datestamp = gmdate('Ymd', $now);
        $amzdate = gmdate('Ymd\THis\Z', $now);
        $credentialscope = "{$datestamp}/auto/storage/goog4_request";

        $queryparams = [
            'X-Goog-Algorithm' => 'GOOG4-RSA-SHA256',
            'X-Goog-Credential' => "{$saemail}/{$credentialscope}",
            'X-Goog-Date' => $amzdate,
            'X-Goog-Expires' => (string)$ttl,
            'X-Goog-SignedHeaders' => 'host',
        ];

        $nice = $this->get_nice_filename($headers);
        if (!empty($nice)) {
            $queryparams['response-content-disposition'] = $nice['Content-Disposition'] . '; ' . $nice['filename'];
            if (!empty($nice['Content-Type'])) {
                $queryparams['response-content-type'] = $nice['Content-Type'];
            }
        } else {
            $disposition = manager::get_header($headers, 'Content-Disposition');
            if ($disposition !== '') {
                $queryparams['response-content-disposition'] = $disposition;
            }
            $ctype = manager::get_header($headers, 'Content-Type');
            if ($ctype !== '') {
                $queryparams['response-content-type'] = $ctype;
            }
        }

        ksort($queryparams);
        $canonicalquerystring = [];
        foreach ($queryparams as $k => $v) {
            $canonicalquerystring[] = rawurlencode((string)$k) . '=' . rawurlencode((string)$v);
        }
        $canonicalquery = implode('&', $canonicalquerystring);

        $encodedsegments = array_map('rawurlencode', explode('/', $objectkey));
        $canonicaluri = '/' . rawurlencode($this->bucket) . '/' . implode('/', $encodedsegments);
        $canonicalheaders = "host:storage.googleapis.com\n";

        $canonicalrequest = implode("\n", [
            'GET',
            $canonicaluri,
            $canonicalquery,
            $canonicalheaders,
            'host',
            'UNSIGNED-PAYLOAD',
        ]);

        $stringtosign = implode("\n", [
            'GOOG4-RSA-SHA256',
            $amzdate,
            $credentialscope,
            hash('sha256', $canonicalrequest),
        ]);

        $signurl = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' .
            rawurlencode($saemail) . ':signBlob';
        $signbody = (string)json_encode([
            'payload' => base64_encode($stringtosign),
        ]);
        $signresp = $this->request(
            'POST',
            $signurl,
            [
                'Content-Type: application/json; charset=UTF-8',
                'Content-Length: ' . strlen($signbody),
            ],
            $signbody,
            15
        );

        if ($signresp['status'] !== 200) {
            throw new RuntimeException(
                "IAM signBlob failed for {$saemail} (HTTP {$signresp['status']}): " .
                substr($signresp['body'], 0, 300)
            );
        }

        $signdata = json_decode($signresp['body'], true);
        $rawsig = isset($signdata['signedBlob']) ? base64_decode((string)$signdata['signedBlob'], true) : false;
        if ($rawsig === false || $rawsig === '') {
            throw new RuntimeException('IAM signBlob returned an empty signature.');
        }

        $finalurl = 'https://storage.googleapis.com' . $canonicaluri . '?' .
            $canonicalquery . '&X-Goog-Signature=' . bin2hex($rawsig);

        return new signed_url(new \moodle_url($finalurl), $now + $ttl);
    }

    /**
     * Extract RFC 5987 UTF-8 filename and Content-Type from response headers.
     *
     * @param array $headers
     * @return array
     */
    private function get_nice_filename(array $headers): array {
        $originalfilename = '';
        $result = [];
        $contentdisposition = trim(manager::get_header($headers, 'Content-Disposition'));
        $originalcontenttype = trim(manager::get_header($headers, 'Content-Type'));

        if ($contentdisposition !== '') {
            $fparts = explode('; ', $contentdisposition);
            if (!empty($fparts[1])) {
                $originalfilename = str_replace(['filename=', '"'], '', $fparts[1]);
            }
            if (!empty($fparts[0])) {
                $contentdisposition = $fparts[0];
            }
            if ($originalfilename !== '') {
                $result['Content-Disposition'] = $contentdisposition;
                $asciifilename = preg_replace('/[^\x20-\x7E]/', '_', $originalfilename);
                $asciifilename = str_replace(['"', '\\', '+'], '_', (string)$asciifilename);
                $result['filename'] = 'filename="' . $asciifilename . '"; filename*=UTF-8\'\'' . rawurlencode($originalfilename);
                $result['Content-Type'] = $originalcontenttype;
            }
        }
        return $result;
    }

    /**
     * Compute rounded expiration timestamp for pre-signed URLs (up to 7 days).
     *
     * @param int $now
     * @param mixed $expires
     * @return int
     */
    public function get_expiration_time(int $now, $expires): int {
        if (is_string($expires)) {
            $expires = strtotime($expires);
        }
        if (empty($expires)) {
            $expires = $now + (int)$this->expirationtime + MINSECS;
        }
        if ($expires < $now + (2 * MINSECS)) {
            $expires = $now + (2 * MINSECS);
        }
        if ($expires - $now > WEEKSECS - MINSECS) {
            $expires = $now + WEEKSECS - MINSECS;
        }
        $expires -= ($expires % MINSECS);
        return (int)$expires;
    }

    /**
     * Proxy an HTTP byte-range request directly from GCS using bearer auth.
     *
     * @param \stored_file $file
     * @param object $ranges
     * @return false
     * @throws \file_exception
     */
    public function proxy_range_request(\stored_file $file, $ranges) {
        if (empty($this->config->proxyrangerequests) || $file->get_filesize() < self::MAX_TEMP_LIMIT) {
            return false;
        }

        $objectkey = $this->get_object_key_from_hash($file->get_contenthash());
        $url = self::GCS_API_BASE . '/b/' . rawurlencode($this->bucket) .
            '/o/' . rawurlencode($objectkey) . '?alt=media';

        try {
            $resp = $this->request(
                'GET',
                $url,
                ["Range: bytes={$ranges->rangefrom}-{$ranges->rangeto}"],
                null,
                60
            );
        } catch (Throwable $e) {
            throw new \file_exception('GCS range request failed: ' . $e->getMessage());
        }

        if ($resp['status'] === 206 && $resp['body'] !== '') {
            header('HTTP/1.1 206 Partial Content');
            header('Accept-Ranges: bytes');
            if (!empty($resp['headers']['content-range'])) {
                header('Content-Range: ' . $resp['headers']['content-range']);
            }
            header('Content-Length: ' . strlen($resp['body']));
            echo $resp['body'];
            die;
        }

        throw new \file_exception(
            "Range request to GCS failed with HTTP {$resp['status']}: " . substr($resp['body'], 0, 200)
        );
    }

    /**
     * Test HTTP byte-range request support against GCS.
     *
     * @param object $filesystem
     * @return object
     * @throws coding_exception
     */
    public function test_range_request($filesystem) {
        global $PAGE;
        $output = $PAGE->get_renderer('tool_objectfs');
        $testfiles = $output->presignedurl_tests_load_files($filesystem);
        foreach ($testfiles as $file) {
            if ($file->get_filename() === 'testvideo.mp4') {
                $objectkey = $this->get_object_key_from_hash($file->get_contenthash());
                try {
                    $bytes = $this->download_object_bytes($this->bucket, $objectkey, 0, 999);
                    if (strlen($bytes) === 1000) {
                        return (object)['result' => true];
                    }
                } catch (Throwable $e) {
                    $a = (object)['url' => $objectkey, 'httpcode' => 'ERROR', 'details' => $e->getMessage()];
                    return (object)['result' => false, 'error' => get_string('rangerequestfailed', 'tool_objectfs', $a)];
                }
            }
        }
        return (object)['result' => false, 'error' => get_string('fixturefilemissing', 'tool_objectfs')];
    }

    /**
     * GCS supports custom key-value object metadata for tagging.
     *
     * @return bool
     */
    public function supports_object_tagging(): bool {
        return true;
    }

    /**
     * Test setting custom metadata tags on a GCS object.
     *
     * @return stdClass
     */
    public function test_set_object_tag(): stdClass {
        if (!$this->is_functional()) {
            return (object)[
                'success' => false,
                'details' => get_string('settings:notconfigured', 'tool_objectfs'),
            ];
        }

        try {
            $key = $this->bucketkeyprefix . 'tagging_check_file';
            $this->put_object_content($this->bucket, $key, 'test content', 'text/plain');
            $this->patch_object_metadata($this->bucket, $key, ['test' => 'test']);
        } catch (Throwable $e) {
            return (object)[
                'success' => false,
                'details' => $e->getMessage(),
            ];
        }

        return (object)['success' => true, 'details' => ''];
    }

    /**
     * Store tags as custom metadata on a GCS object.
     *
     * @param string $contenthash
     * @param array $tags
     * @return void
     */
    public function set_object_tags(string $contenthash, array $tags) {
        $objectkey = $this->get_object_key_from_hash($contenthash);
        $normalized = [];
        foreach ($tags as $k => $v) {
            $normalized[(string)$k] = (string)$v;
        }
        $this->patch_object_metadata($this->bucket, $objectkey, $normalized);
    }

    /**
     * Retrieve custom metadata tags from a GCS object.
     *
     * @param string $contenthash
     * @return array
     */
    public function get_object_tags(string $contenthash): array {
        $objectkey = $this->get_object_key_from_hash($contenthash);
        $meta = $this->get_object_metadata($this->bucket, $objectkey);
        if ($meta === null || empty($meta['metadata']) || !is_array($meta['metadata'])) {
            return [];
        }
        $result = [];
        foreach ($meta['metadata'] as $k => $v) {
            $result[(string)$k] = (string)$v;
        }
        return $result;
    }

    /**
     * Patch custom user metadata on a GCS object.
     *
     * @param string $bucket
     * @param string $objectkey
     * @param array $metadata
     * @return void
     * @throws RuntimeException
     */
    private function patch_object_metadata(string $bucket, string $objectkey, array $metadata): void {
        $url = self::GCS_API_BASE . '/b/' . rawurlencode($bucket) . '/o/' . rawurlencode($objectkey);
        $body = (string)json_encode(['metadata' => (object)$metadata]);
        $resp = $this->request(
            'PATCH',
            $url,
            [
                'Content-Type: application/json; charset=UTF-8',
                'Content-Length: ' . strlen($body),
            ],
            $body,
            30
        );
        if ($resp['status'] !== 200) {
            throw new RuntimeException(
                "Failed updating GCS object metadata for {$bucket}/{$objectkey} (HTTP {$resp['status']}): " .
                substr($resp['body'], 0, 300)
            );
        }
    }

    /**
     * URL-safe base64 encoding helper for JWT assertions.
     *
     * @param string $input
     * @return string
     */
    private function base64url_encode(string $input): string {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }
}
