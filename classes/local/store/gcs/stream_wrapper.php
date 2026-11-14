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
 * PHP stream wrapper for gcs://<bucket>/<object> URIs.
 *
 * Implements the exact error-signalling contract expected by
 * tool_objectfs\local\store\object_file_system::is_file_readable_externally_by_hash():
 * - Confirmed missing objects (HTTP 404) return false from url_stat() WITHOUT trigger_error().
 * - Transient / auth / network failures emit trigger_error(..., E_USER_WARNING) and return false.
 *
 * @package   tool_objectfs
 * @copyright 2026 Horizon Education Network
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace tool_objectfs\local\store\gcs;

defined('MOODLE_INTERNAL') || die();

use Throwable;
use tool_objectfs\local\manager;

/**
 * Google Cloud Storage stream wrapper (gcs://).
 */
class stream_wrapper {
    /** @var int Read-ahead Range window size (8 MiB). */
    private const READ_WINDOW_SIZE = 8388608;

    /** @var resource|null Stream context injected by PHP runtime. */
    public $context;

    /** @var client|null Default registered GCS client instance. */
    private static ?client $defaultclient = null;

    /** @var string Bucket name for open stream. */
    private string $bucket = '';

    /** @var string Object key for open stream. */
    private string $objectkey = '';

    /** @var bool Whether stream is opened for reading. */
    private bool $isreading = false;

    /** @var bool Whether stream is opened for writing. */
    private bool $iswriting = false;

    /** @var bool Fail if object exists ('x' mode). */
    private bool $nooverwrite = false;

    /** @var int Object byte size when reading. */
    private int $filesize = 0;

    /** @var int Object modification timestamp. */
    private int $mtime = 0;

    /** @var int Current byte cursor for reading. */
    private int $position = 0;

    /** @var int Start offset of cached read window (-1 when empty). */
    private int $windowstart = -1;

    /** @var string Cached read window bytes. */
    private string $windowdata = '';

    /** @var resource|null Temp buffer handle when writing. */
    private $writestream = null;

    /** @var bool Whether buffered writes need flushing to GCS. */
    private bool $dirty = false;

    /**
     * Register the gcs:// protocol wrapper with PHP.
     *
     * @param client $client
     * @return void
     */
    public static function register(client $client): void {
        self::$defaultclient = $client;
        if (!in_array('gcs', stream_get_wrappers(), true)) {
            stream_wrapper_register('gcs', self::class, STREAM_IS_URL);
        }
    }

    /**
     * Obtain active GCS client instance.
     *
     * @return client
     */
    private static function get_client(): client {
        if (self::$defaultclient === null) {
            $config = manager::get_objectfs_config();
            self::$defaultclient = new client($config);
        }
        return self::$defaultclient;
    }

    /**
     * Parse a gcs://<bucket>/<key> URI.
     *
     * @param string $path
     * @return array{bucket:string, key:string}|null
     */
    private static function parse_gcs_uri(string $path): ?array {
        if (!preg_match('#^gcs://([^/]+)(?:/(.*))?$#s', $path, $m)) {
            return null;
        }
        return [
            'bucket' => $m[1],
            'key' => $m[2] ?? '',
        ];
    }

    /**
     * Build a standard 26-entry PHP stat array for a regular file.
     *
     * @param int $size
     * @param int $mtime
     * @param int $mode
     * @return array
     */
    private static function build_stat_array(int $size, int $mtime, int $mode = 0100444): array {
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : 0;
        $gid = function_exists('posix_getegid') ? posix_getegid() : 0;
        $named = [
            'dev' => 0,
            'ino' => 0,
            'mode' => $mode,
            'nlink' => 1,
            'uid' => $uid,
            'gid' => $gid,
            'rdev' => 0,
            'size' => $size,
            'atime' => $mtime,
            'mtime' => $mtime,
            'ctime' => $mtime,
            'blksize' => 8192,
            'blocks' => (int)ceil($size / 512),
        ];
        return array_merge(array_values($named), $named);
    }

    /**
     * Open a gcs:// stream.
     *
     * @param string $path
     * @param string $mode
     * @param int $options
     * @param string|null $openedpath
     * @return bool
     */
    public function stream_open(string $path, string $mode, int $options, ?string &$openedpath = null): bool {
        $parsed = self::parse_gcs_uri($path);
        if ($parsed === null || $parsed['bucket'] === '' || $parsed['key'] === '') {
            trigger_error("Invalid GCS URI: {$path}", E_USER_WARNING);
            return false;
        }

        $this->bucket = $parsed['bucket'];
        $this->objectkey = $parsed['key'];

        $cleanmode = str_replace(['b', 't'], '', $mode);
        switch ($cleanmode) {
            case 'r':
                $this->isreading = true;
                break;
            case 'w':
            case 'c':
            case 'a':
                $this->iswriting = true;
                break;
            case 'x':
                $this->iswriting = true;
                $this->nooverwrite = true;
                break;
            case 'r+':
            case 'w+':
                $this->isreading = true;
                $this->iswriting = true;
                break;
            default:
                trigger_error("Unsupported stream mode '{$mode}' for {$path}", E_USER_WARNING);
                return false;
        }

        $client = self::get_client();

        try {
            if ($this->isreading && !$this->iswriting) {
                $meta = $client->get_object_metadata($this->bucket, $this->objectkey);
                if ($meta === null) {
                    trigger_error("GCS object does not exist: {$path}", E_USER_WARNING);
                    return false;
                }
                $this->filesize = isset($meta['size']) ? (int)$meta['size'] : 0;
                $this->mtime = !empty($meta['updated']) ? (int)strtotime((string)$meta['updated']) : time();
                $this->position = 0;
                $this->windowstart = -1;
                $this->windowdata = '';
                return true;
            }

            if ($this->nooverwrite) {
                $meta = $client->get_object_metadata($this->bucket, $this->objectkey);
                if ($meta !== null) {
                    trigger_error("GCS object already exists and mode x forbids overwrite: {$path}", E_USER_WARNING);
                    return false;
                }
            }

            $this->writestream = fopen('php://temp', 'w+b');
            if ($this->writestream === false) {
                trigger_error("Failed opening php://temp buffer for {$path}", E_USER_WARNING);
                return false;
            }
            $this->dirty = ($cleanmode === 'w' || $cleanmode === 'x');
            $this->mtime = time();
            return true;
        } catch (Throwable $e) {
            trigger_error("GCS stream_open error for {$path}: " . $e->getMessage(), E_USER_WARNING);
            return false;
        }
    }

    /**
     * Read up to $count bytes from the stream.
     *
     * @param int $count
     * @return string|false
     */
    public function stream_read(int $count) {
        if ($this->writestream !== null) {
            return fread($this->writestream, $count);
        }

        if (!$this->isreading || $count <= 0) {
            return '';
        }

        if ($this->position >= $this->filesize) {
            return '';
        }

        $windowend = $this->windowstart + strlen($this->windowdata);
        if ($this->windowstart < 0 || $this->position < $this->windowstart || $this->position >= $windowend) {
            $fetchstart = $this->position;
            $fetchend = min($this->filesize - 1, $fetchstart + self::READ_WINDOW_SIZE - 1);

            try {
                $client = self::get_client();
                if ($fetchstart === 0 && $fetchend === ($this->filesize - 1)) {
                    $this->windowdata = $client->download_object_bytes($this->bucket, $this->objectkey);
                } else {
                    $this->windowdata = $client->download_object_bytes(
                        $this->bucket,
                        $this->objectkey,
                        $fetchstart,
                        $fetchend
                    );
                }
                $this->windowstart = $fetchstart;
            } catch (Throwable $e) {
                trigger_error(
                    "GCS stream_read failed at byte {$fetchstart} for gcs://{$this->bucket}/{$this->objectkey}: " .
                    $e->getMessage(),
                    E_USER_WARNING
                );
                return false;
            }
        }

        $rel = $this->position - $this->windowstart;
        $chunk = substr($this->windowdata, $rel, $count);
        $this->position += strlen($chunk);
        return $chunk;
    }

    /**
     * Write bytes to the buffered write stream.
     *
     * @param string $data
     * @return int
     */
    public function stream_write(string $data): int {
        if (!$this->iswriting || $this->writestream === null) {
            return 0;
        }
        $written = fwrite($this->writestream, $data);
        if ($written === false) {
            return 0;
        }
        $this->dirty = true;
        return $written;
    }

    /**
     * Flush buffered write content to Google Cloud Storage.
     *
     * @return bool
     */
    public function stream_flush(): bool {
        if (!$this->iswriting || !$this->dirty || $this->writestream === null) {
            return true;
        }

        $stat = fstat($this->writestream);
        $size = is_array($stat) && isset($stat['size']) ? (int)$stat['size'] : 0;
        rewind($this->writestream);

        $client = self::get_client();

        try {
            if ($size <= client::RESUMABLE_THRESHOLD) {
                $payload = stream_get_contents($this->writestream);
                if ($payload === false) {
                    throw new \RuntimeException('Failed reading write buffer.');
                }
                $client->put_object_content($this->bucket, $this->objectkey, $payload);
            } else {
                $tmpfile = tempnam(sys_get_temp_dir(), 'objfsgcs_');
                if ($tmpfile === false) {
                    throw new \RuntimeException('Failed creating temporary upload file.');
                }
                $tmpfh = fopen($tmpfile, 'wb');
                if ($tmpfh === false) {
                    @unlink($tmpfile);
                    throw new \RuntimeException('Failed opening temporary upload file.');
                }
                try {
                    stream_copy_to_stream($this->writestream, $tmpfh);
                    fclose($tmpfh);
                    $client->upload_file_to_object($this->bucket, $this->objectkey, $tmpfile);
                } finally {
                    @unlink($tmpfile);
                }
            }
            $this->dirty = false;
            return true;
        } catch (Throwable $e) {
            trigger_error(
                "GCS stream_flush failed for gcs://{$this->bucket}/{$this->objectkey}: " . $e->getMessage(),
                E_USER_WARNING
            );
            return false;
        }
    }

    /**
     * Close the stream, flushing any pending writes.
     *
     * @return void
     */
    public function stream_close(): void {
        if ($this->iswriting && $this->dirty) {
            $this->stream_flush();
        }
        if (is_resource($this->writestream)) {
            fclose($this->writestream);
        }
        $this->writestream = null;
        $this->windowdata = '';
        $this->windowstart = -1;
    }

    /**
     * Check whether cursor has reached EOF.
     *
     * @return bool
     */
    public function stream_eof(): bool {
        if ($this->writestream !== null) {
            return feof($this->writestream);
        }
        return $this->position >= $this->filesize;
    }

    /**
     * Return current cursor offset.
     *
     * @return int
     */
    public function stream_tell(): int {
        if ($this->writestream !== null) {
            $pos = ftell($this->writestream);
            return ($pos === false) ? 0 : $pos;
        }
        return $this->position;
    }

    /**
     * Seek to a byte offset within the stream.
     *
     * @param int $offset
     * @param int $whence
     * @return bool
     */
    public function stream_seek(int $offset, int $whence = SEEK_SET): bool {
        if ($this->writestream !== null) {
            return fseek($this->writestream, $offset, $whence) === 0;
        }

        switch ($whence) {
            case SEEK_SET:
                $target = $offset;
                break;
            case SEEK_CUR:
                $target = $this->position + $offset;
                break;
            case SEEK_END:
                $target = $this->filesize + $offset;
                break;
            default:
                return false;
        }

        if ($target < 0 || $target > $this->filesize) {
            return false;
        }

        $this->position = $target;
        return true;
    }

    /**
     * Stat an open stream.
     *
     * @return array
     */
    public function stream_stat(): array {
        if ($this->writestream !== null) {
            $stat = fstat($this->writestream);
            $size = is_array($stat) && isset($stat['size']) ? (int)$stat['size'] : 0;
            return self::build_stat_array($size, $this->mtime, 0100666);
        }
        return self::build_stat_array($this->filesize, $this->mtime, 0100444);
    }

    /**
     * Handle stream_set_option calls gracefully without PHP warnings.
     *
     * @param int $option
     * @param int $arg1
     * @param int|null $arg2
     * @return bool
     */
    public function stream_set_option(int $option, int $arg1, ?int $arg2 = null): bool {
        return false;
    }

    /**
     * Stat a gcs:// URL (invoked by is_readable, file_exists, filesize, stat).
     *
     * Contract required by object_file_system::is_file_readable_externally_by_hash():
     * - Confirmed missing object (HTTP 404): return false silently (NO trigger_error).
     * - Transient/auth/permission error: emit trigger_error(E_USER_WARNING) and return false.
     *
     * @param string $path
     * @param int $flags
     * @return array|false
     */
    public function url_stat(string $path, int $flags) {
        $parsed = self::parse_gcs_uri($path);
        if ($parsed === null || $parsed['bucket'] === '') {
            return false;
        }

        // Root or prefix directory check.
        if ($parsed['key'] === '' || substr($parsed['key'], -1) === '/') {
            return self::build_stat_array(0, time(), 0040555);
        }

        try {
            $meta = self::get_client()->get_object_metadata($parsed['bucket'], $parsed['key']);
            if ($meta === null) {
                return false;
            }
            $size = isset($meta['size']) ? (int)$meta['size'] : 0;
            $mtime = !empty($meta['updated']) ? (int)strtotime((string)$meta['updated']) : time();
            return self::build_stat_array($size, $mtime, 0100444);
        } catch (Throwable $e) {
            trigger_error("GCS transient stat error for {$path}: " . $e->getMessage(), E_USER_WARNING);
            return false;
        }
    }

    /**
     * Delete a gcs:// object via unlink().
     *
     * @param string $path
     * @return bool
     */
    public function unlink(string $path): bool {
        $parsed = self::parse_gcs_uri($path);
        if ($parsed === null || $parsed['bucket'] === '' || $parsed['key'] === '') {
            trigger_error("Invalid GCS URI for unlink: {$path}", E_USER_WARNING);
            return false;
        }

        try {
            return self::get_client()->delete_object($parsed['bucket'], $parsed['key']);
        } catch (Throwable $e) {
            trigger_error("GCS unlink failed for {$path}: " . $e->getMessage(), E_USER_WARNING);
            return false;
        }
    }

    /**
     * Move/rename a gcs:// object via rewriteTo + delete.
     *
     * @param string $pathfrom
     * @param string $pathto
     * @return bool
     */
    public function rename(string $pathfrom, string $pathto): bool {
        $src = self::parse_gcs_uri($pathfrom);
        $dst = self::parse_gcs_uri($pathto);
        if (
            $src === null || $dst === null ||
            $src['bucket'] === '' || $src['key'] === '' ||
            $dst['bucket'] === '' || $dst['key'] === ''
        ) {
            trigger_error("Invalid GCS URI for rename: {$pathfrom} -> {$pathto}", E_USER_WARNING);
            return false;
        }

        try {
            $client = self::get_client();
            $client->copy_object($src['bucket'], $src['key'], $dst['bucket'], $dst['key']);
            $client->delete_object($src['bucket'], $src['key']);
            return true;
        } catch (Throwable $e) {
            trigger_error("GCS rename failed ({$pathfrom} -> {$pathto}): " . $e->getMessage(), E_USER_WARNING);
            return false;
        }
    }
}
