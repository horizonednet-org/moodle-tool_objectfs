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
 * Google Cloud Storage object_file_system implementation.
 *
 * @package   tool_objectfs
 * @copyright 2026 Horizon Education Network
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace tool_objectfs\local\store\gcs;

defined('MOODLE_INTERNAL') || die();

use Throwable;
use tool_objectfs\local\manager;
use tool_objectfs\local\store\object_file_system;

require_once(__DIR__ . '/../../../../lib.php');

/**
 * Keyless Google Cloud Storage file_system store.
 */
class file_system extends object_file_system {
    /**
     * Initialise the external GCS client.
     *
     * @param \stdClass $config
     * @return client
     */
    protected function initialise_external_client($config) {
        return new client($config);
    }

    /**
     * Output the content of the specified stored file.
     *
     * @param \stored_file $file
     * @return void
     * @throws \file_exception
     */
    public function readfile(\stored_file $file) {
        if (!$this->is_configured()) {
            parent::readfile($file);
            return;
        }

        $path = $this->get_remote_path_from_storedfile($file);

        $this->get_logger()->start_timing();
        if ($path === $this->get_external_client()->get_fullpath_from_hash($file->get_contenthash())) {
            $success = $this->get_external_client()->stream_object_to_output($file->get_contenthash());
        } else {
            $success = readfile_allow_large($path, $file->get_filesize());
        }
        $this->get_logger()->end_timing();
        $this->get_logger()->log_object_read('readfile', $path, $file->get_filesize());

        if ($success === false) {
            manager::update_object_by_hash($file->get_contenthash(), OBJECT_LOCATION_ERROR);
            throw new \file_exception('storedfilecannotreadfile', $file->get_filename());
        }
    }

    /**
     * Upload a local filedir object to Google Cloud Storage.
     *
     * Catches \Throwable so PHP 8 TypeErrors or runtime errors are logged cleanly
     * without crashing the entire scheduled task batch.
     *
     * @param string $contenthash
     * @return bool
     */
    public function copy_from_local_to_external($contenthash) {
        $localpath = $this->get_local_path_from_hash($contenthash);
        $mime = $this->get_mimetype_from_hash($contenthash);

        try {
            $this->get_external_client()->upload_to_gcs($localpath, $contenthash, $mime);
            return true;
        } catch (Throwable $e) {
            $this->get_logger()->error_log(
                'ERROR: copy ' . $localpath . ' to ' . $this->get_external_path_from_hash($contenthash) . ': ' . $e->getMessage()
            );
            return false;
        }
    }

    /**
     * Stream an external GCS object atomically into the local Moodle filedir.
     *
     * @param string $contenthash
     * @return bool
     */
    protected function copy_from_external_to_local($contenthash) {
        $localpath = $this->get_local_path_from_hash($contenthash);
        $tmppath = $localpath . '.tmp.' . getmypid() . '.' . mt_rand(1000, 9999);
        $fh = @fopen($tmppath, 'wb');
        if ($fh === false) {
            return false;
        }

        try {
            $client = $this->get_external_client();
            $ok = $client->download_object_to_stream(
                $client->get_bucket(),
                $client->get_object_key_from_hash($contenthash),
                $fh
            );
            fclose($fh);
            $fh = null;

            if (!$ok || !@rename($tmppath, $localpath)) {
                @unlink($tmppath);
                return false;
            }
            return true;
        } catch (Throwable $e) {
            if (is_resource($fh)) {
                fclose($fh);
            }
            @unlink($tmppath);
            $this->get_logger()->error_log(
                'ERROR: copy ' . $this->get_external_path_from_hash($contenthash) . ' to ' . $localpath . ': ' . $e->getMessage()
            );
            return false;
        }
    }

    /**
     * Whether GCS supports pre-signed URLs (via keyless IAM signBlob V4 signing).
     *
     * @return bool
     */
    public function supports_presigned_urls() {
        return true;
    }

    /**
     * Whether the current HTTP request originates from a country configured to bypass pre-signed URLs.
     *
     * Evaluates Cloudflare's HTTP_CF_IPCOUNTRY header in O(1) memory with zero database queries.
     *
     * @return bool
     */
    public function should_bypass_presigned_for_country(): bool {
        $client = $this->get_external_client();
        if (!($client instanceof client)) {
            return false;
        }

        $excluded = $client->get_nopresign_countries();
        if (empty($excluded)) {
            return false;
        }

        $country = strtoupper(trim((string)($_SERVER['HTTP_CF_IPCOUNTRY'] ?? '')));
        if ($country === '') {
            return false;
        }

        return in_array($country, $excluded, true);
    }

    /**
     * Skip pre-signed URL redirects when the requester is in an excluded country (e.g., CN).
     *
     * @param object $file
     * @param array $headers
     * @return bool
     */
    public function presigned_url_should_redirect_file($file, array $headers = []) {
        if ($this->should_bypass_presigned_for_country()) {
            return false;
        }
        return parent::presigned_url_should_redirect_file($file, $headers);
    }

    /**
     * Skip pre-signed URL redirects by hash when the requester is in an excluded country.
     *
     * @param string $contenthash
     * @param array $headers
     * @return bool
     */
    public function presigned_url_should_redirect($contenthash, $headers = []) {
        if ($this->should_bypass_presigned_for_country()) {
            return false;
        }
        return parent::presigned_url_should_redirect($contenthash, $headers);
    }

    /**
     * Ensure country-conditional 303 redirects are never edge-cached publicly by Cloudflare.
     *
     * @param string $contenthash
     * @param array $headers
     * @return bool
     */
    public function redirect_to_presigned_url($contenthash, $headers = []) {
        $client = $this->get_external_client();
        if ($client instanceof client && !empty($client->get_nopresign_countries()) && !headers_sent()) {
            header('Cache-Control: private');
        }
        return parent::redirect_to_presigned_url($contenthash, $headers);
    }
}
