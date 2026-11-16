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

namespace tool_objectfs\local\store\gcs;

/**
 * Unit tests for Google Cloud Storage client configuration and path routing.
 *
 * @package   tool_objectfs
 * @copyright 2026 Horizon Education Network
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class client_test extends \advanced_testcase {
    /**
     * Tests GCS client reports not configured when gcs_bucket is missing and normalizes prefixes cleanly.
     *
     * @covers \tool_objectfs\local\store\gcs\client
     */
    public function test_gcs_client_configuration_and_paths(): void {
        $unconfigured = new client((object)['gcs_bucket' => '', 'gcs_key_prefix' => 'dev']);
        $this->assertFalse($unconfigured->is_functional());
        $this->assertFalse($unconfigured->is_configured((object)['gcs_bucket' => '']));
        $result = $unconfigured->test_connection();
        $this->assertFalse($result->success);
        $this->assertSame(get_string('settings:notconfigured', 'tool_objectfs'), $result->details);

        $configured = new client((object)[
            'gcs_bucket' => 'hen-test-bucket',
            'gcs_key_prefix' => '/staging',
            'key_prefix' => 's3-prefix-should-be-ignored/',
        ]);
        $this->assertTrue($configured->is_functional());
        $this->assertTrue($configured->is_configured((object)['gcs_bucket' => 'hen-test-bucket']));
        $this->assertSame(-1, $configured->get_token_expiry_time());

        $hash = sha1('sample moodle object');
        $l1 = substr($hash, 0, 2);
        $l2 = substr($hash, 2, 2);
        $this->assertSame(
            "gcs://hen-test-bucket/staging/{$l1}/{$l2}/{$hash}",
            $configured->get_fullpath_from_hash($hash)
        );
    }

    /**
     * Tests legacy bucket and prefix config properties continue to work as fallbacks.
     *
     * @covers \tool_objectfs\local\store\gcs\client
     */
    public function test_gcs_client_legacy_config_fallback(): void {
        $legacy = new client((object)[
            'bucket' => 'hen-legacy-bucket',
            'prefix' => 'tenant-a/',
            'key_prefix' => 's3-prefix-should-not-leak/',
        ]);
        $this->assertTrue($legacy->is_functional());
        $this->assertTrue($legacy->is_configured((object)['bucket' => 'hen-legacy-bucket']));

        $hash = sha1('legacy fallback moodle object');
        $l1 = substr($hash, 0, 2);
        $l2 = substr($hash, 2, 2);
        $this->assertSame(
            "gcs://hen-legacy-bucket/tenant-a/{$l1}/{$l2}/{$hash}",
            $legacy->get_fullpath_from_hash($hash)
        );
    }

    /**
     * Tests gcs_nopresign_countries normalizes, trims, and deduplicates ISO country codes.
     *
     * @covers \tool_objectfs\local\store\gcs\client
     */
    public function test_gcs_nopresign_countries_parsing(): void {
        $empty = new client((object)['gcs_bucket' => 'hen-test-bucket']);
        $this->assertSame([], $empty->get_nopresign_countries());

        $parsed = new client((object)[
            'gcs_bucket' => 'hen-test-bucket',
            'gcs_nopresign_countries' => ' cn, ir ; CN  sy ',
        ]);
        $this->assertSame(['CN', 'IR', 'SY'], $parsed->get_nopresign_countries());
    }

    /**
     * Tests Cloudflare HTTP_CF_IPCOUNTRY bypasses pre-signed URL redirects only for configured countries.
     *
     * @covers \tool_objectfs\local\store\gcs\file_system
     */
    public function test_gcs_country_presigned_url_bypass(): void {
        global $CFG;
        $this->resetAfterTest();

        set_config('filesystem', '\tool_objectfs\gcs_file_system', 'tool_objectfs');
        set_config('gcs_bucket', 'hen-test-bucket', 'tool_objectfs');
        set_config('enablepresignedurls', 1, 'tool_objectfs');
        set_config('presignedminfilesize', 0, 'tool_objectfs');
        set_config('signingwhitelist', '*', 'tool_objectfs');
        set_config('gcs_nopresign_countries', 'cn, ir', 'tool_objectfs');
        $CFG->alternative_file_system_class = '\tool_objectfs\gcs_file_system';

        $fs = new \tool_objectfs\gcs_file_system();
        $hash = sha1('country-routing-test-object');
        $mockfile = $this->createMock(\stored_file::class);

        $hadheader = array_key_exists('HTTP_CF_IPCOUNTRY', $_SERVER);
        $origheader = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? null;

        try {
            // Philippines (PH) user in the same tenant continues receiving pre-signed URL redirects.
            $_SERVER['HTTP_CF_IPCOUNTRY'] = 'PH';
            $this->assertFalse($fs->should_bypass_presigned_for_country());
            $this->assertTrue($fs->presigned_url_should_redirect($hash, []));

            // US user continues receiving pre-signed URL redirects.
            $_SERVER['HTTP_CF_IPCOUNTRY'] = 'US';
            $this->assertFalse($fs->should_bypass_presigned_for_country());
            $this->assertTrue($fs->presigned_url_should_redirect($hash, []));

            // Mainland China (CN) user bypasses pre-signed URLs and streams via Moodle.
            $_SERVER['HTTP_CF_IPCOUNTRY'] = 'CN';
            $this->assertTrue($fs->should_bypass_presigned_for_country());
            $this->assertFalse($fs->presigned_url_should_redirect($hash, []));
            $this->assertFalse($fs->presigned_url_should_redirect_file($mockfile, []));

            // Case-insensitive header matching works cleanly.
            $_SERVER['HTTP_CF_IPCOUNTRY'] = ' ir ';
            $this->assertTrue($fs->should_bypass_presigned_for_country());
            $this->assertFalse($fs->presigned_url_should_redirect($hash, []));

            // Missing header defaults to normal pre-signed URL behavior.
            unset($_SERVER['HTTP_CF_IPCOUNTRY']);
            $this->assertFalse($fs->should_bypass_presigned_for_country());
            $this->assertTrue($fs->presigned_url_should_redirect($hash, []));
        } finally {
            if ($hadheader) {
                $_SERVER['HTTP_CF_IPCOUNTRY'] = $origheader;
            } else {
                unset($_SERVER['HTTP_CF_IPCOUNTRY']);
            }
        }
    }
}
