<?php
// ============================================================
// SL INDUSTRY - Core Helper Functions  (v3)
// ============================================================
// Changes from v2:
//   - encryptField() / decryptField() for AES-256-CBC encryption
//     of bank account numbers and passport/ID numbers.
//   - hashField() for SHA-256 duplicate-detection hashes.
//   - uploadFile() uses image-only MIME for photos (MAJ-05 fix).
//   - calculateAttendanceFromTimes() — new: computes all
//     attendance values from check-in / check-out alone.
// ============================================================

require_once __DIR__ . '/database.php';

// ============================================================
// ENCRYPTION — AES-256-CBC for sensitive employee fields
// Set SL_ENCRYPT_KEY in your environment / php.ini / .env
// Never hard-code the key here in production.
// ============================================================
function getEncryptionKey(): string {
    $key = getenv('SL_ENCRYPT_KEY');
    $key = $key === false ? 'SL_INDUSTRY_DEFAULT_KEY_CHANGE_ME_IN_PRODUCTION!' : $key;
    return substr(hash('sha256', $key, true), 0, 32);
}

function encryptField(?string $value): ?string {
    if ($value === null || $value === '') {
        return null;
    }

    // Generate a secure IV and encrypt the value using AES-256-CBC.
    $iv = random_bytes(16);
    $enc = openssl_encrypt(
        $value,
        'AES-256-CBC',
        getEncryptionKey(),
        OPENSSL_RAW_DATA,
        $iv
    );
    if ($enc === false) {
        return null;
    }

    $payload = $iv . $enc;
    return base64_encode($payload);
}

function decryptField(?string $encrypted): ?string {
    if ($encrypted === null || $encrypted === '') {
        return null;
    }

    $raw = base64_decode($encrypted, true);
    if ($raw === false || strlen($raw) < 17) {
        return null;
    }

    $iv  = substr($raw, 0, 16);
    $enc = substr($raw, 16);
    $dec = openssl_decrypt(
        $enc,
        'AES-256-CBC',
        getEncryptionKey(),
        OPENSSL_RAW_DATA,
        $iv
    );

    return $dec !== false ? $dec : null;
}

/** One-way hash for duplicate detection (never decrypt needed) */
function hashField(?string $value): ?string {
    if ($value === null || $value === '') {
        return null;
    }
    return hash('sha256', strtolower(trim($value)));
}

// ============================================================
// SMART ATTENDANCE CALCULATOR
// Given check-in, check-out and day-of-week, returns all
// computed attendance values conforming to business rules.
//
// Rules applied:
//   1. Total duration = checkout − checkin (overnight handled)
//   2. Lunch deduction = 1 hour (configurable), only if duration > 1hr
//   3. Actual worked = duration − lunch
//   4. Weekday:  first 8 hrs = basic, remainder = overtime
//   5. Weekend:  ALL hours = overtime, basic = 0
//   6. Night allowance: checkout <= 00:00 → 2 hrs, after midnight → 3 hrs
//      Only applied for productive types (full_day / half_day)
// ============================================================
function calculateAttendanceFromTimes(
    string  $checkIn,
    string  $checkOut,
    int     $dayOfWeek,      // 1=Mon … 7=Sun
    string  $attendanceType, // full_day | half_day | absent | …
    float   $stdHours  = 8.0,
    float   $lunchHrs  = 1.0,
    bool    $isHoliday = false
): array {
    $result = [
        'total_duration_hours' => 0.0,
        'lunch_deduction_hours'=> 0.0,
        'work_hours'           => 0.0,
        'overtime_hours'       => 0.0,
        'night_shift_hours'    => 0.0,
    ];

    // Non-productive types: all zeros
    if (!in_array($attendanceType, ['full_day', 'half_day'])) {
        return $result;
    }

    // Parse times as seconds-since-midnight
    $inSec  = timeToSeconds($checkIn);
    $outSec = timeToSeconds($checkOut);

    if ($inSec === null || $outSec === null) {
        return $result;
    }

    // Handle overnight: if checkout <= checkin treat as next-day
    $isOvernight = ($outSec <= $inSec);
    if ($isOvernight) {
        $outSec += 86400;
    }

    $durationSec = $outSec - $inSec;
    $durationHrs = $durationSec / 3600.0;

    // Deduct lunch only if shift is long enough to have a break
    $actualLunch = ($durationHrs > $lunchHrs) ? $lunchHrs : 0.0;
    $workedHrs   = $durationHrs - $actualLunch;
    if ($workedHrs < 0) {
        $workedHrs = 0.0;
    }

    $result['total_duration_hours']  = round($durationHrs, 2);
    $result['lunch_deduction_hours'] = round($actualLunch, 2);

    // Saturday/Sunday OR a public holiday: ALL hours are overtime — no basic hours
    $isWeekend = $dayOfWeek >= 6 || $isHoliday;

    if ($isWeekend) {
        $result['work_hours']     = 0.0;
        $result['overtime_hours'] = round($workedHrs, 2);
    } else {
        // Weekday: first $stdHours = basic, remainder = overtime
        $result['work_hours']     = round(min($workedHrs, $stdHours), 2);
        $result['overtime_hours'] = round(max(0.0, $workedHrs - $stdHours), 2);
    }

    // Night allowance from check-out time + day of week
    $result['night_shift_hours'] = $isOvernight ? calculateNightAllowance($checkOut, $dayOfWeek) : 0.0;

    return $result;
}


/** Convert "HH:MM" or "HH:MM:SS" to seconds since midnight, or null on error */
function timeToSeconds(string $time): ?int {
    $parts = explode(':', $time);
    if (count($parts) < 2) {
        return null;
    }
    $h = (int)$parts[0];
    $m = (int)$parts[1];
    $s = isset($parts[2]) ? (int)$parts[2] : 0;
    return $h * 3600 + $m * 60 + $s;
}

/**
 * Night allowance hours from check-out time string.
 *
 * Rule (per company spec):
 *   - Checkout at 12:00 AM (00:00) or BEFORE midnight (20:00~23:59) → 2 hrs
 *   - Checkout AFTER 12:00 AM (00:01 ~ 05:59)                       → 3 hrs
 *   - Checkout during daytime (06:00 ~ 19:59)                       → 0 hrs
 *
 
 */
function calculateNightAllowance(string $checkOut, int $dayOfWeek): float {
    $parts = explode(':', $checkOut);
    if (count($parts) < 2) {
        return 0.0;
    }

    $h = (int)$parts[0];
    $m = (int)$parts[1];

    // Night allowance rules:
    //  - 20:00 - 23:59 or 00:00 => 2 hrs
    //  - 00:01 - 05:59 => 3 hrs
    //  - 06:00 - 19:59 => 0 hrs
    if ($h === 0) {
        return $m === 0 ? 2.0 : 3.0;
    }

    if ($h >= 20 && $h <= 23) {
        return 2.0;
    }

    if ($h >= 1 && $h <= 5) {
        return 3.0;
    }

    return 0.0;
}

// ============================================================
// SESSION MANAGEMENT
// ============================================================
function initSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_strict_mode', 1);
        ini_set('session.cookie_samesite', 'Strict');
        session_start();
    }
}

function isLoggedIn(): bool {
    initSession();
    return isset($_SESSION['admin_id']) && isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

function requireLogin(): void {
    if (!isLoggedIn()) {
        header('Location: ' . APP_URL . '/login.php');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

function loginAdmin(array $admin): void {
    session_regenerate_id(true);
    $_SESSION['admin_id']       = $admin['id'];
    $_SESSION['admin_username'] = $admin['username'];
    $_SESSION['admin_name']     = $admin['full_name'];
    $_SESSION['admin_logged_in']= true;
    $_SESSION['last_activity']  = time();
    $_SESSION['lang']           = $_SESSION['lang'] ?? 'en';
}

function logoutAdmin(): void {
    session_destroy();
    header('Location: ' . APP_URL . '/login.php');
    exit;
}

// ============================================================
// CSRF PROTECTION
// ============================================================
function generateCSRF(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(CSRF_TOKEN_LENGTH));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRF(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function csrfField(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(generateCSRF()) . '">';
}

// ============================================================
// OUTPUT SANITISATION
// ============================================================
function e(mixed $value): string {
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function sanitize(string $input): string {
    return trim(strip_tags($input));
}

// ============================================================
// FORMATTING
// ============================================================
function formatKRW(float $amount): string {
    return '₩' . number_format($amount, 0, '.', ',');
}

function formatNumber(float $amount, int $decimals = 2): string {
    return number_format($amount, $decimals, '.', ',');
}

function formatDate(string $date, string $format = 'Y년 m월 d일'): string {
    if (empty($date)) {
        return '-';
    }
    return date($format, strtotime($date));
}

// ============================================================
// DATE HELPERS
// ============================================================
function getDaysInMonth(int $year, int $month): int {
    return cal_days_in_month(CAL_GREGORIAN, $month, $year);
}


function clearSundayBonusOverrideForDate(int $employeeId, string $date): void {
    $ts = strtotime($date);
    $isoWeek = (int)date('W', $ts);
    $isoYear = (int)date('o', $ts);
    db()->execute(
        "DELETE FROM sunday_bonus_overrides WHERE employee_id=? AND iso_year=? AND iso_week=?",
        [$employeeId, $isoYear, $isoWeek]
    );
}




function isWeekend(string $date): bool {
    $dow = (int)date('N', strtotime($date));
    return $dow === 6 || $dow === 7;
}

function isHoliday(string $date): bool {
    $row = db()->fetchOne("SELECT id FROM korean_public_holidays WHERE holiday_date = ?", [$date]);
    return $row !== null;
}

// ============================================================
// KOREAN PUBLIC HOLIDAY AUTO-GENERATION
// ------------------------------------------------------------
// Fixed-date (solar) holidays are computed for ANY year.
// Lunar-calendar holidays (Seollal, Chuseok, Buddha's Birthday)
// cannot be derived with simple arithmetic — Korea uses the
// East-Asian lunisolar calendar, whose new-moon/leap-month
// dates require real astronomical calculation. Instead we ship
// an official lookup table (verified against government /
// published sources) covering 2020-2030. Outside that range the
// fixed-date holidays are still auto-generated correctly; only
// the 3 lunar holidays need a manual one-time entry via the
// "Add Holiday" form (extend the table below once official
// dates are published, usually ~1-2 years ahead).
// ============================================================

// Main lunar-holiday day for each year (Y-m-d, main day only)
const KR_LUNAR_HOLIDAYS = [
    'seollal' => [
        2020=>'2020-01-25', 2021=>'2021-02-12', 2022=>'2022-02-01', 2023=>'2023-01-22',
        2024=>'2024-02-10', 2025=>'2025-01-29', 2026=>'2026-02-17', 2027=>'2027-02-07',
        2028=>'2028-01-27', 2029=>'2029-02-12', 2030=>'2030-02-03',
    ],
    'chuseok' => [
        2020=>'2020-10-01', 2021=>'2021-09-21', 2022=>'2022-09-10', 2023=>'2023-09-29',
        2024=>'2024-09-17', 2025=>'2025-10-06', 2026=>'2026-09-25', 2027=>'2027-09-15',
        2028=>'2028-10-03', 2029=>'2029-09-22', 2030=>'2030-09-12',
    ],
    'buddha' => [
        2020=>'2020-04-30', 2021=>'2021-05-19', 2022=>'2022-05-08', 2023=>'2023-05-27',
        2024=>'2024-05-15', 2025=>'2025-05-05', 2026=>'2026-05-24', 2027=>'2027-05-13',
    ],
];

/**
 * Build the full list of Korean public holidays for a given year.
 * Returns array of ['holiday_date','holiday_name_en','holiday_name_kr','is_recurring']
 * Includes automatically-computed substitute holidays (대체공휴일).
 */
function generateKoreanHolidaysForYear(int $year): array {
    $holidays = []; // date => ['en'=>,'kr'=>,'recurring'=>bool,'sub'=>'none'|'sunday'|'weekend']

    $add = function(string $date, string $en, string $kr, bool $recurring, string $sub) use (&$holidays) {
        if (!isset($holidays[$date])) {
            $holidays[$date] = ['en'=>$en,'kr'=>$kr,'recurring'=>$recurring,'sub'=>$sub];
        }
    };

    // ---- Fixed-date (solar) holidays — every year ----
    // Substitute holiday does NOT apply to New Year's Day or Memorial Day (they are
    // "statutory holidays", not "national holidays", per Korean holiday law). The
    // rest get a substitute if they land on EITHER a Saturday or a Sunday.
    $add("$year-01-01", "New Year's Day", '새해', true, 'none');
    $add("$year-03-01", 'Independence Movement Day', '3·1절', true, 'weekend');
    $add("$year-05-05", "Children's Day", '어린이날', true, 'weekend');
    $add("$year-06-06", 'Memorial Day', '현충일', true, 'none');
    $add("$year-08-15", 'Liberation Day', '광복절', true, 'weekend');
    $add("$year-10-03", 'National Foundation Day', '개천절', true, 'weekend');
    $add("$year-10-09", 'Hangul Day', '한글날', true, 'weekend');
    $add("$year-12-25", 'Christmas', '성탄절', true, 'weekend');

    // ---- Lunar-calendar holidays (from lookup table) ----
    // Seollal/Chuseok only get a substitute if a day of the 3-day cluster lands
    // on a SUNDAY (not Saturday) — this is the older, narrower rule that was
    // never widened to Saturdays for these two (unlike the other holidays above).
    if (isset(KR_LUNAR_HOLIDAYS['seollal'][$year])) {
        $main = KR_LUNAR_HOLIDAYS['seollal'][$year];
        $eve  = date('Y-m-d', strtotime($main.' -1 day'));
        $after= date('Y-m-d', strtotime($main.' +1 day'));
        $add($eve,  'Seollal Eve',     '설날 전날', false, 'sunday');
        $add($main, 'Seollal',         '설날',     false, 'sunday');
        $add($after,'Seollal Holiday', '설날 연휴', false, 'sunday');
    }
    if (isset(KR_LUNAR_HOLIDAYS['chuseok'][$year])) {
        $main = KR_LUNAR_HOLIDAYS['chuseok'][$year];
        $eve  = date('Y-m-d', strtotime($main.' -1 day'));
        $after= date('Y-m-d', strtotime($main.' +1 day'));
        $add($eve,  'Chuseok Eve',     '추석 전날', false, 'sunday');
        $add($main, 'Chuseok',         '추석',     false, 'sunday');
        $add($after,'Chuseok Holiday', '추석 연휴', false, 'sunday');
    }
    if (isset(KR_LUNAR_HOLIDAYS['buddha'][$year])) {
        $add(KR_LUNAR_HOLIDAYS['buddha'][$year], "Buddha's Birthday", '부처님오신날', false, 'weekend');
    }

    // ---- Substitute holidays (대체공휴일) ----
    $dates = array_keys($holidays);
    sort($dates);
    $clusters = [];
    $used = [];
    foreach ($dates as $d) {
        if (isset($used[$d])) {
            continue;
        }
        $info = $holidays[$d];
        if ($info['sub'] === 'none') {
            continue;
        }
        if (in_array($info['en'], ['Seollal Eve','Seollal','Seollal Holiday','Chuseok Eve','Chuseok','Chuseok Holiday'])) {
            $base = $this->determineClusterBase($info['en'], $d);
            $c = [$base, date('Y-m-d', strtotime($base.' +1 day')), date('Y-m-d', strtotime($base.' +2 day'))];
            foreach ($c as $cd) {
                $used[$cd] = true;
            }
            $clusters[] = $c;
        } else {
            $used[$d] = true;
            $clusters[] = [$d];
        }
    }

    foreach ($clusters as $cluster) {
        $mode = $holidays[$cluster[0]]['sub']; // 'sunday' or 'weekend'
        $overlaps = false;
        foreach ($cluster as $cd) {
            $dow = (int)date('N', strtotime($cd)); // 6=Sat, 7=Sun
            if ($mode === 'sunday') {
                if ($dow === 7) {
                    $overlaps = true;
                    break;
                }
            } else {
                if ($dow >= 6) {
                    $overlaps = true;
                    break;
                }
            }
        }
        if (!$overlaps) {
            continue;
        }

        $cursor = date('Y-m-d', strtotime(end($cluster).' +1 day'));
        while (true) {
            $dow = (int)date('N', strtotime($cursor));
            if ($dow < 6 && !isset($holidays[$cursor])) {
                break;
            }
            $cursor = date('Y-m-d', strtotime($cursor.' +1 day'));
        }
        $srcName = $holidays[$cluster[0]]['en'];
        $srcName = str_replace([' Eve',' Holiday'], '', $srcName);
        $add($cursor, 'Substitute Holiday ('.$srcName.')', '대체공휴일', false, 'none');
    }

    // ---- Flatten to output rows ----
    $rows = [];
    foreach ($holidays as $date => $info) {
        $rows[] = [
            'holiday_date'    => $date,
            'holiday_name_en' => $info['en'],
            'holiday_name_kr' => $info['kr'],
            'is_recurring'    => $info['recurring'] ? 1 : 0,
        ];
    }
    usort($rows, fn($a,$b) => strcmp($a['holiday_date'], $b['holiday_date']));
    return $rows;
}

/**
 * Ensure the korean_public_holidays table has rows for the given year,
 * generating + inserting them (INSERT IGNORE, so existing/manually-edited
 * rows are never overwritten) if they're missing. Returns number inserted.
 */
function ensureKoreanHolidaysForYear(int $year): int {
    $rows = generateKoreanHolidaysForYear($year);
    $inserted = 0;
    foreach ($rows as $r) {
        $ok = db()->execute(
            "INSERT IGNORE INTO korean_public_holidays (holiday_date,holiday_name_en,holiday_name_kr,is_recurring) VALUES (?,?,?,?)",
            [$r['holiday_date'], $r['holiday_name_en'], $r['holiday_name_kr'], $r['is_recurring']]
        );
        if ($ok) {
            $inserted++;
        }
    }
    return $inserted;
}

function getDayOfWeek(string $date): int {
    return (int)date('N', strtotime($date)); // 1=Mon, 7=Sun
}

// ============================================================
// ACTIVITY LOGGING
// ============================================================
function logActivity(string $action, string $module, int $recordId = 0, string $details = ''): void {
    $adminId = $_SESSION['admin_id'] ?? null;
    db()->insert('activity_logs', [
        'admin_id'   => $adminId,
        'action'     => $action,
        'module'     => $module,
        'record_id'  => $recordId,
        'details'    => $details,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    ]);
}

// ============================================================
// LANGUAGE / TRANSLATION
// ============================================================
function lang(string $key, ?string $fallback = null): string {
    global $translations;
    if (!isset($translations)) {
        loadTranslations($_SESSION['lang'] ?? 'en');
    }
    return $translations[$key] ?? ($fallback ?? $key);
}

function loadTranslations(string $langCode): void {
    global $translations;
    $file = __DIR__ . "/languages/{$langCode}.php";
    if (file_exists($file)) {
        $translations = require $file;
    } else {
        $fallback = __DIR__ . "/kr.php";
        $translations = file_exists($fallback) ? require $fallback : [];
    }
}

// ============================================================
// FILE UPLOAD
// Photo: image only (no PDF). Passbook/ID: image + PDF.
// ============================================================
function uploadFile(array $file, string $type = 'photo'): array {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'Upload error: ' . $file['error']];
    }

    $maxSize = MAX_FILE_SIZE_MB * 1024 * 1024;
    if ($file['size'] > $maxSize) {
        return ['success' => false, 'message' => 'File too large. Max ' . MAX_FILE_SIZE_MB . 'MB'];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime  = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    $imageMimes    = ['image/jpeg','image/jpg','image/png','image/webp'];
    $documentMimes = ['image/jpeg','image/jpg','image/png','image/webp','application/pdf'];
    $allowedMimes  = ($type === 'photo') ? $imageMimes : $documentMimes;
    $allowedLabel  = ($type === 'photo') ? 'JPG, PNG, WEBP' : 'JPG, PNG, WEBP, PDF';

    if (!in_array($mime, $allowedMimes)) {
        return ['success' => false, 'message' => "Invalid file type. Allowed: {$allowedLabel}"];
    }

 $allowedExtensions = ['jpg', 'jpeg', 'png', 'pdf'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowedExtensions, true)) {
        return ['success' => false, 'message' => 'Invalid file extension.'];
    }

    $filename = $type . '_' . time() . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
    $subDir  = match($type) {
        'photo'    => 'photos/',
        'passbook' => 'passbooks/',
        'id_card'  => 'id-cards/',
        default    => 'misc/',
    };

    $uploadDir = UPLOAD_PATH . $subDir;
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    // Canonical path validation: ensure destination stays inside UPLOAD_PATH
    $realUploadRoot = realpath(UPLOAD_PATH);
    $realTargetDir  = realpath($uploadDir);
    if ($realUploadRoot === false || $realTargetDir === false
        || !str_starts_with($realTargetDir . DIRECTORY_SEPARATOR, $realUploadRoot . DIRECTORY_SEPARATOR)) {
        return ['success' => false, 'message' => 'Invalid upload path'];
    }

    $destination = $realTargetDir . DIRECTORY_SEPARATOR . $filename;
    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['success' => false, 'message' => 'Failed to save file'];
    }
    return [
        'success'  => true,
        'path'     => $subDir . $filename,
        'filename' => $filename,
        'url'      => APP_URL . '/uploads/' . $subDir . $filename,
    ];
}

// ============================================================
// SETTINGS (cached per request)
// ============================================================
function getSettings(): array {
    static $settings = null;
    if ($settings === null) {
        $settings = db()->fetchOne("SELECT * FROM company_settings LIMIT 1") ?? [];
    }
    return $settings;
}

// ============================================================
// PAGINATION
// ============================================================
function paginate(int $total, int $perPage, int $currentPage): array {
    $totalPages = (int)ceil($total / $perPage);
    $offset     = ($currentPage - 1) * $perPage;
    return [
        'total'        => $total,
        'per_page'     => $perPage,
        'current_page' => $currentPage,
        'total_pages'  => $totalPages,
        'offset'       => $offset,
        'has_prev'     => $currentPage > 1,
        'has_next'     => $currentPage < $totalPages,
    ];
}