<?php
// ============================================================
// SL INDUSTRY - Unified API  (v3)
// ============================================================
// Changes from v2:
//
//   SMART ATTENDANCE AUTO-CALCULATION (new business rules):
//     save_attendance now accepts only employee, date, check-in,
//     check-out. All computed values (work_hours, overtime_hours,
//     night_shift_hours, total_duration, lunch_deduction) are
//     derived automatically by calculateAttendanceFromTimes().
//     Admin can set is_manual_override=1 to supply custom values.
//
//   WEEKLY SUNDAY BONUS:
//     Bonus logic moved to PayrollEngine (per-ISO-week).
//     API passes through sunday_bonus_weeks for display.
//
//   ENCRYPTION:
//     account_number and id_card_passport_number are encrypted
//     before storage via encryptField(). Duplicates detected via
//     hashField() SHA-256 hashes.
//
//   COMPLIANCE (new requirements):
//     - Sensitive field encryption on save / decrypt on read.
//     - audit log for attendance deletion (MAJ-04).
//     - is_manual_override flag tracked in audit log.
//     - is_holiday auto-set (MIN-01).
//     - Soft-deleted employee guard (MIN-04).
//     - All previous MAJ/CRIT fixes preserved.
// ============================================================
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/PayrollEngine.php';

initSession();
header('Content-Type: application/json; charset=utf-8');

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (!isLoggedIn()) {
    http_response_code(401);
    die(json_encode(['success' => false, 'error' => 'Unauthorized']));
}

$action = trim($_REQUEST['action'] ?? '');

$body  = [];
$raw   = file_get_contents('php://input');
if ($raw) {
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
        $body = $decoded;
    }
}
$input = array_merge($_POST, $body);

define('PHP_OUTPUT_STREAM', 'php://output');

function p(string $key, mixed $default = null): mixed { global $input; return $input[$key] ?? $default; }
function g(string $key, mixed $default = null): mixed { return $_GET[$key] ?? $default; }
function ok(mixed $data = null, string $msg = ''): void {
    $r = ['success' => true];
    if ($data !== null) {
        $r['data'] = $data;
    }
    if ($msg) {
        $r['message'] = $msg;
    }
    echo json_encode($r); exit;
}
function fail(string $msg, int $code = 400): void {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $msg]); exit;
}
function require_fields(array $keys): void {
    global $input;
    foreach ($keys as $k) {
        if (!isset($input[$k]) || $input[$k] === '') {
            fail("Field '$k' is required.");
        }
    }
}

define('ERROR_MISSING_ID', 'Missing id.');

try {

// ============================================================
// EMPLOYEES
// ============================================================
if ($action === 'get_employees') {
    $search = g('search','');
    $status = g('status','');
    $type   = g('type','');
    $sql    = "SELECT id, employee_id, full_name, employee_type, phone, email,
                      country, nationality, date_of_birth, join_date,
                      bank_name, account_holder_name,
                      account_number_enc, id_card_passport_number_enc,
                      hourly_rate, tax_rate, employment_status,
                      emergency_contact, notes, photo_path,
                      passbook_photo_path, id_card_photo_path,
                      deleted_at, created_at, updated_at
               FROM employees WHERE deleted_at IS NULL";
    $params = [];
    if ($search) {
        $sql .= " AND (full_name LIKE ? OR employee_id LIKE ? OR phone LIKE ?)";
        $s = "%$search%"; $params = [$s,$s,$s];
    }
    if ($status) { $sql .= " AND employment_status = ?"; $params[] = $status; }
    if ($type)   { $sql .= " AND employee_type = ?";     $params[] = $type; }
    $sql .= " ORDER BY full_name";
    $rows = db()->fetchAll($sql, $params);
    // Decrypt sensitive fields for each row
    foreach ($rows as &$row) {
        $row['account_number']          = decryptField($row['account_number_enc'] ?? null);
        $row['id_card_passport_number'] = decryptField($row['id_card_passport_number_enc'] ?? null);
        unset($row['account_number_enc'], $row['id_card_passport_number_enc']);
    }
    unset($row);
    ok($rows);
}

if ($action === 'get_employee') {
    $id = (int)g('id',0);
    if (!$id) {
        fail(ERROR_MISSING_ID);
    }
    $row = db()->fetchOne("SELECT * FROM employees WHERE id = ?", [$id]);
    if (!$row) {
        fail('Employee not found.');
    }
    $row['account_number']          = decryptField($row['account_number_enc'] ?? null);
    $row['id_card_passport_number'] = decryptField($row['id_card_passport_number_enc'] ?? null);
    unset($row['account_number_enc'],$row['account_number_hash'],
          $row['id_card_passport_number_enc'],$row['id_card_passport_hash']);
    ok($row);
}

if ($action === 'save_employee') {
    require_fields(['employee_id','full_name','join_date','hourly_rate']);
    $id     = (int)p('id', 0);
    $type   = strtolower(p('employee_type','korean'));
    if (!in_array($type,['korean','foreign'])) {
        $type = 'korean';
    }
    $status = strtolower(p('employment_status','active'));
    if (!in_array($status,['active','inactive'])) {
        $status = 'active';
    }

    // ── Full backend validation ──────────────────────────────
    if (empty(trim((string)p('phone','')))) {
        fail('Phone number is required.');
    }
    if (empty(trim((string)p('country','')))) {
        fail('Country is required.');
    }
    if (empty(trim((string)p('bank_name','')))) {
        fail('Bank name is required.');
    }

    $accountNumber = trim((string)p('account_number',''));
    if ($accountNumber === '') {
        fail('Account number is required.');
    }
    if (!ctype_digit($accountNumber)) {
        fail('Account number must be numeric digits only.');
    }

    if (empty(trim((string)p('account_holder_name','')))) {
        fail('Account holder name is required.');
    }

    $idCardNo = trim((string)p('id_card_passport_number',''));
    if ($idCardNo === '') {
        fail('ID card / passport number is required.');
    }

    $hourlyRate = (float)p('hourly_rate', 0);
    if ($hourlyRate <= 0) {
        fail('Hourly rate must be greater than zero.');
    }

    $taxRate = (float)p('tax_rate', 3.3);
    if ($taxRate < 0 || $taxRate > 100) {
        fail('Tax rate must be between 0 and 100.');
    }

    $joinDate = p('join_date');
    if ($joinDate > date('Y-m-d')) {
        fail('Join date cannot be a future date.');
    }

    // ── Duplicate checks ────────────────────────────────────
    $notSelf = $id ? " AND id <> $id" : '';
    $dupEmpId = db()->fetchOne(
        "SELECT id FROM employees WHERE employee_id = ? AND deleted_at IS NULL$notSelf",
        [p('employee_id')]
    );
    if ($dupEmpId) {
        fail('Employee ID already exists. Please use a unique Employee ID.');
    }

    $idCardHash = hashField($idCardNo);
    $dupIdCard  = db()->fetchOne(
        "SELECT id FROM employees WHERE id_card_passport_hash = ? AND deleted_at IS NULL$notSelf",
        [$idCardHash]
    );
    if ($dupIdCard) {
        fail('ID card / passport number is already registered to another employee.');
    }

    // ── Encrypt sensitive fields ─────────────────────────────
    $accEnc     = encryptField($accountNumber);
    $accHash    = hashField($accountNumber);
    $idCardEnc  = encryptField($idCardNo);

    $fields = [
        'employee_id'               => p('employee_id'),
        'full_name'                 => p('full_name'),
        'employee_type'             => $type,
        'phone'                     => p('phone'),
        'email'                     => p('email') ?: null,
        'country'                   => p('country'),
        'nationality'               => p('nationality') ?: p('country'),
        'date_of_birth'             => p('date_of_birth') ?: null,
        'join_date'                 => $joinDate,
        'bank_name'                 => p('bank_name'),
        'account_holder_name'       => p('account_holder_name'),
        'account_number_enc'        => $accEnc,
        'account_number_hash'       => $accHash,
        'id_card_passport_number_enc' => $idCardEnc,
        'id_card_passport_hash'     => $idCardHash,
        'hourly_rate'               => $hourlyRate,
        'tax_rate'                  => $taxRate,
        'employment_status'         => $status,
        'emergency_contact'         => p('emergency_contact') ?: null,
        'notes'                     => p('notes') ?: null,
    ];

    if ($id) {
        $fields['updated_at'] = date('Y-m-d H:i:s');
        db()->update('employees', $fields, 'id = ?', [$id]);
        logActivity('UPDATE_EMPLOYEE','employees',$id,"Updated: {$fields['full_name']}");
        ok(null, 'Employee updated successfully.');
    } else {
        $newId = db()->insert('employees', $fields);
        logActivity('ADD_EMPLOYEE','employees',$newId,"Added: {$fields['full_name']}");
        ok(['id' => $newId], 'Employee added successfully.');
    }
}

if ($action === 'delete_employee') {
    $id = (int)p('id',0);
    if (!$id) {
        fail(ERROR_MISSING_ID);
    }
    $emp = db()->fetchOne("SELECT * FROM employees WHERE id=? AND deleted_at IS NULL", [$id]);
    if (!$emp) {
        fail('Employee not found.');
    }

    // Delete child records that have no ON DELETE CASCADE (would block employee delete otherwise)
    db()->execute("DELETE FROM payroll_records WHERE employee_id=?", [$id]);
    db()->execute("DELETE FROM due_salaries WHERE employee_id=?", [$id]);
    db()->execute("DELETE FROM attendance_audit_log WHERE employee_id=?", [$id]);
    db()->execute("DELETE FROM sunday_bonus_overrides WHERE employee_id=?", [$id]);
    // Explicit delete (don't rely on DB-level ON DELETE CASCADE, in case it's missing/inactive on the live server)
    db()->execute("DELETE FROM attendance WHERE employee_id=?", [$id]);
    db()->execute("DELETE FROM salary_advances WHERE employee_id=?", [$id]);

    // Remove uploaded files (photo, ID card, passbook)
    foreach (['photo_path', 'passbook_photo_path', 'id_card_photo_path'] as $col) {
        if (!empty($emp[$col])) {
            $filePath = UPLOAD_PATH . $emp[$col];
            if (is_file($filePath)) {
                @unlink($filePath);
            }
        }
    }

    db()->execute("DELETE FROM employees WHERE id=?", [$id]);
    logActivity('DELETE_EMPLOYEE','employees',$id,"Hard-deleted: {$emp['full_name']}");
    ok(null, 'Employee and all related data deleted.');
}

// ============================================================
// FILE UPLOAD
// ============================================================
if ($action === 'upload_file') {
    if (empty($_FILES['file']['tmp_name'])) {
        fail('No file uploaded.');
    }
    $type = $_POST['type'] ?? 'photo';
    if (!in_array($type, ['photo', 'passbook', 'id_card'], true)) {
        fail('Invalid file type.');
    }
    
    $empId = (int)($_POST['employee_id'] ?? 0);
    $result = uploadFile($_FILES['file'], $type);
    if (!$result['success']) {
        fail($result['message']);
    }
    if ($empId) {
        $col = match($type) {
            'passbook' => 'passbook_photo_path',
            'id_card'  => 'id_card_photo_path',
            default    => 'photo_path',
        };
        db()->execute("UPDATE employees SET $col=? WHERE id=?", [$result['path'], $empId]);
    }
    ok(['path' => $result['path'], 'url' => $result['url']], 'File uploaded.');
}

if ($action === 'list_uploads') {
    $subDirs = ['photos', 'passbooks', 'id-cards', 'misc'];
    $currentLogo = db()->fetchOne("SELECT company_logo FROM company_settings LIMIT 1")['company_logo'] ?? '';

    $usedPaths = [];
    foreach (db()->fetchAll("SELECT photo_path, passbook_photo_path, id_card_photo_path FROM employees WHERE deleted_at IS NULL") as $row) {
        foreach (['photo_path', 'passbook_photo_path', 'id_card_photo_path'] as $col) {
            if (!empty($row[$col])) {
                $usedPaths[$row[$col]] = true;
            }
        }
    }

    $files = [];
    foreach ($subDirs as $subDir) {
        $dir = UPLOAD_PATH . $subDir;
        if (!is_dir($dir)) {
            continue;
        }
        foreach (scandir($dir) as $fname) {
            if ($fname === '.' || $fname === '..' || $fname === '.gitkeep') {
                continue;
            }
            $full = $dir . '/' . $fname;
            if (!is_file($full)) {
                continue;
            }
            $relPath = $subDir . '/' . $fname;
            $files[] = [
                'path'     => $relPath,
                'url'      => APP_URL . '/uploads/' . $relPath,
                'size'     => filesize($full),
                'modified' => date('Y-m-d H:i:s', filemtime($full)),
                'is_logo'  => ($relPath === $currentLogo),
                'in_use'   => isset($usedPaths[$relPath]) || ($relPath === $currentLogo),
            ];
        }
    }
    usort($files, fn($a, $b) => strcmp($b['modified'], $a['modified']));
    ok($files);
}

if ($action === 'delete_upload') {
    $path = p('path', '');
    if (!$path) {
        fail('No file path provided.');
    }
    $base = realpath(UPLOAD_PATH);
    $real = realpath(UPLOAD_PATH . $path);
    if (!$real || !$base || strpos($real, $base) !== 0) {
        fail('Invalid file path.');
    }
    if (!is_file($real)) {
        fail('File not found.');
    }
    if (!unlink($real)) {
        fail('Failed to delete file.');
    }

    db()->execute("UPDATE employees SET photo_path=NULL WHERE photo_path=?", [$path]);
    db()->execute("UPDATE employees SET passbook_photo_path=NULL WHERE passbook_photo_path=?", [$path]);
    db()->execute("UPDATE employees SET id_card_photo_path=NULL WHERE id_card_photo_path=?", [$path]);
    db()->execute("UPDATE company_settings SET company_logo='' WHERE company_logo=?", [$path]);

    logActivity('DELETE_FILE', 'uploads', 0, "Deleted upload: $path");
    ok(null, 'File deleted.');
}

// ============================================================
// ATTENDANCE
// ============================================================
if ($action === 'get_attendance') {
    $year  = (int)g('year',  date('Y'));
    $month = (int)g('month', date('n'));
    $empId = (int)g('employee_id', 0);
    $start = sprintf('%04d-%02d-01', $year, $month);
    $end   = date('Y-m-t', strtotime($start));

   $sql    = "SELECT a.*, e.full_name, e.employee_id AS emp_code, e.employee_type
               FROM attendance a   JOIN employees e ON a.employee_id = e.id
               WHERE a.attendance_date BETWEEN ? AND ?";
    $params = [$start, $end];
    if ($empId) {
        $sql .= " AND a.employee_id=?";
        $params[] = $empId;
    }
    $sql .= " ORDER BY a.employee_id, a.attendance_date";
    ok(db()->fetchAll($sql, $params));
}

if ($action === 'save_attendance') {
    require_fields(['employee_id','attendance_date','attendance_type']);

    $empId   = (int)p('employee_id');
    $date    = p('attendance_date');
    $attType = p('attendance_type');
    $dow     = (int)date('N', strtotime($date));   // 1=Mon…7=Sun
    $isWeekend = $dow >= 6 ? 1 : 0;

    // MIN-04: verify employee is not soft-deleted
    $emp = db()->fetchOne("SELECT id FROM employees WHERE id=? AND deleted_at IS NULL", [$empId]);
    if (!$emp) {
        fail('Employee not found or has been deleted.');
    }

    $checkIn  = p('check_in_time')  ?: null;
    $checkOut = p('check_out_time') ?: null;

   // MAJ-07: check_out must be after check_in (overnight allowed if checkout < 12:00 PM)
    if ($checkIn && $checkOut) {
        $inSec  = timeToSeconds($checkIn);
        $outSec = timeToSeconds($checkOut);
        if ($outSec !== null && $inSec !== null && $outSec <= $inSec) {
            [$h] = explode(':', $checkOut);
            if ((int)$h >= 12) {
                fail('Check-out time must be later than check-in time.');
            }
        }
    }

    // ── SMART AUTO-CALCULATION ────────────────────────────────
    // If admin provided check-in and check-out, compute everything.
    // If is_manual_override=1, use the values they supplied directly.
    $isManualOverride = (int)p('is_manual_override', 0);

    $settings      = getSettings();
    $stdHours      = (float)($settings['standard_work_hours'] ?? 8.0);
    $lunchHrs      = (float)($settings['lunch_break_hours']   ?? 1.0);

    // MIN-01: auto-detect public holiday (moved up so it can affect the OT calc below)
    $isHolidayDay = isHoliday($date) ? 1 : 0;

    if (!$isManualOverride && $checkIn && $checkOut && in_array($attType, ['full_day','half_day'])) {
        // Auto-calculate all values from times
        $calc = calculateAttendanceFromTimes($checkIn, $checkOut, $dow, $attType, $stdHours, $lunchHrs, (bool)$isHolidayDay);
        $totalDuration  = $calc['total_duration_hours'];
        $lunchDeduction = $calc['lunch_deduction_hours'];
        $workHours      = $calc['work_hours'];
        $otHours        = $calc['overtime_hours'];
        $nightHrs       = $calc['night_shift_hours'];

  } else {
        // Manual or no times
        $totalDuration  = (float)p('total_duration_hours', 0);
        $lunchDeduction = (float)p('lunch_deduction_hours', 0);
        $workHours      = (float)p('work_hours', 0);
        $otHours        = (float)p('overtime_hours', 0);
        // If manually overridden, respect the posted night hours (do NOT
        // silently recalculate from checkout — that was discarding edits).
        $nightHrs = 0.0;
        if ($isManualOverride) {
            $nightHrs = (float)p('night_shift_hours', 0);
        } elseif ($checkOut && in_array($attType, ['full_day','half_day'])) {
            $nightHrs = calculateNightAllowance($checkOut, $dow);
        }
    }

    // Non-productive types: zero everything
    if (in_array($attType, ['absent','paid_leave','unpaid_leave'])) {
        $totalDuration = $lunchDeduction = $workHours = $otHours = $nightHrs = 0.0;
        $isManualOverride = 0;
    }

    $fields = [
        'employee_id'          => $empId,
        'attendance_date'      => $date,
        'attendance_type'      => $attType,
        'check_in_time'        => $checkIn,
        'check_out_time'       => $checkOut,
        'total_duration_hours' => $totalDuration,
        'lunch_deduction_hours'=> $lunchDeduction,
        'work_hours'           => $workHours,
        'overtime_hours'       => $otHours,
        'night_shift_hours'    => $nightHrs,
        'holiday_hours'        => (float)p('holiday_hours', 0),
        'is_manual_override'   => $isManualOverride,
        'is_holiday'           => $isHolidayDay,
        'is_weekend'           => $isWeekend,
        'day_of_week'          => $dow,
        'remarks'              => p('remarks') ?: null,
        'created_by'           => $_SESSION['admin_id'] ?? null,
    ];

    if ($dow >= 1 && $dow <= 5) {
        clearSundayBonusOverrideForDate($empId, $date);
    }

    $existing = db()->fetchOne(
        "SELECT * FROM attendance WHERE employee_id=? AND attendance_date=?",
        [$empId, $date]
    );

    if ($existing) {
        // Write audit log for each changed field
        $auditFields = ['attendance_type','check_in_time','check_out_time',
                        'total_duration_hours','lunch_deduction_hours',
                        'work_hours','overtime_hours','night_shift_hours',
                        'holiday_hours','is_manual_override','remarks'];
        $adminId = $_SESSION['admin_id'] ?? null;
        $reason  = p('remarks') ?: 'Manual update';
        foreach ($auditFields as $fld) {
            $oldVal = (string)($existing[$fld] ?? '');
            $newVal = (string)($fields[$fld]   ?? '');
            if ($oldVal !== $newVal) {
                db()->insert('attendance_audit_log', [
                    'attendance_id'  => $existing['id'],
                    'employee_id'    => $empId,
                    'field_changed'  => $fld,
                    'previous_value' => $oldVal,
                    'new_value'      => $newVal,
                    'modified_by'    => $adminId,
                    'remarks'        => $reason,
                ]);
            }
        }
        unset($fields['employee_id'], $fields['attendance_date'], $fields['created_by']);
        $fields['updated_at'] = date('Y-m-d H:i:s');
        db()->update('attendance', $fields, 'id=?', [$existing['id']]);
        logActivity('UPDATE_ATTENDANCE','attendance',$existing['id'],"Updated $date");
        ok(null, 'Attendance updated.');
    } else {
        $newId = db()->insert('attendance', $fields);
        logActivity('ADD_ATTENDANCE','attendance',$newId,"Added $date");
        ok(['id' => $newId, 'calculated' => [
            'total_duration_hours'  => $totalDuration,
            'lunch_deduction_hours' => $lunchDeduction,
            'work_hours'            => $workHours,
            'overtime_hours'        => $otHours,
            'night_shift_hours'     => $nightHrs,
        ]], 'Attendance saved.');
    }
}

// PREVIEW — calculate attendance values from times without saving
if ($action === 'preview_attendance') {
    $checkIn  = p('check_in_time')  ?: '';
    $checkOut = p('check_out_time') ?: '';
    $date     = p('attendance_date') ?: date('Y-m-d');
    $attType  = p('attendance_type','full_day');
    if (!$checkIn || !$checkOut) {
        fail('check_in_time and check_out_time are required.');
    }

    $dow      = (int)date('N', strtotime($date));
    $settings = getSettings();
    $stdHours = (float)($settings['standard_work_hours'] ?? 8.0);
    $lunchHrs = (float)($settings['lunch_break_hours']   ?? 1.0);
    $calc     = calculateAttendanceFromTimes($checkIn, $checkOut, $dow, $attType, $stdHours, $lunchHrs);
    ok($calc);
}

if ($action === 'delete_attendance') {
    $id = (int)p('id',0);
    if (!$id) {
        fail(ERROR_MISSING_ID);
    }

    // MAJ-04: write final audit log before deleting
    $existing = db()->fetchOne("SELECT * FROM attendance WHERE id=?", [$id]);
    if ($existing) {
        db()->insert('attendance_audit_log', [
            'attendance_id'  => null,
            'employee_id'    => $existing['employee_id'],
            'field_changed'  => 'deleted',
            'previous_value' => json_encode($existing),
            'new_value'      => '',
            'modified_by'    => $_SESSION['admin_id'] ?? null,
            'remarks'        => 'Record hard-deleted',
        ]);
    }
    db()->execute("DELETE FROM attendance WHERE id=?", [$id]);
    if ($existing) {
        clearSundayBonusOverrideForDate((int)$existing['employee_id'], $existing['attendance_date']);
    }
    logActivity('DELETE_ATTENDANCE','attendance',$id,'Deleted record');
    ok(null, 'Attendance deleted.');
}

// ============================================================
// SUNDAY BONUS MANUAL OVERRIDES
// ============================================================
if ($action === 'get_sunday_bonus_overrides') {
    $empId = (int)g('employee_id', 0);
    $sql    = "SELECT employee_id, iso_year, iso_week, override_hours, remarks FROM sunday_bonus_overrides";
    $params = [];
    if ($empId) { $sql .= " WHERE employee_id=?"; $params[] = $empId; }
    ok(db()->fetchAll($sql, $params));
}

if ($action === 'save_sunday_bonus_override') {
    require_fields(['employee_id','iso_year','iso_week','override_hours']);

    $empId  = (int)p('employee_id');
    $isoYr  = (int)p('iso_year');
    $isoWk  = (int)p('iso_week');
    $hours  = (float)p('override_hours');
    if ($hours < 0 || $hours > 16) {
        fail('override_hours must be between 0 and 16.');
    }

    $emp = db()->fetchOne("SELECT id FROM employees WHERE id=? AND deleted_at IS NULL", [$empId]);
    if (!$emp) {
        fail('Employee not found or has been deleted.');
    }

    $adminId = $_SESSION['admin_id'] ?? null;
    $remarks = p('remarks') ?: 'Manual Sunday Bonus override';

    $existing = db()->fetchOne(
        "SELECT * FROM sunday_bonus_overrides WHERE employee_id=? AND iso_year=? AND iso_week=?",
        [$empId, $isoYr, $isoWk]
    );

    if ($existing) {
        db()->insert('attendance_audit_log', [
            'attendance_id'  => null,
            'employee_id'    => $empId,
            'field_changed'  => "sunday_bonus_override (ISO {$isoYr}-W{$isoWk})",
            'previous_value' => (string)$existing['override_hours'],
            'new_value'      => (string)$hours,
            'modified_by'    => $adminId,
            'remarks'        => $remarks,
        ]);
        db()->update('sunday_bonus_overrides',
            ['override_hours' => $hours, 'modified_by' => $adminId, 'remarks' => $remarks],
            'id=?', [$existing['id']]
        );
        logActivity('UPDATE_SUNDAY_BONUS_OVERRIDE','sunday_bonus_overrides',$existing['id'],"ISO {$isoYr}-W{$isoWk} => {$hours}h");
        ok(null, 'Sunday Bonus override updated.');
    } else {
        db()->insert('attendance_audit_log', [
            'attendance_id'  => null,
            'employee_id'    => $empId,
            'field_changed'  => "sunday_bonus_override (ISO {$isoYr}-W{$isoWk})",
            'previous_value' => 'auto',
            'new_value'      => (string)$hours,
            'modified_by'    => $adminId,
            'remarks'        => $remarks,
        ]);
        $newId = db()->insert('sunday_bonus_overrides', [
            'employee_id'    => $empId,
            'iso_year'       => $isoYr,
            'iso_week'       => $isoWk,
            'override_hours' => $hours,
            'modified_by'    => $adminId,
            'remarks'        => $remarks,
        ]);
        logActivity('ADD_SUNDAY_BONUS_OVERRIDE','sunday_bonus_overrides',$newId,"ISO {$isoYr}-W{$isoWk} => {$hours}h");
        ok(['id' => $newId], 'Sunday Bonus override saved.');
    }
}

if ($action === 'delete_sunday_bonus_override') {
    require_fields(['employee_id','iso_year','iso_week']);
    $empId = (int)p('employee_id');
    $isoYr = (int)p('iso_year');
    $isoWk = (int)p('iso_week');

    $existing = db()->fetchOne(
        "SELECT * FROM sunday_bonus_overrides WHERE employee_id=? AND iso_year=? AND iso_week=?",
        [$empId, $isoYr, $isoWk]
    );
    if (!$existing) { ok(null, 'No override existed; already automatic.'); }

    db()->insert('attendance_audit_log', [
        'attendance_id'  => null,
        'employee_id'    => $empId,
        'field_changed'  => "sunday_bonus_override (ISO {$isoYr}-W{$isoWk})",
        'previous_value' => (string)$existing['override_hours'],
        'new_value'      => 'auto',
        'modified_by'    => $_SESSION['admin_id'] ?? null,
        'remarks'        => 'Reverted to automatic calculation',
    ]);
    db()->execute("DELETE FROM sunday_bonus_overrides WHERE id=?", [$existing['id']]);
    logActivity('DELETE_SUNDAY_BONUS_OVERRIDE','sunday_bonus_overrides',$existing['id'],"ISO {$isoYr}-W{$isoWk} reverted to auto");
    ok(null, 'Sunday Bonus override removed; reverted to automatic calculation.');
}

// ============================================================
// SALARY ADVANCES
// ============================================================
if ($action === 'get_advances') {
    $empId = (int)g('employee_id',0);
    $sql = "SELECT a.*, e.full_name, e.employee_id AS emp_code
            FROM salary_advances a
            JOIN employees e ON a.employee_id = e.id WHERE 1=1";
    $params = [];
    if ($empId) { $sql .= " AND a.employee_id=?"; $params[] = $empId; }
    $sql .= " ORDER BY a.advance_date DESC";
    ok(db()->fetchAll($sql, $params));
}

if ($action === 'save_advance') {
    require_fields(['employee_id','amount','advance_date']);
    $amt = (float)p('amount');
    if ($amt <= 0) {
        fail('Advance amount must be greater than zero.');
    }
    $fields = [
        'employee_id'  => (int)p('employee_id'),
        'advance_date' => p('advance_date'),
        'amount'       => $amt,
        'reason'       => p('reason') ?: null,
        'status'       => 'pending',
        'created_by'   => $_SESSION['admin_id'] ?? null,
    ];
    $newId = db()->insert('salary_advances', $fields);
    logActivity('ADD_ADVANCE','salary_advances',$newId,'Added advance ₩'.p('amount'));
    ok(['id' => $newId], 'Advance saved.');
}

if ($action === 'delete_advance') {
    $id = (int)p('id',0);
    if (!$id) {
        fail('Missing id.');
    }
    db()->execute("DELETE FROM salary_advances WHERE id=? AND status='pending'", [$id]);
    logActivity('DELETE_ADVANCE','salary_advances',$id,'Deleted');
    ok(null, 'Advance deleted.');
}

if ($action === 'save_due_salary') {
    require_fields(['employee_id','amount']);
    $amt = (float)p('amount');
    if ($amt <= 0) {
        fail('Due salary amount must be greater than zero.');
    }
    $fields = [
        'employee_id' => (int)p('employee_id'),
        'amount'      => $amt,
        'reason'      => p('reason') ?: 'Manual due salary addition',
        'status'      => 'pending',
    ];
    $newId = db()->insert('due_salaries', $fields);
    logActivity('ADD_DUE_SALARY','due_salaries',$newId,'Manually added due salary ₩'.p('amount'));
    ok(['id' => $newId], 'Due salary added.');
}



// ============================================================
// PAYROLL
// ============================================================
if ($action === 'get_payroll') {
    $year  = (int)g('year',  date('Y'));
    $month = (int)g('month', date('n'));
    $rows  = db()->fetchAll(
        "SELECT pr.*, e.full_name, e.employee_id AS emp_code, e.employee_type,
                pp.period_year, pp.period_month
         FROM payroll_records pr
         JOIN employees e ON pr.employee_id = e.id
         JOIN payroll_periods pp ON pr.payroll_period_id = pp.id
         WHERE pp.period_year=? AND pp.period_month=? AND e.deleted_at IS NULL
         ORDER BY e.full_name",
        [$year, $month]
    );
    $summary = ['total_gross'=>0.0,'total_tax'=>0.0,'total_advances'=>0.0,'total_net'=>0.0];
    foreach ($rows as $r) {
        $summary['total_gross']    += (float)$r['gross_salary'];
        $summary['total_tax']      += (float)$r['tax_amount'];
        $summary['total_advances'] += (float)$r['advance_deduction'];
        $summary['total_net']      += (float)$r['net_salary'];
    }
    ok(['records' => $rows, 'summary' => $summary]);
}

if ($action === 'get_payroll_periods') {
    ok(db()->fetchAll("SELECT * FROM payroll_periods ORDER BY period_year DESC, period_month DESC LIMIT 24"));
}

if ($action === 'generate_payroll') {
    $year   = (int)p('year',  date('Y'));
    $month  = (int)p('month', date('n'));
    $engine = new PayrollEngine();
    $result = $engine->generateMonthlyPayroll($year, $month);
    logActivity('GENERATE_PAYROLL','payroll_periods',$result['period_id'],
        "Generated $year-".str_pad($month,2,'0',STR_PAD_LEFT));
    ok($result, "Payroll generated for $year-".str_pad($month,2,'0',STR_PAD_LEFT).".");
}

if ($action === 'approve_payroll') {
    $periodId = (int)p('period_id',0);
    if (!$periodId) {
        fail('Missing period_id.');
    }
    db()->execute(
        "UPDATE payroll_periods SET status='approved',approved_by=?,approved_at=NOW() WHERE id=?",
        [$_SESSION['admin_id'], $periodId]
    );
    db()->execute("UPDATE payroll_records SET status='approved' WHERE payroll_period_id=?", [$periodId]);
    logActivity('APPROVE_PAYROLL','payroll_periods',$periodId,'Approved');
    ok(null, 'Payroll approved.');
}

if ($action === 'approve_all_payroll') {
    $year  = (int)p('year',  date('Y'));
    $month = (int)p('month', date('n'));
    $period = db()->fetchOne(
        "SELECT id,status FROM payroll_periods WHERE period_year=? AND period_month=?",[$year,$month]);
    if (!$period) {
        fail('No payroll period found for this month.');
    }
    if ($period['status'] === 'paid') {
        fail('Payroll already marked as paid.');
    }
    db()->execute(
        "UPDATE payroll_periods SET status='approved',approved_by=?,approved_at=NOW() WHERE id=?",
        [$_SESSION['admin_id'], $period['id']]
    );
    db()->execute("UPDATE payroll_records SET status='approved' WHERE payroll_period_id=?",[$period['id']]);
    logActivity('APPROVE_ALL_PAYROLL','payroll_periods',$period['id'],"Approved all for $year-$month");
    ok(null, 'All payroll records approved.');
}

if ($action === 'mark_payroll_paid') {
    $periodId = (int)p('period_id',0);
    if (!$periodId) {
        fail('Missing period_id.');
    }
    $period = db()->fetchOne("SELECT * FROM payroll_periods WHERE id=?", [$periodId]);
    if (!$period) {
        fail('Period not found.');
    }
    if ($period['status'] === 'paid') {
        fail('Already marked as paid.');
    }

    db()->execute("UPDATE payroll_periods SET status='paid' WHERE id=?", [$periodId]);
    db()->execute("UPDATE payroll_records SET status='paid',payment_date=CURDATE() WHERE payroll_period_id=?",[$periodId]);

    $records = db()->fetchAll(
        "SELECT employee_id, advance_deduction, due_salary_carried FROM payroll_records WHERE payroll_period_id=?",
        [$periodId]
    );
    foreach ($records as $rec) {
        if ($rec['advance_deduction'] > 0) {
            $pending = db()->fetchAll(
                "SELECT id, amount FROM salary_advances WHERE employee_id=? AND status='pending' ORDER BY advance_date ASC",
                [$rec['employee_id']]
            );
            $remaining = (float)$rec['advance_deduction'];
            foreach ($pending as $adv) {
                if ($remaining <= 0) {
                    break;
                }
                db()->execute(
                    "UPDATE salary_advances SET status='deducted',deducted_date=CURDATE(),payroll_record_id=? WHERE id=?",
                    [$periodId, $adv['id']]
                );
                $remaining -= (float)$adv['amount'];
            }
        }
        if ($rec['due_salary_carried'] > 0) {
            db()->insert('due_salaries', [
                'employee_id'       => $rec['employee_id'],
                'source_payroll_id' => $periodId,
                'amount'            => $rec['due_salary_carried'],
                'reason'            => 'Negative balance from payroll period '
                    . $period['period_year'] . '-' . str_pad($period['period_month'],2,'0',STR_PAD_LEFT),
                'status'            => 'pending',
            ]);
        }
    }
    logActivity('MARK_PAID','payroll_periods',$periodId,'Marked as paid, advances settled');
    ok(null, 'Payroll marked as paid. Advances settled.');
}

// ============================================================
// DASHBOARD
// ============================================================
if ($action === 'get_dashboard') {
   // NEW
$totalEmp  = (int)(db()->fetchOne("SELECT COUNT(*) AS c FROM employees WHERE deleted_at IS NULL")['c'] ?? 0);
$activeEmp = (int)(db()->fetchOne("SELECT COUNT(*) AS c FROM employees WHERE deleted_at IS NULL AND employment_status='active'")['c'] ?? 0);
    $year  = (int)date('Y'); $month = (int)date('n');
    $payrollRow = db()->fetchOne(
        "SELECT COALESCE(SUM(pr.net_salary),0) AS total FROM payroll_records pr
         JOIN payroll_periods pp ON pr.payroll_period_id=pp.id
         WHERE pp.period_year=? AND pp.period_month=?", [$year,$month]);
    $advRow = db()->fetchOne("SELECT COALESCE(SUM(amount),0) AS total FROM salary_advances WHERE status='pending'");
    $recent = db()->fetchAll(
        "SELECT pr.net_salary,pr.status,pr.employee_id,e.full_name,e.employee_id AS emp_code,
                pp.period_year,pp.period_month
         FROM payroll_records pr
         JOIN employees e ON pr.employee_id=e.id
         JOIN payroll_periods pp ON pr.payroll_period_id=pp.id
         ORDER BY pr.created_at DESC LIMIT 5"
    );
   // NEW
   $attSummary = db()->fetchOne(
        "SELECT
            SUM(CASE WHEN a.attendance_type='full_day' THEN 1 ELSE 0 END) AS full_days,
            SUM(CASE WHEN a.overtime_hours>0 THEN 1 ELSE 0 END) AS overtime_days,
            SUM(CASE WHEN a.attendance_type='absent' THEN 1 ELSE 0 END) AS absences,
            SUM(CASE WHEN a.night_shift_hours>0 THEN 1 ELSE 0 END) AS night_shifts,
            SUM(CASE WHEN a.is_holiday=1 THEN 1 ELSE 0 END) AS public_holidays,
            SUM(a.overtime_hours) AS total_overtime_hours,
            COUNT(*) AS total_records
         FROM attendance a
         JOIN employees e ON a.employee_id = e.id
         WHERE e.deleted_at IS NULL AND YEAR(a.attendance_date)=? AND MONTH(a.attendance_date)=?", [$year,$month]
    );

    $prevMonth = $month - 1; $prevYear = $year;
    if ($prevMonth < 1) { $prevMonth = 12; $prevYear--; }

    $newHiresThisMonth = (int)(db()->fetchOne(
        "SELECT COUNT(*) AS c FROM employees WHERE deleted_at IS NULL AND YEAR(join_date)=? AND MONTH(join_date)=?",
        [$year,$month]
    )['c'] ?? 0);

    $inactiveEmp = max(0, $totalEmp - $activeEmp);

    $overtimePrevRow = db()->fetchOne(
        "SELECT COALESCE(SUM(overtime_hours),0) AS total FROM attendance WHERE YEAR(attendance_date)=? AND MONTH(attendance_date)=?",
        [$prevYear,$prevMonth]
    );
    $overtimeThis = (float)($attSummary['total_overtime_hours'] ?? 0);
    $overtimePrev = (float)($overtimePrevRow['total'] ?? 0);
    $overtimeDiff = $overtimeThis - $overtimePrev;

    $payrollPrevRow = db()->fetchOne(
        "SELECT COALESCE(SUM(pr.net_salary),0) AS total FROM payroll_records pr
         JOIN payroll_periods pp ON pr.payroll_period_id=pp.id
         WHERE pp.period_year=? AND pp.period_month=?", [$prevYear,$prevMonth]);
    $payrollThis = (float)($payrollRow['total'] ?? 0);
    $payrollPrev = (float)($payrollPrevRow['total'] ?? 0);
    $payrollChangePct = $payrollPrev > 0 ? round((($payrollThis - $payrollPrev) / $payrollPrev) * 100, 1) : null;

    $advPendingCount = (int)(db()->fetchOne("SELECT COUNT(*) AS c FROM salary_advances WHERE status='pending'")['c'] ?? 0);

    $dueRow = db()->fetchOne("SELECT COALESCE(SUM(amount),0) AS total, COUNT(DISTINCT employee_id) AS emp_count FROM due_salaries WHERE status='pending'");
    ok([
        'total_employees'      => $totalEmp,
        'active_employees'     => $activeEmp,
        'inactive_employees'   => $inactiveEmp,
        'new_hires_this_month' => $newHiresThisMonth,
        'payroll_this_month'   => $payrollThis,
        'payroll_change_pct'   => $payrollChangePct,
        'total_advances'       => (float)($advRow['total'] ?? 0),
        'advances_pending'     => $advPendingCount,
        'total_overtime_hours' => $overtimeThis,
        'overtime_change_hours'=> $overtimeDiff,
        'due_salaries_total'   => (float)($dueRow['total'] ?? 0),
        'due_salaries_count'   => (int)($dueRow['emp_count'] ?? 0),
        'recent_payroll'       => $recent,
        'attendance_summary'   => [
            'full_days'        => (int)($attSummary['full_days'] ?? 0),
            'overtime_days'    => (int)($attSummary['overtime_days'] ?? 0),
            'absences'         => (int)($attSummary['absences'] ?? 0),
            'night_shifts'     => (int)($attSummary['night_shifts'] ?? 0),
            'public_holidays'  => (int)($attSummary['public_holidays'] ?? 0),
            'total_records'    => (int)($attSummary['total_records'] ?? 0),
        ],
    ]);
}

// ============================================================
// SETTINGS
// ============================================================
if ($action === 'get_settings') {
    ok(db()->fetchOne("SELECT * FROM company_settings LIMIT 1"));
}

if ($action === 'save_settings') {
    $fields = [
        'company_name'        => p('company_name','SL Industry'),
        'default_tax_rate'    => (float)p('default_tax_rate', 3.3),
        'overtime_multiplier' => (float)p('overtime_multiplier', 1.5),
        'holiday_multiplier'  => (float)p('holiday_multiplier', 2.0),
        'saturday_multiplier' => (float)p('saturday_multiplier', 1.5),
        'sunday_multiplier'   => (float)p('sunday_multiplier', 2.0),
        'standard_work_hours' => (float)p('standard_work_hours', 8),
        'lunch_break_hours'   => (float)p('lunch_break_hours', 1.0),
        'payroll_cutoff_day'  => (int)p('payroll_cutoff_day', 28),
        'default_language'    => p('default_language','en'),
        'company_logo'        => p('company_logo',''),
        'updated_at'          => date('Y-m-d H:i:s'),
    ];
    $existing = db()->fetchOne("SELECT id FROM company_settings LIMIT 1");
    if ($existing) {
        db()->update('company_settings', $fields, 'id=?', [$existing['id']]);
    } else {
        db()->insert('company_settings', $fields);
    }
    logActivity('UPDATE_SETTINGS','company_settings',1,'Updated settings');
    ok(null, 'Settings saved.');
}

// ============================================================
// HOLIDAYS
// ============================================================








if ($action === 'get_holidays') {
    $year = (int)g('year', date('Y'));
    ok(db()->fetchAll(
        "SELECT * FROM korean_public_holidays WHERE YEAR(holiday_date)=? ORDER BY holiday_date",
        [$year]
    ));
}

if ($action === 'save_holiday') {
    require_fields(['holiday_date','holiday_name_en']);
    $fields = [
        'holiday_date'    => p('holiday_date'),
        'holiday_name_en' => p('holiday_name_en'),
        'holiday_name_kr' => p('holiday_name_kr') ?: null,
        'is_recurring'    => (int)p('is_recurring', 0),
        'month_day'       => p('month_day') ?: null,
    ];
    $existing = db()->fetchOne("SELECT id FROM korean_public_holidays WHERE holiday_date=?", [$fields['holiday_date']]);
    if ($existing) { db()->update('korean_public_holidays', $fields, 'id=?', [$existing['id']]); ok(null, 'Holiday updated.'); }
    else           { $newId = db()->insert('korean_public_holidays', $fields); ok(['id'=>$newId], 'Holiday added.'); }
}

if ($action === 'generate_holidays') {
    $year = (int)p('year', date('Y'));
    if ($year < 2000 || $year > 2100) {
        fail('Invalid year.');
    }

    $fixed = [
        ['01-01', "New Year's Day", '신정'],
        ['03-01', 'Independence Movement Day', '삼일절'],
        ['05-01', 'Labor Day', '근로자의 날'],
        ['05-05', "Children's Day", '어린이날'],
        ['06-06', 'Memorial Day', '현충일'],
        ['08-15', 'Liberation Day', '광복절'],
        ['10-03', 'National Foundation Day', '개천절'],
        ['10-09', 'Hangeul Day', '한글날'],
        ['12-25', 'Christmas Day', '성탄절'],
    ];

    $lunar = [
        2026 => [
            ['02-16', 'Seollal (Lunar New Year)', '설날 연휴'],
            ['02-17', 'Seollal (Lunar New Year)', '설날'],
            ['02-18', 'Seollal (Lunar New Year)', '설날 연휴'],
            ['03-02', 'Substitute Holiday (Independence Movement Day)', '대체공휴일'],
            ['05-24', "Buddha's Birthday", '부처님오신날'],
            ['05-25', "Substitute Holiday (Buddha's Birthday)", '대체공휴일'],
            ['08-17', 'Substitute Holiday (Liberation Day)', '대체공휴일'],
            ['09-24', 'Chuseok (Korean Thanksgiving)', '추석 연휴'],
            ['09-25', 'Chuseok (Korean Thanksgiving)', '추석'],
            ['09-26', 'Chuseok (Korean Thanksgiving)', '추석 연휴'],
        ],
        2027 => [
            ['02-06', 'Seollal (Lunar New Year)', '설날 연휴'],
            ['02-07', 'Seollal (Lunar New Year)', '설날'],
            ['02-08', 'Seollal (Lunar New Year)', '설날 연휴'],
            ['02-09', 'Substitute Holiday (Seollal)', '대체공휴일'],
            ['05-13', "Buddha's Birthday", '부처님오신날'],
            ['09-21', 'Chuseok (Korean Thanksgiving)', '추석 연휴'],
            ['09-22', 'Chuseok (Korean Thanksgiving)', '추석'],
            ['09-23', 'Chuseok (Korean Thanksgiving)', '추석 연휴'],
            ['10-04', 'Substitute Holiday (National Foundation Day)', '대체공휴일'],
            ['10-11', 'Substitute Holiday (Hangeul Day)', '대체공휴일'],
            ['12-27', 'Substitute Holiday (Christmas)', '대체공휴일'],
        ],
    ];

    $inserted = 0; $skipped = 0;

    foreach ($fixed as [$md, $nameEn, $nameKr]) {
        $date = "$year-$md";
        $exists = db()->fetchOne("SELECT id FROM korean_public_holidays WHERE holiday_date=?", [$date]);
        if ($exists) { $skipped++; continue; }
        db()->insert('korean_public_holidays', [
            'holiday_date'    => $date,
            'holiday_name_en' => $nameEn,
            'holiday_name_kr' => $nameKr,
            'is_recurring'    => 1,
            'month_day'       => $md,
        ]);
        $inserted++;
    }

    $hasLunarData = isset($lunar[$year]);
    if ($hasLunarData) {
        foreach ($lunar[$year] as [$md, $nameEn, $nameKr]) {
            $date = "$year-$md";
            $exists = db()->fetchOne("SELECT id FROM korean_public_holidays WHERE holiday_date=?", [$date]);
            if ($exists) { $skipped++; continue; }
            db()->insert('korean_public_holidays', [
                'holiday_date'    => $date,
                'holiday_name_en' => $nameEn,
                'holiday_name_kr' => $nameKr,
                'is_recurring'    => 0,
                'month_day'       => null,
            ]);
            $inserted++;
        }
        ok(['inserted'=>$inserted,'skipped'=>$skipped],
           "Generated $inserted holidays for $year (fixed-date + lunar/substitute). $skipped already existed.");
    } else {
        ok(['inserted'=>$inserted,'skipped'=>$skipped],
           "Generated $inserted fixed-date holidays for $year. Lunar holidays (Seollal/Chuseok/Buddha's Birthday) aren't verified for this year yet — add them manually once officially announced.");
    }
}

// ============================================================
// AUDIT LOG
// ============================================================
if ($action === 'get_audit_log') {
    ok(db()->fetchAll(
        "SELECT al.*, a.username FROM activity_logs al
         LEFT JOIN admin_users a ON al.admin_id=a.id
         ORDER BY al.created_at DESC LIMIT 200"
    ));
}

// ============================================================
// DUE SALARIES
// ============================================================
if ($action === 'get_due_salaries') {
    ok(db()->fetchAll(
        "SELECT ds.*, e.full_name, e.employee_id AS emp_code FROM due_salaries ds
         JOIN employees e ON ds.employee_id=e.id ORDER BY ds.created_at DESC"
    ));
}

if ($action === 'cancel_due_salary') {
    $id = (int)p('id',0);
    if (!$id) {
        fail(ERROR_MISSING_ID);
    }
    db()->execute("UPDATE due_salaries SET status='cancelled' WHERE id=? AND status='pending'", [$id]);
    logActivity('CANCEL_DUE_SALARY','due_salaries',$id,'Cancelled');
    ok(null, 'Due salary cancelled.');
}

if ($action === 'process_all_due_salaries') {
    $pending = db()->fetchAll("SELECT id FROM due_salaries WHERE status='pending'");
    if (empty($pending)) {
        fail('No pending due salaries to process.');
    }

    $year  = (int)date('Y');
    $month = (int)date('n');
    $period = db()->fetchOne(
        "SELECT id FROM payroll_periods WHERE period_year=? AND period_month=?",
        [$year, $month]
    );
    $periodId = $period['id'] ?? null;

    db()->execute(
        "UPDATE due_salaries SET status='added', added_date=CURDATE(), added_to_payroll_id=?
         WHERE status='pending'",
        [$periodId]
    );
    logActivity('PROCESS_ALL_DUE_SALARIES','due_salaries',0,
        'Processed '.count($pending).' pending due salary record(s)');
    ok(['processed' => count($pending)], count($pending).' due salary record(s) processed.');
}

// ============================================================
// PAYSHEET (individual view)
// ============================================================
if ($action === 'get_paysheet') {
    $empId = (int)g('employee_id',0); $year=(int)g('year',date('Y')); $month=(int)g('month',date('n'));
    if (!$empId) {
        fail('Missing employee_id.');
    }

    // Always recalculate live from attendance so values are always accurate
    $engine = new PayrollEngine();
    try {
        $calc = $engine->calculateEmployeePayroll($empId, $year, $month);
    } catch (\Exception $e) {
        fail($e->getMessage());
    }

    $attendance = db()->fetchAll(
        "SELECT a.*, k.holiday_name_en as holiday_name FROM attendance a
         LEFT JOIN korean_public_holidays k ON a.attendance_date=k.holiday_date
         WHERE a.employee_id=? AND YEAR(a.attendance_date)=? AND MONTH(a.attendance_date)=?
         ORDER BY a.attendance_date",
        [$empId, $year, $month]
    );

    $emp = $calc['employee'];
    $record = [
        'full_name'              => $emp['full_name'],
        'emp_code'               => $emp['employee_id'],
        'employee_type'          => $emp['employee_type'],
        'hourly_rate'            => $calc['hourly_rate'],
        'tax_rate'               => $calc['tax_rate'],
        'bank_name'              => $emp['bank_name'] ?? null,
        'account_number'         => $emp['account_number'] ?? null,
        'account_holder_name'    => $emp['account_holder_name'] ?? null,
        'phone'                  => $emp['phone'] ?? null,
        'period_year'            => $year,
        'period_month'           => $month,
        'status'                 => 'calculated',
        'basic_salary'           => $calc['basic_salary'],
        'overtime_pay'           => $calc['overtime_pay'],
        'night_allowance'        => $calc['night_allowance'],
        'holiday_pay'            => $calc['holiday_pay'],
        'sunday_bonus'           => $calc['sunday_bonus'],
        'sunday_bonus_weeks'     => $calc['sunday_bonus_weeks'],
        'sunday_bonus_hours'     => $calc['sunday_bonus_hours'],
        'due_salary_added'       => $calc['due_salary_added'],
        'gross_salary'           => $calc['gross_salary'],
        'tax_amount'             => $calc['tax_amount'],
        'advance_deduction'      => $calc['advance_deduction'],
        'unpaid_leave_deduction' => $calc['unpaid_leave_deduction'],
        'total_deductions'       => $calc['total_deductions'],
        'net_salary'             => $calc['net_salary'],
        'due_salary_carried'     => $calc['due_salary_carried'],
        'total_work_days'        => $calc['total_work_days'],
        'total_work_hours'       => $calc['total_work_hours'],
        'overtime_hours'         => $calc['overtime_hours'],
        'night_shift_hours'      => $calc['night_shift_hours'],
        'holiday_hours'          => $calc['holiday_hours'],
        'absent_days'            => $calc['absent_days'],
        'unpaid_leave_days'      => $calc['unpaid_leave_days'],
    ];
    ok(['record' => $record, 'attendance' => $attendance]);
}

if ($action === 'calculate_paysheet') {
    $empId=(int)g('employee_id',0); $year=(int)g('year',date('Y')); $month=(int)g('month',date('n'));
    if (!$empId) {
        fail('Missing employee_id.');
    }
    $engine = new PayrollEngine();
    try { $calc = $engine->calculateEmployeePayroll($empId,$year,$month); }
    catch (\Exception $e) { fail($e->getMessage()); }
    $attendance = db()->fetchAll(
        "SELECT a.*, k.holiday_name_en as holiday_name FROM attendance a
         LEFT JOIN korean_public_holidays k ON a.attendance_date=k.holiday_date
         WHERE a.employee_id=? AND YEAR(a.attendance_date)=? AND MONTH(a.attendance_date)=?
         ORDER BY a.attendance_date",
        [$empId,$year,$month]
    );
    $emp = $calc['employee'];
    $record = [
        'full_name'              => $emp['full_name'],
        'emp_code'               => $emp['employee_id'],
        'employee_type'          => $emp['employee_type'],
        'hourly_rate'            => $calc['hourly_rate'],
        'tax_rate'               => $calc['tax_rate'],
        'bank_name'              => $emp['bank_name'] ?? null,
        'account_number'         => $emp['account_number'] ?? null,
        'account_holder_name'    => $emp['account_holder_name'] ?? null,
        'phone'                  => $emp['phone'] ?? null,
        'period_year'            => $year,
        'period_month'           => $month,
        'period_start'           => $calc['period_start'],
        'period_end'             => $calc['period_end'],
        'status'                 => 'preview',
        'basic_salary'           => $calc['basic_salary'],
        'overtime_pay'           => $calc['overtime_pay'],
        'night_allowance'        => $calc['night_allowance'],
        'holiday_pay'            => $calc['holiday_pay'],
        'sunday_bonus'           => $calc['sunday_bonus'],
        'sunday_bonus_weeks'     => $calc['sunday_bonus_weeks'],
        'due_salary_added'       => $calc['due_salary_added'],
        'gross_salary'           => $calc['gross_salary'],
        'tax_amount'             => $calc['tax_amount'],
        'advance_deduction'      => $calc['advance_deduction'],
        'unpaid_leave_deduction' => $calc['unpaid_leave_deduction'],
        'total_deductions'       => $calc['total_deductions'],
        'net_salary'             => $calc['net_salary'],
        'due_salary_carried'     => $calc['due_salary_carried'],
        'total_work_days'        => $calc['total_work_days'],
        'total_work_hours'       => $calc['total_work_hours'],
        'overtime_hours'         => $calc['overtime_hours'],
        'night_shift_hours'      => $calc['night_shift_hours'],
        'holiday_hours'          => $calc['holiday_hours'],
        'absent_days'            => $calc['absent_days'],
        'unpaid_leave_days'      => $calc['unpaid_leave_days'],
    ];
    ok(['record'=>$record,'attendance'=>$attendance,'is_preview'=>true]);
}

// ============================================================
// EXPORT — PDF PAYSHEET
// ============================================================
if ($action === 'export_paysheet_pdf') {
    // HTML escape helper for PDF output
    

    $empId=(int)g('employee_id',0); $year=(int)g('year',date('Y')); $month=(int)g('month',date('n'));
    if (!$empId) {
        fail('Missing employee_id.');
    }

    // Always recalculate live — ensures hours and sunday_bonus_weeks are always fresh
    $engine = new PayrollEngine();
    try { $calc = $engine->calculateEmployeePayroll($empId, $year, $month); }
    catch (\Exception $e) { fail('No payroll data: '.$e->getMessage()); }

    $emp = $calc['employee'];
    $record = [
        'full_name'              => $emp['full_name'],
        'emp_code'               => $emp['employee_id'],
        'employee_type'          => $emp['employee_type'],
        'phone'                  => $emp['phone'] ?? '',
        'bank_name'              => $emp['bank_name'] ?? '',
        'account_number'         => $emp['account_number'] ?? '',
        'account_holder_name'    => $emp['account_holder_name'] ?? '',
        'hourly_rate'            => $calc['hourly_rate'],
        'tax_rate'               => $calc['tax_rate'],
        'period_year'            => $year,
        'period_month'           => $month,
        'status'                 => 'calculated',
        // Earnings
        'basic_salary'           => $calc['basic_salary'],
        'overtime_pay'           => $calc['overtime_pay'],
        'night_allowance'        => $calc['night_allowance'],
        'holiday_pay'            => $calc['holiday_pay'],
        'sunday_bonus'           => $calc['sunday_bonus'],
        'sunday_bonus_weeks'     => $calc['sunday_bonus_weeks'],
        'due_salary_added'       => $calc['due_salary_added'],
        'gross_salary'           => $calc['gross_salary'],
        // Deductions
        'tax_amount'             => $calc['tax_amount'],
        'advance_deduction'      => $calc['advance_deduction'],
        'unpaid_leave_deduction' => $calc['unpaid_leave_deduction'],
        'total_deductions'       => $calc['total_deductions'],
        'net_salary'             => $calc['net_salary'],
        // Hours summary
        'total_work_hours'       => $calc['total_work_hours'],
        'overtime_hours'         => $calc['overtime_hours'],
        'night_shift_hours'      => $calc['night_shift_hours'],
        'holiday_hours'          => $calc['holiday_hours'],
        'total_work_days'        => $calc['total_work_days'],
        'absent_days'            => $calc['absent_days'],
        'unpaid_leave_days'      => $calc['unpaid_leave_days'],
    ];

    $attendance = db()->fetchAll(
        "SELECT * FROM attendance WHERE employee_id=? AND YEAR(attendance_date)=? AND MONTH(attendance_date)=? ORDER BY attendance_date",
        [$empId,$year,$month]
    );
    $attByDay = [];
    foreach ($attendance as $a) { $attByDay[(int)date('j',strtotime($a['attendance_date']))] = $a; }
    $daysInMonth = cal_days_in_month(CAL_GREGORIAN,$month,$year);
    $monthName   = date('F Y',mktime(0,0,0,$month,1,$year));

    // Load Korean public holidays for this month
    $holidays = db()->fetchAll(
        "SELECT holiday_date, holiday_name_en FROM korean_public_holidays WHERE YEAR(holiday_date)=? AND MONTH(holiday_date)=?",
        [$year,$month]
    );
    $holidayMap = [];
    foreach ($holidays as $h) { $holidayMap[(int)date('j',strtotime($h['holiday_date']))] = $h['holiday_name_en']; }

    header('Content-Type: text/html; charset=utf-8');
    $typeLabel   = $record['employee_type']==='korean' ? 'Korean Employee' : 'Foreign Employee';
    $periodLabel = $record['period_year'].'년 '.str_pad($record['period_month'],2,'0',STR_PAD_LEFT).'월';
    $dayNames    = ['','Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    $calRows     = '';
    $labels      = [
        ['key'=>'work_hours',        'label'=>'Basic', 'color'=>'#059669'],
        ['key'=>'overtime_hours',    'label'=>'OT',    'color'=>'#C2410C'],
        ['key'=>'night_shift_hours', 'label'=>'Night', 'color'=>'#1D4ED8'],
        ['key'=>'holiday_hours',     'label'=>'Hol',   'color'=>'#B91C1C'],
    ];
    foreach ($labels as $row) {
        $calRows .= '<tr><td class="rl">'.$row['label'].'</td>';
        $tot = 0;
        for ($d=1;$d<=$daysInMonth;$d++) {
            $dow = date('N',mktime(0,0,0,$month,$d,$year));
            $att = $attByDay[$d]??null;
            $val = $att?(float)$att[$row['key']]:0;
           if ($val>0) {
               $tot += $val;
               $calRows .= '<td class="hv" style="color:'.$row['color'].'">'.$val.'</td>';
           } elseif ($row['key'] === 'work_hours' && isset($holidayMap[$d]) && $val == 0) {
               $calRows .= '<td class="hd" title="'.htmlspecialchars($holidayMap[$d]).'">HD</td>';
           } elseif ($dow == 7) {
               $calRows .= '<td class="sc"></td>';
           } elseif ($dow == 6) {
               $calRows .= '<td class="sc"></td>';
           } elseif ($att && $att['attendance_type'] === 'absent') {
               $calRows .= '<td class="ac">A</td>';
           } elseif ($att && strpos($att['attendance_type'], 'leave') !== false) {
               $calRows .= '<td class="lc">L</td>';
           } else {
               $calRows .= '<td></td>';
           }
        }
        $calRows .= '<td class="tc">'.$tot.'</td></tr>';
    }
    $dayHeaders=$dayNameRow='';
    for ($d=1;$d<=$daysInMonth;$d++) {
        $dow=date('N',mktime(0,0,0,$month,$d,$year));
        $cls=($dow==7||$dow==6)?' class="sc"':'';
        $dayHeaders.="<th$cls>$d</th>"; $dayNameRow.="<td$cls>".$dayNames[$dow]."</td>";
    }
    $previewBanner='';
    $bonusWeeks = (int)($record['sunday_bonus_weeks'] ?? 0);
    $bonusHours = (float)($record['sunday_bonus_hours'] ?? ($bonusWeeks*8));
    $bonusNote  = $bonusWeeks > 0 ? " ({$bonusWeeks} week" . ($bonusWeeks>1?'s':'') . ", {$bonusHours}h)" : '';
    $hoursSummary =
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;font-size:11px">'.
        '<span style="background:#e8f5e9;color:#059669;padding:2px 8px;border-radius:20px;font-weight:600">Work Days: '.($record['total_work_days']??0).'</span>'.
        '<span style="background:#e8f5e9;color:#059669;padding:2px 8px;border-radius:20px;font-weight:600">Basic Hrs: '.number_format($record['total_work_hours']??0,1).'</span>'.
        '<span style="background:#fff3e0;color:#C2410C;padding:2px 8px;border-radius:20px;font-weight:600">OT Hrs: '.number_format($record['overtime_hours']??0,1).'</span>'.
        '<span style="background:#e3f2fd;color:#1D4ED8;padding:2px 8px;border-radius:20px;font-weight:600">Night Hrs: '.number_format($record['night_shift_hours']??0,1).'</span>'.
        (($record['absent_days']??0)>0?'<span style="background:#fde8e8;color:#dc2626;padding:2px 8px;border-radius:20px;font-weight:600">Absent: '.$record['absent_days'].'</span>':'').
        (($record['unpaid_leave_days']??0)>0?'<span style="background:#f3f4f6;color:#6B7280;padding:2px 8px;border-radius:20px;font-weight:600">Unpaid Leave: '.$record['unpaid_leave_days'].'</span>':'').
        '</div>';

    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Paysheet – '.htmlspecialchars($record['full_name']).' – '.$monthName.'</title>
<style>
body{font-family:"Noto Sans KR",sans-serif;font-size:12px;color:#000;margin:0;padding:20px;background:#fff}
.ps{max-width:900px;margin:0 auto;border:1px solid #ccc}
.ph{background:#0A2342;color:#fff;padding:16px 24px;display:flex;justify-content:space-between;align-items:center}
.ph h2{margin:0;font-size:18px}.ph .badge{background:#E63946;padding:4px 12px;border-radius:4px;font-size:13px}
.pb{padding:16px 24px}
.info-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;background:#f5f5f5;padding:12px;border-radius:6px;margin-bottom:14px}
.info-item label{display:block;font-size:10px;color:#666;text-transform:uppercase}
.info-item span{font-size:13px;font-weight:600;color:#111}
table{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:11px}
th{background:#0A2342;color:#fff;padding:5px 4px;text-align:center}
td{border:1px solid #ddd;padding:4px 3px;text-align:center}
.rl{text-align:left;padding-left:8px;background:#f0f4f8;font-weight:600;white-space:nowrap;min-width:55px}
.sc{color:#dc2626;background:#fef2f2}.hv{font-weight:600}.tc{background:#0A2342;color:#fff;font-weight:700}
.ac{background:#fee2e2;color:#dc2626}.lc{background:#ede9fe;color:#7c3aed}.hd{background:#FEF3C7;color:#b45309;font-weight:700}
.earn-table th,.ded-table th{text-align:left;padding-left:8px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.net-bar{background:#0A2342;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
.net-bar .label{font-size:14px;font-weight:600}.net-bar .amount{font-size:22px;font-weight:800;font-family:monospace}
.sig-row{display:flex;gap:40px;margin-top:20px;padding-top:14px;border-top:2px solid #eee}
.sig-box{text-align:center}.sig-line{width:130px;border-bottom:1px solid #333;margin:0 auto 6px;padding-bottom:22px}
.sig-label{font-size:10px;color:#555}.footer-note{text-align:center;font-size:10px;color:#999;margin-top:10px}
.section-title{font-size:12px;font-weight:700;color:#0A2342;margin-bottom:6px}
@media print{body{padding:0}.ps{border:none}.no-print{display:none}}
</style></head><body>
<div class="no-print" style="margin-bottom:12px">
  <button onclick="window.print()" style="background:#E63946;color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px">🖨 Print / Save PDF</button>
  <button onclick="window.close()" style="margin-left:8px;background:#444;color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px">✕ Close</button>
</div>
<div class="ps">
  <div class="ph">
    <div><h2>SL Industry</h2><div style="font-size:11px;opacity:.8">급여 명세서 / Salary Statement</div></div>
    <div class="badge">'.$periodLabel.'</div>
  </div>
  <div class="pb">
    <div class="info-grid">
      <div class="info-item"><label>Name / 성명</label><span>'.e($record['full_name']).'</span></div>
      <div class="info-item"><label>Employee ID</label><span>'.e($record['emp_code']).'</span></div>
      <div class="info-item"><label>Type / 구분</label><span>'.$typeLabel.'</span></div>
      <div class="info-item"><label>Hourly Rate</label><span>₩'.number_format($record['hourly_rate']).'</span></div>
      <div class="info-item"><label>Tax Rate</label><span>'.$record['tax_rate'].'%</span></div>
      <div class="info-item"><label>Bank</label><span>'.e($record['bank_name']??'-').'</span></div>
      <div class="info-item"><label>Account No</label><span>'.e($record['account_number']??'-').'</span></div>
      <div class="info-item"><label>Payment Method</label><span>Bank Transfer</span></div>
      <div class="info-item"><label>Status</label><span>'.ucfirst($record['status']).'</span></div>
    </div>
    <div class="section-title">근태 현황 / Attendance — '.$monthName.'</div>
    '.$hoursSummary.'
    <div style="overflow-x:auto;margin-bottom:14px">
    <table><thead><tr><th class="rl">Item</th>'.$dayHeaders.'<th class="tc">Total</th></tr>
    <tr><td class="rl" style="font-size:10px;color:#666">Day</td>'.$dayNameRow.'<td></td></tr>
    </thead><tbody>'.$calRows.'</tbody></table>
    </div>
    <div class="two-col">
      <div>
        <div class="section-title">지급 내역 / Earnings</div>
        <table class="earn-table"><thead><tr><th>Item</th><th style="text-align:center">Hrs</th><th>Amount (₩)</th></tr></thead><tbody>
        <tr><td>기본급 Basic Salary</td><td style="text-align:center">'.number_format($record['total_work_hours']??0,1).'</td><td style="text-align:right;color:#059669">'.number_format($record['basic_salary']).'</td></tr>
        <tr><td>초과근무 Overtime Pay</td><td style="text-align:center">'.number_format($record['overtime_hours']??0,1).'</td><td style="text-align:right;color:#059669">'.number_format($record['overtime_pay']).'</td></tr>
        <tr><td>야간수당 Night Allowance</td><td style="text-align:center">'.number_format($record['night_shift_hours']??0,1).'</td><td style="text-align:right;color:#059669">'.number_format($record['night_allowance']).'</td></tr>
        <tr><td>공휴일수당 Holiday Pay</td><td style="text-align:center">'.number_format($record['holiday_hours']??0,1).'</td><td style="text-align:right;color:#059669">'.number_format($record['holiday_pay']).'</td></tr>
        <tr style="background:#fff8e1"><td>일요일보너스 Sunday Bonus'.$bonusNote.'</td><td style="text-align:center">'.$bonusHours.'</td><td style="text-align:right;color:#e65100;font-weight:700">'.number_format($record['sunday_bonus']).'</td></tr>
        <tr><td>미지급이월 Due Salary</td><td style="text-align:center">—</td><td style="text-align:right;color:#059669">'.number_format($record['due_salary_added']).'</td></tr>
        <tr style="background:#e8f4f8"><td colspan="2"><b>총지급 Gross</b></td><td style="text-align:right"><b>'.number_format($record['gross_salary']).'</b></td></tr>
        </tbody></table>
      </div>
      <div>
        <div class="section-title">공제 내역 / Deductions</div>
        <table class="ded-table"><thead><tr><th>Item</th><th>Amount (₩)</th></tr></thead><tbody>
        <tr><td>소득세 Income Tax ('.$record['tax_rate'].'%)</td><td style="text-align:right;color:#dc2626">-'.number_format($record['tax_amount']).'</td></tr>
        <tr><td>선급금 Advance Deduction</td><td style="text-align:right;color:#dc2626">-'.number_format($record['advance_deduction']).'</td></tr>
        <tr><td>무급공제 Unpaid Leave</td><td style="text-align:right;color:#dc2626">-'.number_format($record['unpaid_leave_deduction']).'</td></tr>
        <tr style="background:#fee2e2"><td><b>총공제 Total Deductions</b></td><td style="text-align:right"><b>-'.number_format($record['total_deductions']).'</b></td></tr>
        </tbody></table>
      </div>
    </div>
  </div>
  <div class="net-bar">
    <div class="label">실수령액 / Net Salary</div>
    <div class="amount">₩'.number_format($record['net_salary']).'</div>
  </div>
  <div class="pb">
    <div class="sig-row">
      <div class="sig-box"><div class="sig-line"></div><div class="sig-label">Employee / 직원</div></div>
      <div class="sig-box"><div class="sig-line"></div><div class="sig-label">HR Manager / 인사담당자</div></div>
      <div class="sig-box"><div class="sig-line"></div><div class="sig-label">Director / 대표</div></div>
    </div>
    <div class="footer-note">SL Industry Co., Ltd. | Generated: '.date('Y-m-d H:i').' | Computer-generated document.</div>
  </div>
</div>
<script>window.onload=function(){window.print();}</script>
</body></html>';
    exit;
}

// ============================================================
// EXPORT — Individual Paysheet CSV
// ============================================================
if ($action === 'export_paysheet_csv') {
    $empId=(int)g('employee_id',0); $year=(int)g('year',date('Y')); $month=(int)g('month',date('n'));
    if (!$empId) { fail('Missing employee_id.'); }

    $engine = new PayrollEngine();
    try { $calc = $engine->calculateEmployeePayroll($empId, $year, $month); }
    catch (\Exception $ex) { fail('No payroll data: '.$ex->getMessage()); }

    $emp = $calc['employee'];
    $monthLabel = $year.'-'.str_pad($month,2,'0',STR_PAD_LEFT);

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="paysheet_'.preg_replace('/\s+/','_',$emp['full_name']).'_'.$monthLabel.'.csv"');
    $out = fopen(PHP_OUTPUT_STREAM,'w');
    fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF));

    // Employee info block
    fputcsv($out,['SL Industry — Salary Statement / 급여 명세서']);
    fputcsv($out,['Period', $monthLabel]);
    fputcsv($out,['Name',   $emp['full_name']]);
    fputcsv($out,['ID',     $emp['employee_id']]);
    fputcsv($out,['Type',   $emp['employee_type']]);
    fputcsv($out,['Hourly Rate', '₩'.number_format($calc['hourly_rate'])]);
    fputcsv($out,['Tax Rate', $calc['tax_rate'].'%']);
    fputcsv($out,['Bank', $emp['bank_name']??'']);
    fputcsv($out,['Account No', $emp['account_number']??'']);
    fputcsv($out,[]);

    // Earnings
    fputcsv($out,['--- EARNINGS ---','Hours','Amount (KRW)']);
    fputcsv($out,['Basic Salary',           number_format($calc['total_work_hours'],1),  $calc['basic_salary']]);
    fputcsv($out,['Overtime Pay',           number_format($calc['overtime_hours'],1),    $calc['overtime_pay']]);
    fputcsv($out,['Night Allowance',        number_format($calc['night_shift_hours'],1), $calc['night_allowance']]);
    fputcsv($out,['Holiday Pay',            number_format($calc['holiday_hours'],1),     $calc['holiday_pay']]);
    fputcsv($out,['Sunday Bonus ('.$calc['sunday_bonus_weeks'].' weeks × 8h)', $calc['sunday_bonus_weeks']*8, $calc['sunday_bonus']]);
    fputcsv($out,['Due Salary Added',       '—', $calc['due_salary_added']]);
    fputcsv($out,['GROSS SALARY',           '',  $calc['gross_salary']]);
    fputcsv($out,[]);

    // Deductions
    fputcsv($out,['--- DEDUCTIONS ---','','Amount (KRW)']);
    fputcsv($out,['Income Tax ('.$calc['tax_rate'].'%)', '', $calc['tax_amount']]);
    fputcsv($out,['Advance Deduction',      '', $calc['advance_deduction']]);
    fputcsv($out,['Unpaid Leave Deduction', '', $calc['unpaid_leave_deduction']]);
    fputcsv($out,['TOTAL DEDUCTIONS',       '', $calc['total_deductions']]);
    fputcsv($out,[]);

    fputcsv($out,['NET SALARY', '', $calc['net_salary']]);
    fclose($out); exit;
}

// ============================================================
// EXPORT — CSV
// ============================================================
if ($action === 'export_employees') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="employees_'.date('Y-m-d').'.csv"');
    $employees = db()->fetchAll("SELECT * FROM employees ORDER BY full_name");
    $out = fopen(PHP_OUTPUT_STREAM,'w');
    fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF));
    fputcsv($out,['ID','Employee ID','Full Name','Type','Phone','Email','Country','Join Date','Bank','Account No','Hourly Rate','Tax Rate','Status']);
    foreach ($employees as $e) {
        fputcsv($out,[$e['id'],$e['employee_id'],$e['full_name'],$e['employee_type'],
            $e['phone'],$e['email'],$e['country']??$e['nationality'],$e['join_date'],
            $e['bank_name'],decryptField($e['account_number_enc']??null),$e['hourly_rate'],$e['tax_rate'],$e['employment_status']]);
    }
    fclose($out); exit;
}

if ($action === 'export_attendance') {
    $year=(int)g('year',date('Y')); $month=(int)g('month',date('n'));
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="attendance_'.$year.'-'.str_pad($month,2,'0',STR_PAD_LEFT).'.csv"');
    $out = fopen(PHP_OUTPUT_STREAM,'w');
    fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF));
    $rows = db()->fetchAll(
        "SELECT a.attendance_date,e.full_name,e.employee_id AS emp_code,a.attendance_type,
                a.check_in_time,a.check_out_time,a.total_duration_hours,a.lunch_deduction_hours,
                a.work_hours,a.overtime_hours,a.night_shift_hours,a.holiday_hours,
                a.is_manual_override,a.remarks
         FROM attendance a JOIN employees e ON a.employee_id=e.id
         WHERE YEAR(a.attendance_date)=? AND MONTH(a.attendance_date)=?
         ORDER BY e.full_name,a.attendance_date",[$year,$month]
    );
    $out=fopen('php://output','w'); fprintf($out,chr(0xEF).chr(0xBB).chr(0xBF));
    fputcsv($out,['Date','Employee','ID','Type','Check-In','Check-Out','Duration','Lunch','Basic Hrs','OT Hrs','Night Hrs','Holiday Hrs','Manual Override','Remarks']);
    foreach ($rows as $r) {
        fputcsv($out,[$r['attendance_date'],$r['full_name'],$r['emp_code'],
            $r['attendance_type'],$r['check_in_time'],$r['check_out_time'],
            $r['total_duration_hours'],$r['lunch_deduction_hours'],
            $r['work_hours'],$r['overtime_hours'],$r['night_shift_hours'],$r['holiday_hours'],
            $r['is_manual_override']?'Yes':'No',$r['remarks']]);
    }
    fclose($out); exit;
}

if ($action === 'export_payroll') {
    $year=(int)g('year',date('Y')); $month=(int)g('month',date('n'));
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="payroll_'.$year.'-'.str_pad($month,2,'0',STR_PAD_LEFT).'.csv"');
    $rows = db()->fetchAll(
        "SELECT e.full_name,e.employee_id AS emp_code,e.employee_type,e.bank_name,
                pr.total_work_hours,pr.overtime_hours,pr.night_shift_hours,pr.holiday_hours,
                pr.sunday_bonus_weeks,
                pr.basic_salary,pr.overtime_pay,pr.night_allowance,pr.holiday_pay,
                pr.sunday_bonus,pr.due_salary_added,pr.gross_salary,
                pr.tax_rate,pr.tax_amount,pr.advance_deduction,pr.unpaid_leave_deduction,
                pr.total_deductions,pr.net_salary,pr.status
         FROM payroll_records pr JOIN employees e ON pr.employee_id=e.id
         JOIN payroll_periods pp ON pr.payroll_period_id=pp.id
         WHERE pp.period_year=? AND pp.period_month=? ORDER BY e.full_name",[$year,$month]
    );
    $out=fopen('php://output','w'); fprintf($out,chr(0xEF).chr(0xBB).chr(0xBF));
    fputcsv($out,['Name','ID','Type','Bank','Work Hrs','OT Hrs','Night Hrs','Holiday Hrs',
        'Bonus Weeks','Basic','OT Pay','Night Allow','Holiday Pay','Sun Bonus','Due Added','Gross',
        'Tax%','Tax Amt','Advance','Unpaid Ded','Total Ded','Net Salary','Status']);
    foreach ($rows as $r) {
        fputcsv($out,[$r['full_name'],$r['emp_code'],$r['employee_type'],$r['bank_name'],
            $r['total_work_hours'],$r['overtime_hours'],$r['night_shift_hours'],$r['holiday_hours'],
            $r['sunday_bonus_weeks'],
            $r['basic_salary'],$r['overtime_pay'],$r['night_allowance'],$r['holiday_pay'],
            $r['sunday_bonus'],$r['due_salary_added'],$r['gross_salary'],
            $r['tax_rate'],$r['tax_amount'],$r['advance_deduction'],$r['unpaid_leave_deduction'],
            $r['total_deductions'],$r['net_salary'],$r['status']]);
    }
    fclose($out); exit;
}

// ── Unknown action ─────────────────────────────────────────
fail("Unknown action: '$action'", 400);

} catch (\Throwable $e) {
    error_log('[SL-API] '.$e->getMessage().' in '.$e->getFile().':'.$e->getLine());
    fail('Server error: '.$e->getMessage(), 500);
}
