<?php


require_once __DIR__ . '/helpers.php';

class PayrollEngine {

    private array $settings;

    public function __construct() {
        $this->settings = getSettings();
    }

    // --------------------------------------------------------
    // MAIN CALCULATION
    // --------------------------------------------------------
    public function calculateEmployeePayroll(
        int     $employeeId,
        int     $year,
        int     $month,
        ?string $startDate = null,
        ?string $endDate   = null
    ): array {
        $employee = db()->fetchOne(
            "SELECT * FROM employees WHERE id = ? AND deleted_at IS NULL",
            [$employeeId]
        );
        if (!$employee) {
            throw new \Exception("Employee not found");
        }

        // Decrypt sensitive fields for display (never stored in memory longer than needed)
        $employee['account_number']          = decryptField($employee['account_number_enc'] ?? null);
        $employee['id_card_passport_number'] = decryptField($employee['id_card_passport_number_enc'] ?? null);

        // Period dates
        $periodStart = $startDate ?? sprintf('%04d-%02d-01', $year, $month);
        $periodEnd   = $endDate   ?? date('Y-m-t', strtotime($periodStart));

        // Pro-rate for late joiners
        if ($employee['join_date'] > $periodStart) {
            $periodStart = $employee['join_date'];
        }

        $attendance = $this->fetchAttendanceOrFail($employeeId, $periodStart, $periodEnd, $employee['full_name']);

        $hourlyRate   = (float)$employee['hourly_rate'];
        $taxRate      = (float)$employee['tax_rate'];
        $overtimeMult = (float)($this->settings['overtime_multiplier'] ?? 1.5);
        $holidayMult  = (float)($this->settings['holiday_multiplier']  ?? 2.0);
        $stdHours     = (float)($this->settings['standard_work_hours'] ?? 8.0);

        $summary = $this->buildAttendanceSummary($attendance);

        $sundayBonusResult = $this->calculateSundayBonus($employeeId, $periodStart, $periodEnd, $summary['week_data']);
        $qualifyingWeeks       = $sundayBonusResult['qualifying_weeks'];
        $sundayBonusHoursTotal = $sundayBonusResult['bonus_hours'];
        $sundayBonus           = $sundayBonusHoursTotal * $hourlyRate;

        // ── Earnings ─────────────────────────────────────────
        $basicSalary    = $summary['total_work_hours']   * $hourlyRate;
        $overtimePay    = $summary['total_overtime_hours'] * $hourlyRate * $overtimeMult;
        $nightAllowance = $summary['total_night_hours']    * $hourlyRate;
        $holidayPay     = $summary['total_holiday_hours']  * $hourlyRate * $holidayMult;
       $dueSalaryAdded = $this->getPendingDueSalary($employeeId, $periodEnd);

        $taxableGross = $basicSalary + $overtimePay + $nightAllowance + $holidayPay + $sundayBonus;
        $grossSalary  = $taxableGross + $dueSalaryAdded;

        // ── Deductions ───────────────────────────────────────
        $taxAmount            = $taxableGross * ($taxRate / 100);
       $advanceDeduction     = $this->getPendingAdvances($employeeId, $periodEnd);
        $unpaidLeaveDeduction = $summary['unpaid_leave_days'] * $stdHours * $hourlyRate;
        $totalDeductions      = $taxAmount + $advanceDeduction + $unpaidLeaveDeduction;

        // ── Net ───────────────────────────────────────────────
        $netSalary       = $grossSalary - $totalDeductions;
        $dueSalaryCarried = 0.0;
        if ($netSalary < 0) {
            $dueSalaryCarried = abs($netSalary);
            $netSalary        = 0.0;
        }

        return [
            'employee'               => $employee,
            'period_start'           => $periodStart,
            'period_end'             => $periodEnd,
            'period_year'            => $year,
            'period_month'           => $month,
            'hourly_rate'            => $hourlyRate,
            'tax_rate'               => $taxRate,

            // Attendance Summary
            'total_work_days'        => $summary['total_work_days'],
            'total_work_hours'       => round($summary['total_work_hours'], 2),
            'overtime_hours'         => round($summary['total_overtime_hours'], 2),
            'night_shift_hours'      => round($summary['total_night_hours'], 2),
            'holiday_hours'          => round($summary['total_holiday_hours'], 2),
            'absent_days'            => $summary['absent_days'],
            'unpaid_leave_days'      => $summary['unpaid_leave_days'],
            'sunday_bonus_weeks'     => $qualifyingWeeks,
            'sunday_bonus_hours'     => round($sundayBonusHoursTotal, 2),

            // Earnings
            'basic_salary'           => round($basicSalary, 2),
            'overtime_pay'           => round($overtimePay, 2),
            'night_allowance'        => round($nightAllowance, 2),
            'holiday_pay'            => round($holidayPay, 2),
            'sunday_bonus'           => round($sundayBonus, 2),
            'due_salary_added'       => round($dueSalaryAdded, 2),
            'gross_salary'           => round($grossSalary, 2),

            // Deductions
            'tax_amount'             => round($taxAmount, 2),
            'advance_deduction'      => round($advanceDeduction, 2),
            'unpaid_leave_deduction' => round($unpaidLeaveDeduction, 2),
            'total_deductions'       => round($totalDeductions, 2),

            // Net
            'net_salary'             => round($netSalary, 2),
            'due_salary_carried'     => round($dueSalaryCarried, 2),

            // Detail
            'attendance_records'     => $attendance,
        ];
    }

    // --------------------------------------------------------
    // Fetch attendance rows for a period, or throw if none found
    // --------------------------------------------------------
    private function fetchAttendanceOrFail(int $employeeId, string $periodStart, string $periodEnd, string $employeeName): array {
        $attendance = db()->fetchAll(
            "SELECT a.*, k.id as is_pub_holiday
             FROM attendance a
             LEFT JOIN korean_public_holidays k ON a.attendance_date = k.holiday_date
             WHERE a.employee_id = ? AND a.attendance_date BETWEEN ? AND ?
             ORDER BY a.attendance_date",
            [$employeeId, $periodStart, $periodEnd]
        );

        if (empty($attendance)) {
            throw new \Exception(
                "No attendance records found for {$employeeName} in $periodStart – $periodEnd"
            );
        }

        return $attendance;
    }

    // --------------------------------------------------------
    // Walk attendance rows, aggregate hours/days, and build
    // per-ISO-week attendance data used for Sunday Bonus calc.
    // --------------------------------------------------------
    private function buildAttendanceSummary(array $attendance): array {
        $totalWorkHours   = 0.0;
        $totalOvertimeHrs = 0.0;
        $totalNightHrs    = 0.0;
        $totalHolidayHrs  = 0.0;
        $totalWorkDays    = 0;
        $absentDays       = 0;
        $unpaidLeaveDays  = 0;

        // Index records by ISO week number for per-week Sunday Bonus
        // Structure: [ isoWeek => ['forfeit'=>bool, 'days'=>[dow=>bool]] ]
        $weekData = [];

        foreach ($attendance as $att) {
            $ts  = strtotime($att['attendance_date']);
            $dow = (int)date('N', $ts); // 1=Mon…7=Sun
            $isWeekday = $dow >= 1 && $dow <= 5;
            $isoWeek   = (int)date('W', $ts);

            // Ensure week slot exists
            if ($isWeekday && !isset($weekData[$isoWeek])) {
                $weekData[$isoWeek] = ['forfeit' => false, 'days' => []];
            }

            switch ($att['attendance_type']) {
                case 'half_day':
                    // Half day still counts as attended for Sunday Bonus purposes
                    // (matches index.html's computeBonusWeeks), hours still count.
                    if ($isWeekday) {
                        if (!isset($weekData[$isoWeek])) {
                            $weekData[$isoWeek] = ['forfeit' => false, 'days' => []];
                        }
                        $weekData[$isoWeek]['days'][$dow] = true;
                    }
                    // fall through to accumulate hours
                case 'full_day':
                    // Hours are already correctly split by save_attendance
                    // (smart calc or manual override). Weekend hours are
                    // stored as overtime_hours with work_hours = 0.
                    $totalWorkHours   += (float)$att['work_hours'];
                    $totalOvertimeHrs += (float)$att['overtime_hours'];
                    $totalNightHrs    += (float)$att['night_shift_hours'];
                    $totalHolidayHrs  += (float)$att['holiday_hours'];
                    $totalWorkDays++;

                    // A full_day counts as attended for Sunday Bonus purposes if any
                    // hours were logged — including holiday-worked days where all hours
                    // land in overtime_hours instead of work_hours (weekend/holiday rule).
                    // A full_day record with zero hours in both (e.g. edited/cleared
                    // via the calendar) must NOT still count as attended.
                    $totalHrsLogged = (float)$att['work_hours'] + (float)$att['overtime_hours'];
                    if ($att['attendance_type'] === 'full_day' && $isWeekday && $totalHrsLogged > 0) {
                        $weekData[$isoWeek]['days'][$dow] = true;
                    } elseif ($att['attendance_type'] === 'full_day' && $isWeekday) {
                        if (!isset($weekData[$isoWeek])) {
                            $weekData[$isoWeek] = ['forfeit' => false, 'days' => []];
                        }
                        $weekData[$isoWeek]['forfeit'] = true;
                    }
                    break;

                case 'absent':
                    $absentDays++;
                    if ($isWeekday) {
                        if (!isset($weekData[$isoWeek])) {
                            $weekData[$isoWeek] = ['forfeit' => false, 'days' => []];
                        }
                        $weekData[$isoWeek]['forfeit'] = true; // forfeit this week's bonus
                    }
                    break;

                case 'paid_leave':
                    // Paid leave counts as "attended" for Sunday Bonus purposes
                    if ($isWeekday) {
                        if (!isset($weekData[$isoWeek])) {
                            $weekData[$isoWeek] = ['forfeit' => false, 'days' => []];
                        }
                        $weekData[$isoWeek]['days'][$dow] = true;
                    }
                    break;

                case 'unpaid_leave':
                    $unpaidLeaveDays++;
                    if ($isWeekday) {
                        if (!isset($weekData[$isoWeek])) {
                            $weekData[$isoWeek] = ['forfeit' => false, 'days' => []];
                        }
                        $weekData[$isoWeek]['forfeit'] = true; // forfeit this week's bonus
                    }
                    break;

                default:
                    break;
            }
        }

        return [
            'week_data'             => $weekData,
            'total_work_hours'      => $totalWorkHours,
            'total_overtime_hours'  => $totalOvertimeHrs,
            'total_night_hours'     => $totalNightHrs,
            'total_holiday_hours'   => $totalHolidayHrs,
            'total_work_days'       => $totalWorkDays,
            'absent_days'           => $absentDays,
            'unpaid_leave_days'     => $unpaidLeaveDays,
        ];
    }

    // --------------------------------------------------------
    // Weekly Sunday Bonus
    // Rule: bonus only awarded if ALL 5 weekdays (Mon–Fri) fall
    // inside this month's period AND employee attended all 5.
    // Partial weeks (e.g. last week has only Mon–Wed in the month)
    // are SKIPPED — bonus carries to next month when full week completes.
    // --------------------------------------------------------
    private function calculateSundayBonus(int $employeeId, string $periodStart, string $periodEnd, array $weekData): array {
        $overrideRows = db()->fetchAll(
            "SELECT iso_year, iso_week, override_hours FROM sunday_bonus_overrides WHERE employee_id=?",
            [$employeeId]
        );
        $overrideMap = [];
        foreach ($overrideRows as $o) {
            $overrideMap[$o['iso_year'] . '-' . $o['iso_week']] = (float)$o['override_hours'];
        }

        $periodStartTs = strtotime($periodStart);
        $periodEndTs   = strtotime($periodEnd);

        $qualifyingWeeks       = 0;
        $sundayBonusHoursTotal = 0.0;

        for ($mondayTs = $periodStartTs; $mondayTs <= $periodEndTs; $mondayTs += 86400) {
            if ((int)date('N', $mondayTs) !== 1) {
                continue; // only Mondays
            }

            $isoWeek  = (int)date('W', $mondayTs);
            $isoYear  = (int)date('o', $mondayTs);
            $fridayTs = $mondayTs + 4 * 86400;
            $sundayTs = $mondayTs + 6 * 86400;

            if ($fridayTs > $periodEndTs) {
                continue;
            }
            if ($sundayTs > $periodEndTs) {
                continue;
            }

            $overrideKey = $isoYear . '-' . $isoWeek;
            $weekHours = $this->resolveWeekBonusHours($overrideKey, $overrideMap, $weekData[$isoWeek] ?? null);

            if ($weekHours > 0) {
                $qualifyingWeeks++;
            }
            $sundayBonusHoursTotal += $weekHours;
        }

        return [
            'qualifying_weeks' => $qualifyingWeeks,
            'bonus_hours'      => $sundayBonusHoursTotal,
        ];
    }

    // --------------------------------------------------------
    // Resolve a single ISO week's Sunday Bonus hours: override
    // takes priority, otherwise check full Mon–Fri attendance.
    // --------------------------------------------------------
    private function resolveWeekBonusHours(string $overrideKey, array $overrideMap, ?array $wd): float {
        if (array_key_exists($overrideKey, $overrideMap)) {
            return $overrideMap[$overrideKey];
        }

        if (!$wd || $wd['forfeit']) {
            return 0.0;
        }

        for ($dow = 1; $dow <= 5; $dow++) {
            if (empty($wd['days'][$dow])) {
                return 0.0;
            }
        }

        return 8.0;
    }

    // --------------------------------------------------------
    // SAVE PAYROLL RECORD
    // --------------------------------------------------------
    public function savePayrollRecord(array $calc, int $periodId): int {
        $data = [
            'payroll_period_id'       => $periodId,
            'employee_id'             => $calc['employee']['id'],
            'period_start'            => $calc['period_start'],
            'period_end'              => $calc['period_end'],
            'total_work_days'         => $calc['total_work_days'],
            'total_work_hours'        => $calc['total_work_hours'],
            'overtime_hours'          => $calc['overtime_hours'],
            'night_shift_hours'       => $calc['night_shift_hours'],
            'holiday_hours'           => $calc['holiday_hours'],
            'absent_days'             => $calc['absent_days'],
            'unpaid_leave_days'       => $calc['unpaid_leave_days'],
            'sunday_bonus_weeks'      => $calc['sunday_bonus_weeks'],
            'hourly_rate'             => $calc['hourly_rate'],
            'basic_salary'            => $calc['basic_salary'],
            'overtime_pay'            => $calc['overtime_pay'],
            'night_allowance'         => $calc['night_allowance'],
            'holiday_pay'             => $calc['holiday_pay'],
            'sunday_bonus'            => $calc['sunday_bonus'],
            'due_salary_added'        => $calc['due_salary_added'],
            'gross_salary'            => $calc['gross_salary'],
            'tax_rate'                => $calc['tax_rate'],
            'tax_amount'              => $calc['tax_amount'],
            'advance_deduction'       => $calc['advance_deduction'],
            'unpaid_leave_deduction'  => $calc['unpaid_leave_deduction'],
            'total_deductions'        => $calc['total_deductions'],
            'net_salary'              => $calc['net_salary'],
            'due_salary_carried'      => $calc['due_salary_carried'],
            'status'                  => 'draft',
        ];

        $existing = db()->fetchOne(
            "SELECT id FROM payroll_records WHERE payroll_period_id = ? AND employee_id = ?",
            [$periodId, $calc['employee']['id']]
        );
        if ($existing) {
            db()->update('payroll_records', $data, 'id = ?', [$existing['id']]);
            return $existing['id'];
        }
        return db()->insert('payroll_records', $data);
    }

    // --------------------------------------------------------
    // GENERATE MONTHLY PAYROLL (all active employees)
    // --------------------------------------------------------
    public function generateMonthlyPayroll(int $year, int $month): array {
        $periodStart = sprintf('%04d-%02d-01', $year, $month);
        $periodEnd   = date('Y-m-t', strtotime($periodStart));

        $period = db()->fetchOne(
            "SELECT * FROM payroll_periods WHERE period_year=? AND period_month=?",
            [$year, $month]
        );
        if (!$period) {
            $periodId = db()->insert('payroll_periods', [
                'period_year'  => $year,
                'period_month' => $month,
                'period_start' => $periodStart,
                'period_end'   => $periodEnd,
                'status'       => 'draft',
                'created_by'   => $_SESSION['admin_id'] ?? null,
            ]);
       } else {
            $periodId = $period['id'];
            if ($period['status'] === 'paid') {
                throw new \Exception("Payroll for $year-$month is already paid and cannot be regenerated.");
            }
            if ($period['status'] === 'approved') {
                db()->execute(
                    "UPDATE payroll_periods SET status='draft', approved_by=NULL, approved_at=NULL WHERE id=?",
                    [$periodId]
                );
            }
        }

        $employees = db()->fetchAll(
            "SELECT id FROM employees WHERE employment_status='active' AND deleted_at IS NULL"
        );

        $skipped = [];
        $totalGross = 0.0; $totalNet = 0.0; $totalDed = 0.0; $count = 0;

        foreach ($employees as $emp) {
            try {
                $calc = $this->calculateEmployeePayroll($emp['id'], $year, $month, $periodStart, $periodEnd);

                // Transactional save
                db()->beginTransaction();
                try {
                    db()->execute(
                        "DELETE FROM payroll_records WHERE payroll_period_id=? AND employee_id=? AND status='draft'",
                        [$periodId, $emp['id']]
                    );
                    $this->savePayrollRecord($calc, $periodId);
                    db()->commit();
                } catch (\Throwable $txErr) {
                    db()->rollback();
                    throw $txErr;
                }

                $totalGross += $calc['gross_salary'];
                $totalNet   += $calc['net_salary'];
                $totalDed   += $calc['total_deductions'];
                $count++;
            } catch (\Exception $e) {
                $skipped[] = ['employee_id' => $emp['id'], 'error' => $e->getMessage()];
                error_log("Payroll error for employee {$emp['id']}: " . $e->getMessage());
            }
        }

        db()->execute(
            "UPDATE payroll_periods SET total_employees=?,total_gross=?,total_deductions=?,total_net=? WHERE id=?",
            [$count, $totalGross, $totalDed, $totalNet, $periodId]
        );

        return [
            'period_id'        => $periodId,
            'employees'        => $count,
            'total_gross'      => $totalGross,
            'total_net'        => $totalNet,
            'total_deductions' => $totalDed,
            'skipped'          => $skipped,
        ];
    }

    // --------------------------------------------------------
    // HELPERS
    // --------------------------------------------------------
     private function getPendingAdvances(int $employeeId, string $periodEnd): float {
        // Only count advances taken on or before this period's end date —
        // an advance given mid-July must not appear in June's paysheet.
        $r = db()->fetchOne(
            "SELECT COALESCE(SUM(amount),0) AS total FROM salary_advances
             WHERE employee_id=? AND status='pending' AND advance_date <= ?",
            [$employeeId, $periodEnd]
        );
        return (float)($r['total'] ?? 0);
    }

    private function getPendingDueSalary(int $employeeId, string $periodEnd): float {
        // Same rule: a due-salary row created after this period's end
        // must not be pulled into an earlier month's payroll.
        $r = db()->fetchOne(
            "SELECT COALESCE(SUM(amount),0) AS total FROM due_salaries
             WHERE employee_id=? AND status='pending' AND DATE(created_at) <= ?",
            [$employeeId, $periodEnd]
        );
        return (float)($r['total'] ?? 0);
    }
}
