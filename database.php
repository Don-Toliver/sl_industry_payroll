<?php
// ============================================================
// SL INDUSTRY - Database Configuration
// ============================================================

define('DB_HOST', 'localhost');
define('DB_PORT', '3306');
define('DB_NAME', 'korean_sl_industry');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

define('APP_NAME', 'SL Industry Payroll');
define('APP_VERSION', '1.0.0');
define('APP_URL', 'http://localhost/sl-industry');
define('APP_TIMEZONE', 'Asia/Seoul');
define('APP_CURRENCY', '₩');

// Security
define('SESSION_LIFETIME', 3600 * 8); // 8 hours
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_MINUTES', 30);
define('CSRF_TOKEN_LENGTH', 32);

// File Upload
define('MAX_FILE_SIZE_MB', 5);
define('ALLOWED_IMAGE_TYPES', ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf']);
define('UPLOAD_PATH', __DIR__ . '/uploads/');

// Set timezone
date_default_timezone_set(APP_TIMEZONE);

class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        ];
        try {
            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log("DB Connection Failed: " . $e->getMessage());
            die(json_encode(['error' => 'Database connection failed']));
        }
    }

    public static function getInstance(): Database {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection(): PDO {
        return $this->pdo;
    }

    /**
     * Validates a SQL identifier (table or column name) to prevent injection.
     * Only allows letters, numbers, and underscores.
     */
    private function validateIdentifier(string $identifier, string $type = 'identifier'): void {
        if (!preg_match('/^[A-Za-z_]\w*$/', $identifier)) {
            throw new InvalidArgumentException("Invalid {$type} name: {$identifier}");
        }
    }

    public function query(string $sql, array $params = []): PDOStatement {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public function fetchOne(string $sql, array $params = []): ?array {
        return $this->query($sql, $params)->fetch() ?: null;
    }

    public function fetchAll(string $sql, array $params = []): array {
        return $this->query($sql, $params)->fetchAll();
    }

    public function insert(string $table, array $data): int {
        $this->validateIdentifier($table, 'table');
        foreach (array_keys($data) as $col) {
            $this->validateIdentifier($col, 'column');
        }
        $cols = implode(', ', array_keys($data));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        $sql = "INSERT INTO {$table} ({$cols}) VALUES ({$placeholders})";
        $this->query($sql, array_values($data));
        return (int) $this->pdo->lastInsertId();
    }

    public function update(string $table, array $data, string $where, array $whereParams = []): int {
        $this->validateIdentifier($table, 'table');
        foreach (array_keys($data) as $col) {
            $this->validateIdentifier($col, 'column');
        }
        $sets = implode(' = ?, ', array_keys($data)) . ' = ?';
        $sql = "UPDATE {$table} SET {$sets} WHERE {$where}";
        $params = array_merge(array_values($data), $whereParams);
        return $this->query($sql, $params)->rowCount();
    }

    public function execute(string $sql, array $params = []): int {
        return $this->query($sql, $params)->rowCount();
    }

    public function lastInsertId(): int {
        
    return (int) $this->pdo->lastInsertId();
    }

    public function beginTransaction(): void { $this->pdo->beginTransaction(); }
    public function commit(): void { $this->pdo->commit(); }
    public function rollback(): void { $this->pdo->rollBack(); }
}

function db(): Database { return Database::getInstance(); }
