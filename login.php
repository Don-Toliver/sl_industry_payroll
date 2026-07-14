<?php
require_once __DIR__ . '/helpers.php';
initSession();

if (isLoggedIn()) {
    header('Location: ' . APP_URL . '/index.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!validateCSRF($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid session. Please refresh and try again.';
    } elseif ($username === '' || $password === '') {
        $error = 'Please enter username and password.';
    } else {
        $db   = db();
        $admin = $db->fetchOne(
            "SELECT * FROM admin_users WHERE username = ? AND is_active = 1 LIMIT 1",
            [$username]
        );

        // Check lockout
        if ($admin && $admin['locked_until'] && strtotime($admin['locked_until']) > time()) {
            $mins = ceil((strtotime($admin['locked_until']) - time()) / 60);
            $error = "Account locked. Try again in $mins minute(s).";
        } elseif ($admin && password_verify($password, $admin['password_hash'])) {
            // Success
            $db->execute(
                "UPDATE admin_users SET login_attempts=0, locked_until=NULL, last_login=NOW() WHERE id=?",
                [$admin['id']]
            );
            loginAdmin($admin);
            header('Location: ' . APP_URL . '/index.php');
            exit;
        } else {
            $error = 'Invalid username or password.';
            if ($admin) {
                $attempts = $admin['login_attempts'] + 1;
                if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                    $until = date('Y-m-d H:i:s', time() + LOGIN_LOCKOUT_MINUTES * 60);
                    $db->execute(
                        "UPDATE admin_users SET login_attempts=?, locked_until=? WHERE id=?",
                        [$attempts, $until, $admin['id']]
                    );
                    $error = 'Too many failed attempts. Account locked for ' . LOGIN_LOCKOUT_MINUTES . ' minutes.';
                } else {
                    $db->execute(
                        "UPDATE admin_users SET login_attempts=? WHERE id=?",
                        [$attempts, $admin['id']]
                    );
                }
            }
        }
    }
}
$csrf = generateCSRF();
$companyLogo = db()->fetchOne("SELECT company_logo FROM company_settings LIMIT 1")['company_logo'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login – SL Industry Payroll</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#F3F5F9;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:'Inter',sans-serif}
  .card{background:#FFFFFF;border:1px solid #E1E7EF;border-radius:14px;padding:44px 40px;width:380px;box-shadow:0 20px 60px rgba(15,30,46,.12)}
  .logo{width:64px;height:64px;background:#E63946;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:900;color:#fff;margin:0 auto 18px}
  h2{color:#0F1E2E;text-align:center;font-size:20px;margin-bottom:6px}
  .sub{color:#5B6B7C;text-align:center;font-size:13px;margin-bottom:28px}
  label{color:#5B6B7C;font-size:13px;display:block;margin-bottom:6px;margin-top:16px}
  .form-control{background:#F3F5F9;border:1px solid #E1E7EF;color:#0F1E2E;border-radius:8px;padding:10px 14px;width:100%;font-size:14px}
  .form-control:focus{outline:none;border-color:#0891B2;box-shadow:0 0 0 3px rgba(8,145,178,.15)}
  .pw-wrap{position:relative}
  .pw-wrap .form-control{padding-right:44px}
  .eye-btn{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:#5B6B7C;cursor:pointer;padding:4px}
  .btn-login{margin-top:24px;width:100%;padding:12px;background:#E63946;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
  .btn-login:hover{background:#c1121f}
  .alert{background:rgba(230,57,70,.1);border:1px solid rgba(230,57,70,.35);color:#C1121F;padding:10px 14px;border-radius:8px;font-size:13px;margin-top:16px}
</style>
</head>
<body>
<div class="card">
  <?php if ($companyLogo): ?>
    <div class="logo"><img src="uploads/<?= htmlspecialchars($companyLogo) ?>" style="width:100%;height:100%;object-fit:cover;border-radius:inherit;"></div>
  <?php else: ?>
    <div class="logo">SL</div>
  <?php endif; ?>

  <h2>Admin Login</h2>
  <p class="sub">SL Industry Payroll Management</p>

  <?php if ($error): ?>
    <div class="alert"><?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <form method="POST" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" class="form-control"
           placeholder="admin" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required autofocus>
    <label for="password">Password</label>
    <div class="pw-wrap">
      <input type="password" id="password" name="password" class="form-control" placeholder="••••••••" required>
      <button type="button" class="eye-btn" onclick="togglePwd()">
        <svg id="eyeIcon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
        </svg>
      </button>
    </div>
    <button type="submit" class="btn-login">Sign In</button>
  </form>
</div>
<script>
function togglePwd(){
  const pw=document.getElementById('password');
  pw.type = pw.type==='password' ? 'text' : 'password';
}
</script>
</body>
</html>
