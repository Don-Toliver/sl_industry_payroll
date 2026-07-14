<?php
require_once __DIR__ . '/helpers.php';
initSession();
if (!isLoggedIn()) {
    header('Location: ' . APP_URL . '/login.php');
    exit;
}
include __DIR__ . '/index.html';
