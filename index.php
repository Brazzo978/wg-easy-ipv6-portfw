<?php
session_start();

// Configurazione GUI: utente e password (modificabili via toggle_gui.sh)
$admin_user = 'admin';
$admin_pass = 'password';  // <-- password GUI

// Setup temi e colori accent
$accent_colors = ['teal','blue','purple','orange','red','green','indigo','pink'];
$accent = in_array($_COOKIE['accent'] ?? '', $accent_colors) ? $_COOKIE['accent'] : 'teal';
$mode   = ($_COOKIE['mode'] ?? 'light') === 'dark' ? 'dark' : 'light';

// Utility functions
function handshakeToSeconds($handshakeStr) {
    $seconds = 0;
    if (preg_match('/(\d+)\s*days?/', $handshakeStr, $m)) $seconds += $m[1] * 86400;
    if (preg_match('/(\d+)\s*hours?/', $handshakeStr, $m)) $seconds += $m[1] * 3600;
    if (preg_match('/(\d+)\s*minutes?/', $handshakeStr, $m)) $seconds += $m[1] * 60;
    if (preg_match('/(\d+)\s*seconds?/', $handshakeStr, $m)) $seconds += $m[1];
    return $seconds;
}

function convertToBytes($valueStr) {
    if (preg_match('/([\d\.]+)\s*(GiB|MiB|KiB|B)/i', $valueStr, $m)) {
        $n = floatval($m[1]);
        switch (strtoupper($m[2])) {
            case 'GIB': return $n * 1073741824;
            case 'MIB': return $n * 1048576;
            case 'KIB': return $n * 1024;
            default:    return $n;
        }
    }
    return 0;
}

function parseTransfer($transferStr) {
    if (empty($transferStr) || strtolower($transferStr) === 'n/a') {
        return 'N/A';
    }
    $sum = 0;
    foreach (explode(',', $transferStr) as $part) {
        $sum += convertToBytes($part);
    }
    if ($sum >= 1073741824) {
        return sprintf("%.2f GiB", $sum / 1073741824);
    } elseif ($sum >= 1048576) {
        return sprintf("%.2f MiB", $sum / 1048576);
    } elseif ($sum >= 1024) {
        return sprintf("%.2f KiB", $sum / 1024);
    }
    return sprintf("%.2f B", $sum);
}

function generateQRCodeDataURI($data) {
    $tmp  = tempnam(sys_get_temp_dir(), 'qr');
    $png  = $tmp . '.png';
    $cmd  = 'qrencode -o ' . escapeshellarg($png) . ' -t PNG ' . escapeshellarg($data);
    exec($cmd, $output, $return_var);
    if ($return_var !== 0 || !file_exists($png)) {
        @unlink($png);
        return false;
    }
    $pngData = file_get_contents($png);
    unlink($png);
    return 'data:image/png;base64,' . base64_encode($pngData);
}

function parseWGConf($filename, &$debugLog = []) {
    if (!file_exists($filename)) {
        $debugLog[] = "File not found: $filename";
        return [];
    }
    $lines = file($filename, FILE_IGNORE_NEW_LINES);
    $debugLog[] = "Lines read: " . count($lines);
    $peers = [];
    for ($i = 0; $i < count($lines); $i++) {
        if (trim($lines[$i]) === '[Peer]') {
            $name = '';
            for ($j = $i - 1; $j >= 0; $j--) {
                $prev = trim($lines[$j]);
                if ($prev === '') break;
                if (strpos($prev, '###') === 0) {
                    $name = trim(preg_replace('/\bClient\b\s*/i', '', substr($prev, 3)));
                }
                break;
            }
            $peerData = ['Name' => $name];
            for ($k = $i + 1; $k < count($lines); $k++) {
                $curr = trim($lines[$k]);
                if (preg_match('/^\[.+\]$/', $curr)) break;
                if (strpos($curr, '=') !== false) {
                    list($key, $val) = array_map('trim', explode('=', $curr, 2));
                    $peerData[$key] = $val;
                }
            }
            if (isset($peerData['PublicKey'])) {
                $peers[$peerData['PublicKey']] = $peerData;
            } else {
                $debugLog[] = "Peer at line " . ($i+1) . " missing PublicKey";
            }
        }
    }
    return $peers;
}

function parseWGShow($output) {
    $lines = explode("\n", $output);
    $data  = [];
    $cur   = null;
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if (strpos($line, 'peer:') === 0) {
            $cur = trim(substr($line, strlen('peer:')));
            $data[$cur] = [];
        } elseif ($cur) {
            if (preg_match('/^(endpoint|allowed ips|latest handshake|transfer):\s*(.+)$/i', $line, $m)) {
                $data[$cur][strtolower($m[1])] = $m[2];
            }
        }
    }
    return $data;
}

// --- Handle download ---
if (isset($_GET['download'])) {
    $file = basename($_GET['download']);
    $path = '/root/' . $file;
    if (file_exists($path)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $file . '"');
        readfile($path);
    } else {
        http_response_code(404);
        echo 'File not found.';
    }
    exit;
}

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Login Page
if (!isset($_SESSION['logged'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $user = $_POST['username'] ?? '';
        $pass = $_POST['password'] ?? '';
        if ($user === $admin_user && $pass === $admin_pass) {
            $_SESSION['logged'] = true;
            header('Location: index.php');
            exit;
        } else {
            $error = 'Credenziali non valide';
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="it" data-mode="<?= \$mode ?>" data-accent="<?= \$accent ?>">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Login WireGuard</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      <style>
        :root { --accent: var(--bs-<?= \$accent ?>); }
        body[data-mode="light"] { background: #f8f9fa; color: #212529; }
        body[data-mode="dark"] { background: #121212; color: #e0e0e0; }
        [data-mode="dark"] .card { background: #1e1e1e; color: #e0e0e0; }
        .btn-accent { background: var(--accent); border-color: var(--accent); }
      </style>
    </head>
    <body data-mode="<?= \$mode ?>">
      <div class="container mt-5"><div class="row justify-content-center"><div class="col-md-4">
        <div class="card shadow-sm">
          <div class="card-header d-flex justify-content-between align-items-center btn-accent text-white">
            <span>Login</span>
            <button id="toggle-mode" class="btn btn-sm btn-light">Mode</button>
          </div>
          <div class="card-body">
            <?php if (isset(\$error)) echo "<div class='alert alert-danger'>\$error</div>"; ?>
            <form method="POST">
              <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" name="username" id="username" class="form-control" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" name="password" id="password" class="form-control" required>
              </div>
              <div class="mb-3">
                <label for="accent-select" class="form-label">Accent Color</label>
                <select id="accent-select" class="form-select">
                  <?php foreach (\$accent_colors as \$c): ?>
                    <option value="<?= \$c ?>" <?= \$c === \$accent ? 'selected' : '' ?>><?= ucfirst(\$c) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <button type="submit" class="btn btn-accent w-100">Accedi</button>
            </form>
          </div>
        </div>
      </div></div></div>
      <script>
        document.getElementById('toggle-mode').onclick = function() {
          var newMode = document.documentElement.getAttribute('data-mode') === 'light' ? 'dark' : 'light';
          document.cookie = 'mode=' + newMode + ';path=/;max-age=' + 60*60*24*365;
          location.reload();
        };
        document.getElementById('accent-select').onchange = function(e) {
          document.cookie = 'accent=' + e.target.value + ';path=/;max-age=' + 60*60*24*365;
          location.reload();
        };
      </script>
    </body>
    </html>
    <?php
    exit;
}

// --- Dashboard ---
$wgShowOutput  = shell_exec('sudo wg show wg0 2>&1') ?: 'No data available';
$wgShowData    = parseWGShow($wgShowOutput);
$debugLog      = [];
$configPeers   = parseWGConf('/etc/wireguard/wg0.conf', $debugLog);
$mergedPeers   = [];
foreach ($wgShowData as $pk => $pdata) {
    $mergedPeers[$pk] = isset($configPeers[$pk]) ? array_merge($configPeers[$pk], $pdata) : array_merge(['Name'=> ''], $pdata);
}

$clientConfigs = [];
foreach (glob('/root/wg0-client-*.conf') as $f) {
    if (preg_match('/wg0-client-(.+)\.conf/i', basename($f), $m)) {
        $id    = strtolower($m[1]);
        $cdata = file_get_contents($f);
        $qr    = generateQRCodeDataURI($cdata);
        $clientConfigs[$id] = [
            'fname' => basename($f),
            'qr'    => $qr
        ];
    }
}
?>
<!DOCTYPE html>
<html lang="it" data-mode="<?= \$mode ?>" data-accent="<?= \$accent ?>">
<head>
  <meta charset="utf-8">
