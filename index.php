<?php
session_start();

// If a config file is requested for download handle it before any output
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

// Enable debug mode if ?debug=1 is set
$debugMode = isset($_GET['debug']);

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}

// Simple login
if (!isset($_SESSION['logged'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $user = $_POST['username'] ?? '';
        $pass = $_POST['password'] ?? '';
        if ($user === 'admin' && $pass === 'password') {
            $_SESSION['logged'] = true;
            header("Location: index.php");
            exit;
        } else {
            $error = "Invalid credentials";
        }
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>WireGuard Admin Login</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
      <div class="container mt-5">
        <div class="row justify-content-center">
          <div class="col-md-4">
            <div class="card shadow-sm">
              <div class="card-header bg-primary text-white">
                <h5 class="mb-0">Login</h5>
              </div>
              <div class="card-body">
                <?php if(isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
                <form method="POST">
                  <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                  </div>
                  <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                  </div>
                  <button type="submit" class="btn btn-primary w-100">Log In</button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

/**
 * Converts a "latest handshake" string into seconds.
 */
function handshakeToSeconds($handshakeStr) {
    $seconds = 0;
    if (preg_match('/(\d+)\s*days?/', $handshakeStr, $matches)) {
        $seconds += $matches[1] * 86400;
    }
    if (preg_match('/(\d+)\s*hours?/', $handshakeStr, $matches)) {
        $seconds += $matches[1] * 3600;
    }
    if (preg_match('/(\d+)\s*minutes?/', $handshakeStr, $matches)) {
        $seconds += $matches[1] * 60;
    }
    if (preg_match('/(\d+)\s*seconds?/', $handshakeStr, $matches)) {
        $seconds += $matches[1];
    }
    return $seconds;
}

/**
 * Converts a value string (e.g. "1.43 GiB") into bytes.
 */
function convertToBytes($valueStr) {
    if (preg_match('/([\d\.]+)\s*(GiB|MiB|KiB|B)/i', $valueStr, $matches)) {
        $number = floatval($matches[1]);
        $unit = strtoupper($matches[2]);
        switch($unit) {
            case 'GIB':
                return $number * 1073741824;
            case 'MIB':
                return $number * 1048576;
            case 'KIB':
                return $number * 1024;
            default:
                return $number;
        }
    }
    return 0;
}

/**
 * Parses the transfer string (e.g. "1.43 GiB received, 2.57 GiB sent")
 * and returns the total formatted in an appropriate unit.
 */
function parseTransfer($transferStr) {
    if (empty($transferStr) || strtolower($transferStr) == 'n/a') {
        return 'N/A';
    }
    $parts = explode(',', $transferStr);
    $sumBytes = 0;
    foreach ($parts as $part) {
        $sumBytes += convertToBytes($part);
    }
    if ($sumBytes >= 1073741824) {
        return sprintf("%.2f GiB", $sumBytes / 1073741824);
    } elseif ($sumBytes >= 1048576) {
        return sprintf("%.2f MiB", $sumBytes / 1048576);
    } elseif ($sumBytes >= 1024) {
        return sprintf("%.2f KiB", $sumBytes / 1024);
    } else {
        return sprintf("%.2f B", $sumBytes);
    }
}

/**
 * Generates a data URI for a QR code PNG using qrencode.
 */
function generateQRCodeDataURI($data) {
    $tmpFile = tempnam(sys_get_temp_dir(), 'qr');
    $pngFile = $tmpFile . '.png';
    $cmd = 'qrencode -o ' . escapeshellarg($pngFile) . ' -t PNG ' . escapeshellarg($data);
    exec($cmd, $output, $return_var);
    if ($return_var !== 0 || !file_exists($pngFile)) {
        if (file_exists($pngFile)) unlink($pngFile);
        unlink($tmpFile);
        return false;
    }
    $pngData = file_get_contents($pngFile);
    unlink($pngFile);
    unlink($tmpFile);
    return 'data:image/png;base64,' . base64_encode($pngData);
}

/**
 * Parses the wg0.conf file.
 * For each [Peer] block, looks at the immediately preceding non-empty line;
 * if it starts with "###", uses it as the client's name (removing the word "Client").
 */
function parseWGConf($filename, &$debugLog = []) {
    if (!file_exists($filename)) {
        $debugLog[] = "File not found: $filename";
        return [];
    }
    $lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $peers = [];
    $totalLines = count($lines);
    $debugLog[] = "Total lines read: $totalLines";
    
    for ($i = 0; $i < $totalLines; $i++) {
        $line = trim($lines[$i]);
        if (preg_match('/^\[Peer\]$/i', $line)) {
            $debugLog[] = "Found [Peer] block at line " . ($i+1);
            $name = '';
            for ($j = $i - 1; $j >= 0; $j--) {
                $prev = trim($lines[$j]);
                if ($prev === '') continue;
                $debugLog[] = "Line preceding line " . ($i+1) . ": $prev";
                if (strpos($prev, '###') === 0) {
                    $name = trim(preg_replace('/\bClient\b\s*/i', '', substr($prev, 3)));
                    $debugLog[] = "Extracted name: $name";
                }
                break;
            }
            $peerData = ['Name' => $name];
            for ($k = $i + 1; $k < $totalLines; $k++) {
                $current = trim($lines[$k]);
                if (preg_match('/^\[.+\]$/', $current)) {
                    break;
                }
                if (strpos($current, '=') !== false) {
                    list($key, $value) = array_map('trim', explode('=', $current, 2));
                    $peerData[$key] = $value;
                }
            }
            if (isset($peerData['PublicKey'])) {
                $peers[$peerData['PublicKey']] = $peerData;
                $debugLog[] = "Added peer: " . $peerData['PublicKey'] . " with name '$name'";
            } else {
                $debugLog[] = "[Peer] block at line " . ($i+1) . " does not contain PublicKey.";
            }
        }
    }
    return $peers;
}

/**
 * Parses the output of "wg show wg0"
 */
function parseWGShow($output) {
    $lines = explode("\n", $output);
    $data = [];
    $currentPeer = null;
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if (strpos($line, 'peer:') === 0) {
            $currentPeer = trim(substr($line, strlen('peer:')));
            $data[$currentPeer] = [];
        } elseif ($currentPeer) {
            if (preg_match('/^(endpoint|allowed ips|latest handshake|transfer):\s*(.+)$/i', $line, $matches)) {
                $key = strtolower($matches[1]);
                $value = $matches[2];
                $data[$currentPeer][$key] = $value;
            }
        }
    }
    return $data;
}

// --- WireGuard Status Section ---

// Path to wg0.conf
$wgConfFile = '/etc/wireguard/wg0.conf';

// Execute "wg show wg0" with sudo (ensure www-data can run sudo wg without a password)
$wgShowOutput = shell_exec('sudo wg show wg0 2>&1');
if (empty($wgShowOutput)) {
    $wgShowOutput = "No data available. Check permissions or if WireGuard is active.";
}
$wgShowData = parseWGShow($wgShowOutput);

// Parse configuration file to get peers with names.
$debugLog = [];
$configPeers = parseWGConf($wgConfFile, $debugLog);

// Merge data: for each peer in wg show, if it exists in configPeers use that data; otherwise set Name to empty.
$mergedPeers = [];
foreach ($wgShowData as $pubkey => $data) {
    if (isset($configPeers[$pubkey])) {
        $mergedPeers[$pubkey] = array_merge($configPeers[$pubkey], $data);
    } else {
        $mergedPeers[$pubkey] = array_merge(['Name' => ''], $data);
    }
}

// --- Client Configuration Files Section ---
// (We use these only for generating the action modals)
// Directory containing client config files (using /root/ as requested)
$clientConfigDir = '/root/';
// Find files matching pattern
$clientConfigFiles = glob($clientConfigDir . 'wg0-client-*.conf');
$clientConfigs = [];
// Build an associative array keyed by lowercased client identifier extracted from filename.
foreach ($clientConfigFiles as $file) {
    $filename = basename($file);
    if (preg_match('/wg0-client-(.+)\.conf/i', $filename, $matches)) {
        $clientId = strtolower($matches[1]);
        $content = file_get_contents($file);
        $qrDataURI = generateQRCodeDataURI($content);
        $clientConfigs[$clientId] = [
            'filename' => $filename,
            'content'  => $content,
            'qr'       => $qrDataURI
        ];
    }
}
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>WireGuard Dashboard</title>
  <!-- Auto-refresh every 5 seconds -->
  <meta http-equiv="refresh" content="5">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding-top: 70px; }
    pre.debug { background: #f8f9fa; padding: 1em; border: 1px solid #ccc; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
  <div class="container">
    <a class="navbar-brand" href="#">WireGuard Dashboard</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
         <li class="nav-item">
           <a class="nav-link" href="?logout=true">Logout</a>
         </li>
         <?php if($debugMode): ?>
         <li class="nav-item">
           <a class="nav-link" href="?debug=0">Disable Debug</a>
         </li>
         <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>
<div class="container" style="margin-top:80px;">
  <h1>WireGuard Clients Status</h1>
  <?php if (empty($mergedPeers)) { ?>
      <div class="alert alert-warning">No peers found.</div>
  <?php } else { ?>
  <div class="table-responsive">
    <table class="table table-bordered table-hover">
      <thead class="table-light">
        <tr>
          <th>Name</th>
          <th>PublicKey</th>
          <th>Endpoint</th>
          <th>Latest Handshake</th>
          <th>Transfer (Total)</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
      <?php
      // For each merged peer, try to find a corresponding client config by matching the lowercased Name.
      foreach ($mergedPeers as $pubkey => $peer) {
          $name      = $peer['Name'] ?? '';
          $endpoint  = $peer['endpoint'] ?? 'N/A';
          $handshake = $peer['latest handshake'] ?? 'N/A';
          $transfer  = $peer['transfer'] ?? 'N/A';
          $totalTransfer = parseTransfer($transfer);
          
          if ($handshake === 'N/A' || $handshake === '' || strtolower($handshake) === '0') {
              $status = "<span class='text-danger'>Disconnected</span>";
          } else {
              $totalSec = handshakeToSeconds($handshake);
              $status = ($totalSec <= 60) ? "<span class='text-success'>Connected</span>" : "<span class='text-danger'>Disconnected</span>";
          }
          
          // Determine actions by matching peer name with clientConfigs key
          $actions = "";
          $clientId = strtolower($name);
          if (!empty($clientId) && isset($clientConfigs[$clientId])) {
              $cfg = $clientConfigs[$clientId];
              $id = md5($cfg['filename']);
              $actions .= '<button type="button" class="btn btn-info btn-sm" data-bs-toggle="modal" data-bs-target="#viewConfigModal-' . $id . '">View Config</button> ';
              $actions .= '<a href="?download=' . urlencode($cfg['filename']) . '" class="btn btn-primary btn-sm">Download</a> ';
              $actions .= '<button type="button" class="btn btn-success btn-sm" data-bs-toggle="modal" data-bs-target="#qrModal-' . $id . '">Show QR</button>';
          }
          
          echo "<tr>
                  <td>$name</td>
                  <td>$pubkey</td>
                  <td>$endpoint</td>
                  <td>$handshake</td>
                  <td>$totalTransfer</td>
                  <td>$status</td>
                  <td>$actions</td>
                </tr>";
      }
      ?>
      </tbody>
    </table>
  </div>
  <?php } ?>

  <!-- Render modals for client configs that matched -->
  <?php 
  if(!empty($clientConfigs)):
      foreach($clientConfigs as $clientId => $cfg):
          $id = md5($cfg['filename']);
          ?>
          <!-- Modal for viewing config -->
          <div class="modal fade" id="viewConfigModal-<?php echo $id; ?>" tabindex="-1" aria-labelledby="viewConfigModalLabel-<?php echo $id; ?>" aria-hidden="true">
            <div class="modal-dialog modal-lg">
               <div class="modal-content">
                  <div class="modal-header">
                     <h5 class="modal-title" id="viewConfigModalLabel-<?php echo $id; ?>">Config: <?php echo htmlspecialchars($cfg['filename']); ?></h5>
                     <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                  <div class="modal-body">
                     <pre><?php echo htmlspecialchars($cfg['content']); ?></pre>
                  </div>
                  <div class="modal-footer">
                     <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                  </div>
               </div>
            </div>
          </div>
          <!-- Modal for QR code -->
          <div class="modal fade" id="qrModal-<?php echo $id; ?>" tabindex="-1" aria-labelledby="qrModalLabel-<?php echo $id; ?>" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
               <div class="modal-content">
                  <div class="modal-header">
                     <h5 class="modal-title" id="qrModalLabel-<?php echo $id; ?>">QR Code: <?php echo htmlspecialchars($cfg['filename']); ?></h5>
                     <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                  <div class="modal-body text-center">
                    <?php if($cfg['qr'] !== false): ?>
                      <img src="<?php echo $cfg['qr']; ?>" alt="QR Code for <?php echo htmlspecialchars($cfg['filename']); ?>" class="img-fluid">
                    <?php else: ?>
                      <div class="alert alert-danger">QR code generation failed.</div>
                    <?php endif; ?>
                  </div>
                  <div class="modal-footer">
                     <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                  </div>
               </div>
            </div>
          </div>
      <?php 
      endforeach;
  endif;
  ?>

  <?php if($debugMode): ?>
  <hr>
  <h2>Debug wg0.conf Parsing</h2>
  <pre class="debug"><?php echo htmlspecialchars(print_r($debugLog, true)); ?></pre>
  <h2>Debug Config Peers Array</h2>
  <pre class="debug"><?php echo htmlspecialchars(print_r($configPeers, true)); ?></pre>
  <h2>Debug wg show Output</h2>
  <pre class="debug"><?php echo htmlspecialchars($wgShowOutput); ?></pre>
  <?php endif; ?>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
