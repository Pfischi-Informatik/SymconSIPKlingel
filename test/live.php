<?php

declare(strict_types=1);

/**
 * Live-Test ohne Symcon. Stellt IPSModule und die IPS-Funktionen minimal nach.
 * 
 *
 *   php -d zend.assertions=1 -d assert.exception=1 test/live.php
 *       spielt einen Provider mit Paketen nach (ohne Netz)
 *   SIP_HOST=.. SIP_USER=.. SIP_PASS=.. [SIP_PORT=5060] php test/live.php
 *       echte Anmeldung ueber UDP, wartet dann SIP_WAIT Sekunden (Standard 60) auf Anrufe
 *   DEBUG=1 ... zeigt SendDebug-Ausgaben
 */

const VARIABLETYPE_BOOLEAN = 0;
const VARIABLETYPE_INTEGER = 1;
const VARIABLETYPE_FLOAT = 2;
const VARIABLETYPE_STRING = 3;
const KL_MESSAGE = 10206;
const KL_WARNING = 10;
const KL_ERROR = 20;
const KR_READY = 10103;
function IPS_VariableProfileExists($n) { global $profiles; return isset($profiles[$n]); }
function IPS_CreateVariableProfile($n, $t) { global $profiles; $profiles[$n] = []; }
function IPS_DeleteVariableProfile($n) { global $profiles; unset($profiles[$n]); }
function IPS_SetVariableProfileAssociation($n, $v, $name, $i, $c) { global $profiles; $profiles[$n][$v] = $name; }
function IPS_SetVariableProfileValues($n, $min, $max, $step) {}
function IPS_SetVariableProfileText($n, $prefix, $suffix) {}
function IPS_SetVariableProfileIcon($n, $icon) {}
function IPS_GetKernelRunlevel() { return KR_READY; }
function IPS_InstanceExists($i) { return $i === 777 || $i === 778; }
function VISU_OpenObject($v, $o, $t) { global $visu; $visu[] = ['open', $v, $o]; return true; }
function VISU_PostNotificationEx($v, $title, $text, $icon, $sound, $target) { global $visu; $visu[] = ['push', $text, $sound, $target]; return true; }
function IPS_SemaphoreEnter($n, $t) { return true; }
function IPS_SemaphoreLeave($n) { return true; }

class IPSModule
{
    public $InstanceID = 12345;
    private $props = [], $attrs = [], $values = [];
    public $status = 0;
    public function Create(): void {}
    public function Destroy(): void {}
    public function ApplyChanges(): void {}
    protected function RegisterPropertyString($n, $v) { $this->props[$n] = $v; }
    protected function RegisterPropertyInteger($n, $v) { $this->props[$n] = $v; }
    protected function RegisterPropertyBoolean($n, $v) { $this->props[$n] = $v; }
    protected function RegisterPropertyFloat($n, $v) { $this->props[$n] = $v; }
    public function SetProperty($n, $v) { $this->props[$n] = $v; }
    protected function ReadPropertyString($n) { return $this->props[$n]; }
    protected function ReadPropertyInteger($n) { return $this->props[$n]; }
    protected function ReadPropertyBoolean($n) { return $this->props[$n]; }
    protected function ReadPropertyFloat($n) { return $this->props[$n]; }
    protected function RegisterAttributeString($n, $v) { $this->attrs[$n] = $v; }
    protected function RegisterAttributeInteger($n, $v) { $this->attrs[$n] = $v; }
    protected function RegisterAttributeBoolean($n, $v) { $this->attrs[$n] = $v; }
    public function ReadAttributeString($n) { return $this->attrs[$n]; }
    public function ReadAttributeInteger($n) { return $this->attrs[$n]; }
    public function ReadAttributeBoolean($n) { return $this->attrs[$n]; }
    public function WriteAttributeString($n, $v) { $this->attrs[$n] = $v; }
    public function WriteAttributeInteger($n, $v) { $this->attrs[$n] = $v; }
    public function WriteAttributeBoolean($n, $v) { $this->attrs[$n] = $v; }
    protected function RegisterTimer($n, $i, $s) {}
    public $timers = [];
    protected function SetTimerInterval($n, $i) { $this->timers[$n] = $i; }
    protected function RegisterVariableBoolean($i, $n, $p = '', $pos = 0) { $this->values[$i] ??= false; }
    protected function RegisterVariableInteger($i, $n, $p = '', $pos = 0) { $this->values[$i] ??= 0; }
    protected function RegisterVariableFloat($i, $n, $p = '', $pos = 0) { $this->values[$i] ??= 0.0; }
    protected function RegisterVariableString($i, $n, $p = '', $pos = 0) { $this->values[$i] ??= ''; }
    protected function EnableAction($i) {}
    protected function SetValue($i, $v) { $this->values[$i] = $v; }
    public function GetValue($i) { return $this->values[$i]; }
    protected function SetStatus($s) { $this->status = $s; }
    public $sent = [], $wire = null;
    public $once = [];
    protected function RegisterOnceTimer($n, $s) { $this->once[] = $s; }
    protected function ForceParent($g) {}
    protected function SetVisualizationType($t) {}
    protected function UpdateVisualizationValue($v) {}
    protected function HasActiveParent() { return true; }
    protected function SendDataToParent($json) {
        $d = json_decode($json, true);
        $d['raw'] = mb_convert_encoding($d['Buffer'], 'ISO-8859-1', 'UTF-8');
        assert($d['DataID'] === '{8E4D9B23-E0F2-1E05-41D8-C21EA53B8706}');
        $this->sent[] = $d;
        if ($this->wire) {
            ($this->wire)($d);
        }
        return '';
    }
    protected function Translate($s) { return $s; }
    protected function LogMessage($m, $t) { fwrite(STDERR, "LOG: $m\n"); }
    protected function SendDebug($t, $m, $f) { if (getenv('DEBUG')) fwrite(STDERR, "DEBUG $t: " . substr((string) $m, 0, 400) . "\n"); }
}

// --- Provider-Nachbau ------------------------------------------------------

require __DIR__ . '/../SIPKlingel/module.php';

function packet($m, string $raw, string $ip = '198.51.100.7', int $port = 5060): void
{
    $m->ReceiveData(json_encode([
        'DataID' => '{9082C662-7864-D5CA-863F-53999200D897}',
        'Buffer' => mb_convert_encoding($raw, 'UTF-8', 'ISO-8859-1'),
        'ClientIP' => $ip,
        'ClientPort' => $port,
    ]));
}

function lastRaw($m): string
{
    return end($m->sent)['raw'];
}

function headerOf(string $raw, string $name): string
{
    return preg_match('/^' . $name . ': (.*)\r$/mi', $raw, $x) ? $x[1] : '';
}

function answer($m, int $code, string $extra = '', string $via = ''): void
{
    $req = lastRaw($m);
    $v = headerOf($req, 'Via') . $via;
    packet($m, "SIP/2.0 $code X\r\nVia: $v\r\nCall-ID: " . headerOf($req, 'Call-ID') . "\r\nCSeq: " . headerOf($req, 'CSeq') . "\r\n$extra\r\n");
}

function invite(string $id, string $from, string $uri = 'sip:x@198.51.100.1:5070'): string
{
    return "INVITE $uri SIP/2.0\r\nv: SIP/2.0/UDP 198.51.100.7;branch=z9hG4bK1\r\nVia: SIP/2.0/UDP 203.0.113.5;branch=z9hG4bK2\r\nf: $from;tag=a\r\nt: <sip:me@p>\r\ni: $id\r\nCSeq: 7 INVITE\r\nl: 0\r\n\r\n";
}

function cancel(string $id): string
{
    return "CANCEL sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.7;branch=z9hG4bK1\r\nFrom: <sip:a@p>;tag=a\r\nTo: <sip:me@p>\r\nCall-ID: $id\r\nCSeq: 7 CANCEL\r\nContent-Length: 0\r\n\r\n";
}

function module(string $host, int $port, string $user, string $pass, ?callable $wire = null): SIPKlingel
{
    $m = new SIPKlingel();
    $m->wire = $wire;
    $m->Create();
    $m->SetProperty('Provider', $host);
    $m->SetProperty('Port', $port);
    $m->SetProperty('Username', $user);
    $m->SetProperty('Password', $pass);
    $m->ApplyChanges();
    return $m;
}

// --- Echter Provider --------------------------------------------------------

if (getenv('SIP_HOST')) {
    $host = getenv('SIP_HOST');
    $wait = (int) (getenv('SIP_WAIT') ?: 60);
    $socket = stream_socket_server('udp://0.0.0.0:5070', $errno, $error, STREAM_SERVER_BIND);
    assert($socket !== false, "Port 5070 belegt: $error");

    $probe = new SIPKlingel();
    $probe->Create();
    $probe->SetProperty('Provider', $host);
    $probe->SetProperty('Port', (int) (getenv('SIP_PORT') ?: 5060));
    $probe->SetProperty('Username', 'x');
    $probe->SetProperty('Password', 'x');
    $cfg = json_decode($probe->GetConfigurationForParent(), true);
    $dest = gethostbyname($cfg['Host']) . ':' . $cfg['Port'];
    echo "Ziel: {$cfg['Host']} -> $dest\n";

    $m = module($host, (int) $cfg['Port'], getenv('SIP_USER'), getenv('SIP_PASS'), function ($d) use ($socket, $dest) {
        $to = $d['ClientIP'] !== '' ? "{$d['ClientIP']}:{$d['ClientPort']}" : $dest;
        stream_socket_sendto($socket, $d['raw'], 0, $to);
    });

    $end = time() + $wait;
    $state = null;
    while (time() < $end) {
        $r = [$socket]; $w = $e = null;
        if (stream_select($r, $w, $e, 1)) {
            $raw = stream_socket_recvfrom($socket, 65535, 0, $peer);
            [$ip, $port] = explode(':', $peer);
            packet($m, $raw, $ip, (int) $port);
        }
        $now = "Status {$m->status}, angemeldet=" . var_export($m->GetValue('Registered'), true)
            . ', klingelt=' . var_export($m->GetValue('Ringing'), true) . ', Anrufer=' . $m->GetValue('Caller');
        if ($now !== $state) {
            echo date('H:i:s '), $now, "\n";
            $state = $now;
        }
        if ($m->status === 201 || $m->status === 203) {
            break;
        }
    }
    exit;
}

// --- Digest: Pruefvektor aus RFC 2617 ---------------------------------------

$m = module('sip.example.test', 5060, 'alice', 'geheim');
$digest = new ReflectionMethod(SIPKlingel::class, 'digest');
$rfc = ['realm' => 'testrealm@host.com', 'nonce' => 'dcd98b7102dd2f0e8b11d0f600bfb0c093', 'qop' => 'auth,auth-int'];
assert($digest->invoke($m, 'GET', '/dir/index.html', 'Mufasa', 'Circle Of Life', $rfc, '0a4f113b', '00000001') === '6629fae49393a05397450978507c4ef1');

// --- Anmeldung -----------------------------------------------------------------

$reg = lastRaw($m);
assert(str_starts_with($reg, 'REGISTER sip:sip.example.test SIP/2.0'));
assert(str_contains($reg, ';rport;branch=z9hG4bK'));
assert($m->timers['SIPKRegister'] === 4000, 'Wiederholung laeuft');

answer($m, 401, "WWW-Authenticate: Digest realm=\"r\", nonce=\"n1\", qop=\"auth\", opaque=\"o\"\r\n");
$auth = headerOf(lastRaw($m), 'Authorization');
assert(str_contains($auth, 'username="alice"') && str_contains($auth, 'opaque="o"') && str_contains($auth, 'qop=auth'));

answer($m, 200, "Contact: <sip:x@1.2.3.4>;expires=120\r\n", ';received=203.0.113.9;rport=40000');
assert(str_contains(lastRaw($m), 'Contact: <sip:') && str_contains(lastRaw($m), '@203.0.113.9:40000>'), 'oeffentliche Adresse wird nachgemeldet');
assert($m->status !== 102 || !$m->GetValue('Registered'));
answer($m, 200, "Contact: <sip:x@1.2.3.4>;expires=120\r\n", ';received=203.0.113.9;rport=40000');
assert($m->status === 102 && $m->GetValue('Registered') === true);
assert($m->timers['SIPKRegister'] === 60000, 'Erneuerung nach halber Laufzeit');

// Falsche Antwort aendert nichts
$count = count($m->sent);
packet($m, "SIP/2.0 401 X\r\nCall-ID: fremd\r\nCSeq: 1 REGISTER\r\n\r\n");
assert(count($m->sent) === $count && $m->status === 102);

// Falsches Passwort: ein Versuch, dann lange Pause
$bad = module('sip.example.test', 5060, 'alice', 'falsch');
answer($bad, 401, "WWW-Authenticate: Digest realm=\"r\", nonce=\"n\"\r\n");
$count = count($bad->sent);
answer($bad, 401, "WWW-Authenticate: Digest realm=\"r\", nonce=\"n2\"\r\n");
assert(count($bad->sent) === $count && $bad->status === 201 && $bad->timers['SIPKRegister'] === 300000);

// Stale-Nonce ist kein falsches Passwort
$stale = module('sip.example.test', 5060, 'alice', 'x');
answer($stale, 401, "WWW-Authenticate: Digest realm=\"r\", nonce=\"n\"\r\n");
$count = count($stale->sent);
answer($stale, 401, "WWW-Authenticate: Digest realm=\"r\", nonce=\"n2\", stale=true\r\n");
assert(count($stale->sent) === $count + 1 && $stale->status !== 201);

// Keine Antwort: nach drei Versuchen Status 202, weiter im Hintergrund
$silent = module('sip.example.test', 5060, 'alice', 'x');
for ($i = 0; $i < 3; $i++) {
    $silent->Register();
}
assert($silent->status === 202 && $silent->timers['SIPKRegister'] === 30000);

// --- Anruf -----------------------------------------------------------------------

// Fremder Absender klingelt nicht
$count = count($m->sent);
packet($m, invite('scan', '<sip:100@evil>'), '192.0.2.66');
assert($m->GetValue('Ringing') === false && count($m->sent) === $count, 'Scanner verworfen');

packet($m, invite('c1', '"Max Muster" <sip:+41791234567@p>'));
$ring = lastRaw($m);
assert(str_starts_with($ring, 'SIP/2.0 180 Ringing'));
assert(substr_count($ring, 'Via:') === 2, 'beide Via zurueck');
assert(preg_match('/^To: <sip:me@p>;tag=\w+/m', $ring) === 1);
assert(end($m->sent)['ClientIP'] === '198.51.100.7');
assert($m->GetValue('Ringing') === true && $m->GetValue('Caller') === 'Max Muster (+41791234567)');
assert($m->GetValue('LastCall') > 0);
assert($m->timers['SIPKCalls'] === 1000);
assert(count($m->once) === 1 && str_contains($m->once[0], 'SIPK_Notify'), 'Meldung im eigenen Thread');
$visu = [];
$m->Notify();
assert($visu === [], 'ohne Visualisierung keine Meldung');
$m->SetProperty('Visualizations', json_encode([['InstanceID' => 777], ['InstanceID' => 778], ['InstanceID' => 777], ['InstanceID' => 0]]));
$m->Notify();
assert($visu[0] === ['open', 777, $m->InstanceID]);
assert($visu[1] === ['push', 'Max Muster (+41791234567)', 'bell', $m->InstanceID]);
assert($visu[2] === ['open', 778, $m->InstanceID]);
assert($visu[3][0] === 'push' && count($visu) === 4, 'jede Visualisierung genau einmal, leere Zeile ignoriert');

// Wiederholtes INVITE ist kein neuer Anruf
$stamp = $m->GetValue('LastCall');
packet($m, invite('c1', '"Max Muster" <sip:+41791234567@p>'));
assert(str_starts_with(lastRaw($m), 'SIP/2.0 180') && count(json_decode($m->ReadAttributeString('Calls'), true)) === 1);
assert(count($m->once) === 1, 'Wiederholung meldet nicht nochmal');

// Parallel zweiter Anruf, erstes CANCEL laesst weiterklingeln
packet($m, invite('c2', '<sip:anonymous@anonymous.invalid>'));
assert($m->GetValue('Caller') === 'Unbekannt');
packet($m, cancel('c1'));
assert($m->GetValue('Ringing') === true);
assert(str_starts_with(lastRaw($m), 'SIP/2.0 487'), '487 nach CANCEL');
assert(str_contains(lastRaw($m), 'CSeq: 7 INVITE'));

// Letztes CANCEL beendet das Klingeln
packet($m, cancel('c2'));
assert($m->GetValue('Ringing') === false);

// Verspaetetes INVITE startet nicht neu
packet($m, invite('c1', '<sip:1@p>'));
assert(str_starts_with(lastRaw($m), 'SIP/2.0 487') && $m->GetValue('Ringing') === false);
packet($m, "ACK sip:x SIP/2.0\r\nCall-ID: c1\r\nCSeq: 7 ACK\r\n\r\n");

// Unbekannte IP, aber Kennung aus dem Contact: das ist der Provider
$token = $m->ReadAttributeString('Token');
packet($m, invite('c3', '<tel:+4144>', "sip:$token@198.51.100.1:5070"), '198.51.100.99');
assert($m->GetValue('Ringing') === true && $m->GetValue('Caller') === '+4144');

// Verlorenes CANCEL: Notbremse nach 120 Sekunden
$calls = json_decode($m->ReadAttributeString('Calls'), true);
$calls['c3']['started'] = time() - 121;
$m->WriteAttributeString('Calls', json_encode($calls));
$m->CheckCalls();
assert($m->GetValue('Ringing') === false && str_starts_with(lastRaw($m), 'SIP/2.0 480'));

// Testklingeln ohne Provider
$m->TestRing();
assert($m->GetValue('Ringing') === true);
$calls = json_decode($m->ReadAttributeString('Calls'), true);
foreach ($calls as $id => $c) {
    $calls[$id]['started'] = time() - 6;
    $calls[$id]['ended'] = ($calls[$id]['ended'] ?? time()) - 40;
}
$m->WriteAttributeString('Calls', json_encode($calls));
$m->CheckCalls();
assert($m->GetValue('Ringing') === false);
$m->CheckCalls();

// Dialog: Ablehnen
packet($m, invite('d1', '<sip:100@p>'));
$m->RequestAction('Reject', true);
assert($m->GetValue('Ringing') === false && str_starts_with(lastRaw($m), 'SIP/2.0 603 Decline'));
packet($m, invite('d1', '<sip:100@p>'));
assert(str_starts_with(lastRaw($m), 'SIP/2.0 603'), 'Wiederholung bekommt dieselbe Antwort');
$count = count($m->sent);
$m->RequestAction('Reject', true);
assert(count($m->sent) === $count, 'zweiter Klick in einer anderen Visualisierung sendet nichts');

// Dialog: Annehmen ohne Ziel tut nichts, die Kachel zeigt den Knopf dann nicht
packet($m, invite('d2', '<sip:100@p>'));
$m->RequestAction('Accept', true);
assert($m->GetValue('Ringing') === true);

// Annehmen leitet weiter, auch bei wiederholtem INVITE
$m->SetProperty('AnswerTarget', '100');
$m->RequestAction('Accept', true);
assert($m->GetValue('Ringing') === false);
assert(str_starts_with(lastRaw($m), 'SIP/2.0 302 Moved') && headerOf(lastRaw($m), 'Contact') === '<sip:100@sip.example.test>');
packet($m, invite('d2', '<sip:100@p>'));
assert(str_starts_with(lastRaw($m), 'SIP/2.0 302') && headerOf(lastRaw($m), 'Contact') === '<sip:100@sip.example.test>');

// Ziel: fertige SIP-Adresse bleibt, Header-Einschleusung wird abgewiesen
$uri = new ReflectionMethod(SIPKlingel::class, 'answerUri');
$m->SetProperty('AnswerTarget', 'sip:a@b.test');
assert($uri->invoke($m) === 'sip:a@b.test');
$m->SetProperty('AnswerTarget', "100\r\nX: y");
assert($uri->invoke($m) === '');
$m->SetProperty('AnswerTarget', '');

// Mikrofon-Test landet gekuerzt im Log und sendet nichts
$count = count($m->sent);
$m->RequestAction('MicTest', 'Mikrofon geht');
assert(count($m->sent) === $count);

// Testanruf endet ohne Paket
$m->TestRing();
$count = count($m->sent);
$m->RequestAction('Reject', true);
assert($m->GetValue('Ringing') === false && count($m->sent) === $count);

// OPTIONS und Keepalive stoeren nicht
packet($m, "OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.7;branch=z\r\nFrom: <sip:a@p>;tag=a\r\nTo: <sip:me@p>\r\nCall-ID: o\r\nCSeq: 1 OPTIONS\r\n\r\n");
assert(str_starts_with(lastRaw($m), 'SIP/2.0 200'));
packet($m, "\r\n\r\n");

// Ohne Zugangsdaten: inaktiv, keine Timer
$idle = module('', 5060, '', '');
assert($idle->status === 104 && $idle->sent === [] && $idle->timers['SIPKRegister'] === 0);
assert(json_decode($idle->GetConfigurationForParent(), true)['Open'] === false);

// Parent-Konfiguration
$parent = json_decode($m->GetConfigurationForParent(), true);
assert($parent['Host'] === 'sip.example.test' && $parent['BindPort'] === 5070 && $parent['Open'] === true);

echo "OK\n";
