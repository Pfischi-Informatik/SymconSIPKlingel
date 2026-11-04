<?php

declare(strict_types=1);

/**
 * SIP Klingel - IP-Symcon Modul
 * -----------------------------
 * Meldet sich per SIP (UDP) beim Provider an und meldet eingehende Anrufe:
 * Variable "Klingelt", Anrufer und Klingelton auf der Kachel. Der Anruf wird
 * nie angenommen, deshalb gibt es weder Audio noch WebRTC und die Meldung
 * kommt ohne Umweg direkt aus dem UDP-Paket.
 *
 * Protokoll: RFC 3261 (SIP), RFC 7616/2617 (Digest), RFC 3581 (rport).
 */
class SIPKlingel extends IPSModule
{
    private const UDP_SOCKET = '{82347F20-F541-41E1-AC5B-A636FD3AE2D8}';
    private const UDP_TX = '{8E4D9B23-E0F2-1E05-41D8-C21EA53B8706}';

    private const EXPIRES = 300;        // gewuenschte Anmeldedauer (Sekunden)
    private const RETRY_MS = 4000;      // Antwort auf REGISTER ausgeblieben
    private const RETRY_DOWN_MS = 30000; // Provider gilt als nicht erreichbar
    private const RETRY_DENIED_MS = 300000; // falsches Passwort, sonst droht Sperre beim Provider
    private const KEEPALIVE_MS = 25000; // haelt die UDP-Freigabe im Router offen
    private const RING_LIMIT = 120;     // Notbremse, falls das CANCEL verloren geht
    private const TEST_LIMIT = 5;
    private const ENDED_KEEP = 32;      // Wiederholungen beendeter Anrufe noch beantworten

    private const COMPACT = [
        'i' => 'call-id', 'f' => 'from', 't' => 'to', 'v' => 'via',
        'm' => 'contact', 'l' => 'content-length',
    ];

    // =====================================================================
    // Lebenszyklus
    // =====================================================================

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyString('Provider', '');
        $this->RegisterPropertyInteger('Port', 5060);
        $this->RegisterPropertyString('Username', '');
        $this->RegisterPropertyString('Password', '');
        $this->RegisterPropertyString('AuthID', '');
        $this->RegisterPropertyInteger('LocalPort', 5070);

        $this->RegisterAttributeString('CallID', '');
        $this->RegisterAttributeString('Tag', '');
        $this->RegisterAttributeString('Token', '');
        $this->RegisterAttributeInteger('CSeq', 0);
        $this->RegisterAttributeInteger('Expires', self::EXPIRES);
        $this->RegisterAttributeInteger('Fails', 0);
        $this->RegisterAttributeBoolean('AuthSent', false);
        $this->RegisterAttributeString('PublicAddress', '');
        $this->RegisterAttributeString('ProviderIPs', '[]');
        $this->RegisterAttributeString('Calls', '{}');

        $this->RegisterTimer('SIPKRegister', 0, 'SIPK_Register($_IPS[\'TARGET\']);');
        $this->RegisterTimer('SIPKKeepalive', 0, 'SIPK_Keepalive($_IPS[\'TARGET\']);');
        $this->RegisterTimer('SIPKCalls', 0, 'SIPK_CheckCalls($_IPS[\'TARGET\']);');

        $this->ForceParent(self::UDP_SOCKET);
        $this->SetVisualizationType(1);
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        if (!IPS_VariableProfileExists('SIPK.Ringing')) {
            IPS_CreateVariableProfile('SIPK.Ringing', VARIABLETYPE_BOOLEAN);
            IPS_SetVariableProfileIcon('SIPK.Ringing', 'Bell');
            IPS_SetVariableProfileAssociation('SIPK.Ringing', 0, 'Ruhe', '', -1);
            IPS_SetVariableProfileAssociation('SIPK.Ringing', 1, 'Klingelt', '', 0xFF0000);
        }

        $this->RegisterVariableBoolean('Ringing', $this->Translate('Klingelt'), 'SIPK.Ringing', 1);
        $this->RegisterVariableString('Caller', $this->Translate('Anrufer'), '', 2);
        $this->RegisterVariableInteger('LastCall', $this->Translate('Letzter Anruf'), '~UnixTimestamp', 3);
        $this->RegisterVariableBoolean('Registered', $this->Translate('Angemeldet'), '~Switch', 4);

        foreach (['CallID', 'Tag', 'Token'] as $name) {
            if ($this->ReadAttributeString($name) === '') {
                $this->WriteAttributeString($name, bin2hex(random_bytes(12)));
            }
        }
        $this->WriteAttributeInteger('Fails', 0);
        $this->WriteAttributeInteger('Expires', self::EXPIRES);
        $this->WriteAttributeString('PublicAddress', '');
        $this->WriteAttributeString('ProviderIPs', '[]');
        $this->WriteAttributeString('Calls', '{}');
        $this->SetValue('Ringing', false);
        $this->SetTimerInterval('SIPKCalls', 0);

        if (!$this->isConfigured()) {
            $this->SetValue('Registered', false);
            $this->SetTimerInterval('SIPKRegister', 0);
            $this->SetTimerInterval('SIPKKeepalive', 0);
            $this->SetStatus(104);
            return;
        }

        $this->SetTimerInterval('SIPKKeepalive', self::KEEPALIVE_MS);
        if (IPS_GetKernelRunlevel() === KR_READY) {
            $this->Register();
        } else {
            $this->SetTimerInterval('SIPKRegister', self::RETRY_MS);
        }
    }

    public function GetConfigurationForParent(): string
    {
        [$host, $port] = $this->isConfigured() ? $this->target() : ['', 0];
        return json_encode([
            'Host'     => $host,
            'Port'     => $port,
            'BindPort' => $this->ReadPropertyInteger('LocalPort'),
            'Open'     => $this->isConfigured(),
        ]);
    }

    public function GetVisualizationTile(): string
    {
        return file_get_contents(__DIR__ . '/module.html')
            . '<script>handleMessage(' . json_encode($this->tilePayload()) . ');</script>';
    }

    // =====================================================================
    // Oeffentliche Funktionen
    // =====================================================================

    public function Register(): bool
    {
        return $this->locked(function () {
            if (!$this->isConfigured()) {
                return false;
            }

            // Jeder Durchlauf zaehlt als offen, bis der Provider endgueltig antwortet
            $fails = $this->ReadAttributeInteger('Fails') + 1;
            $this->WriteAttributeInteger('Fails', $fails);
            if ($fails > 3) {
                $this->setRegistered(false, 202);
            }
            $this->SetTimerInterval('SIPKRegister', $fails > 3 ? self::RETRY_DOWN_MS : self::RETRY_MS);

            $this->WriteAttributeBoolean('AuthSent', false);
            return $this->sendRegister('');
        });
    }

    public function Keepalive(): void
    {
        $this->sendTo("\r\n\r\n");
    }

    public function CheckCalls(): void
    {
        $this->locked(function () {
            $calls = $this->calls();
            foreach ($calls as $id => $call) {
                $age = time() - $call['started'];
                if ($call['final'] === 0 && !empty($call['test']) && $age >= self::TEST_LIMIT) {
                    $calls[$id]['final'] = 487;
                    $calls[$id]['ended'] = time();
                } elseif ($call['final'] === 0 && empty($call['test']) && $age >= self::RING_LIMIT) {
                    $this->reply($call, $call['ip'], $call['port'], 480, 'Temporarily Unavailable');
                    $calls[$id]['final'] = 480;
                    $calls[$id]['ended'] = time();
                } elseif ($call['final'] !== 0 && time() - $call['ended'] >= self::ENDED_KEEP) {
                    unset($calls[$id]);
                }
            }
            $this->storeCalls($calls);
        });
    }

    public function TestRing(): void
    {
        $this->locked(function () {
            $calls = $this->calls();
            $calls['test-' . time()] = ['started' => time(), 'final' => 0, 'test' => true];
            $this->SetValue('Caller', 'Test');
            $this->storeCalls($calls);
        });
    }

    // =====================================================================
    // Empfang
    // =====================================================================

    public function ReceiveData($JSONString)
    {
        $data = json_decode($JSONString, true);
        $raw = mb_convert_encoding($data['Buffer'] ?? '', 'ISO-8859-1', 'UTF-8');
        if (trim($raw) === '') {
            return '';
        }
        $this->SendDebug('RX ' . ($data['ClientIP'] ?? ''), $raw, 0);

        $msg = $this->parse($raw);
        if ($msg === null) {
            return '';
        }

        $this->locked(function () use ($msg, $data) {
            $ip = (string) ($data['ClientIP'] ?? '');
            $port = (int) ($data['ClientPort'] ?? 0);
            if (isset($msg['status'])) {
                $this->handleResponse($msg, $ip);
            } else {
                $this->handleRequest($msg, $ip, $port);
            }
        });
        return '';
    }

    // ---- Antworten auf unser REGISTER -----------------------------------

    private function handleResponse(array $msg, string $ip): void
    {
        $cseq = explode(' ', $this->header($msg, 'cseq'));
        if ($this->header($msg, 'call-id') !== $this->ReadAttributeString('CallID')
            || (int) $cseq[0] !== $this->ReadAttributeInteger('CSeq')
            || strtoupper($cseq[1] ?? '') !== 'REGISTER') {
            return;
        }

        $status = $msg['status'];
        if ($status < 200) {
            return;
        }
        $this->WriteAttributeInteger('Fails', 0);
        $this->rememberProvider($ip);
        $addressChanged = $this->learnPublicAddress($msg);

        if ($status === 401 || $status === 407) {
            $challenge = $this->pickChallenge($msg['headers'][$status === 401 ? 'www-authenticate' : 'proxy-authenticate'] ?? []);
            $stale = strtolower($challenge['stale'] ?? '') === 'true';
            if ($challenge === null || ($this->ReadAttributeBoolean('AuthSent') && !$stale)) {
                $this->fail(201, self::RETRY_DENIED_MS);
                return;
            }
            $this->WriteAttributeBoolean('AuthSent', true);
            $this->sendRegister($this->authHeader($status, $challenge));
            return;
        }

        if ($status === 423) {
            $min = (int) $this->header($msg, 'min-expires');
            if ($min > 0) {
                $this->WriteAttributeInteger('Expires', $min);
                $this->sendRegister('');
                return;
            }
        }

        if ($status >= 200 && $status < 300) {
            if ($addressChanged) {
                // Provider hat uns auf der privaten Adresse eingetragen: dort kaeme kein Anruf an
                $this->WriteAttributeBoolean('AuthSent', false);
                $this->sendRegister('');
                return;
            }
            $this->setRegistered(true, 102);
            $this->SetTimerInterval('SIPKRegister', max(30, (int) ($this->grantedExpires($msg) / 2)) * 1000);
            return;
        }

        $this->fail($status === 403 ? 201 : 203, self::RETRY_DOWN_MS);
    }

    private function fail(int $code, int $retryMs): void
    {
        $this->setRegistered(false, $code);
        $this->SetTimerInterval('SIPKRegister', $retryMs);
    }

    private function setRegistered(bool $on, int $status): void
    {
        $this->SetValue('Registered', $on);
        $this->SetStatus($status);
        $this->UpdateVisualizationValue(json_encode($this->tilePayload()));
    }

    private function grantedExpires(array $msg): int
    {
        if (preg_match('/;\s*expires=(\d+)/i', $this->header($msg, 'contact'), $m)) {
            return (int) $m[1];
        }
        $expires = $this->header($msg, 'expires');
        return $expires !== '' ? (int) $expires : $this->ReadAttributeInteger('Expires');
    }

    private function learnPublicAddress(array $msg): bool
    {
        $via = $this->header($msg, 'via');
        $hasIp = preg_match('/;\s*received=([0-9a-fA-F.:]+)/i', $via, $ip) === 1;
        $hasPort = preg_match('/;\s*rport=(\d+)/i', $via, $port) === 1;
        if (!$hasIp && !$hasPort) {
            return false;
        }
        [$localIp, $localPort] = explode(':', $this->contactAddress());
        $address = ($hasIp ? $ip[1] : $localIp) . ':' . ($hasPort ? $port[1] : $localPort);
        if ($address === $this->contactAddress()) {
            return false;
        }
        $this->WriteAttributeString('PublicAddress', $address);
        return true;
    }

    private function rememberProvider(string $ip): void
    {
        $ips = json_decode($this->ReadAttributeString('ProviderIPs'), true);
        if ($ip !== '' && !in_array($ip, $ips, true)) {
            $ips[] = $ip;
            $this->WriteAttributeString('ProviderIPs', json_encode(array_slice($ips, -8)));
        }
    }

    // ---- Anfragen vom Provider ------------------------------------------

    private function handleRequest(array $msg, string $ip, int $port): void
    {
        $id = $this->header($msg, 'call-id');
        $calls = $this->calls();
        $known = isset($calls[$id]);

        // SIP-Scanner aus dem Internet duerfen nicht klingeln: Anfragen muessen vom
        // Provider kommen oder die nur ihm bekannte Contact-Kennung enthalten.
        $trusted = $known
            || in_array($ip, json_decode($this->ReadAttributeString('ProviderIPs'), true), true)
            || strpos($msg['uri'], $this->ReadAttributeString('Token')) !== false;
        if (!$trusted) {
            $this->SendDebug('Verworfen', $msg['method'] . ' von ' . $ip, 0);
            return;
        }

        switch ($msg['method']) {
            case 'INVITE':
                if ($known) {
                    $call = $calls[$id];
                    if ($call['final'] === 0) {
                        $this->reply($call, $ip, $port, 180, 'Ringing');
                    } else {
                        $this->reply($call, $ip, $port, $call['final'], $call['final'] === 487 ? 'Request Terminated' : 'Temporarily Unavailable');
                    }
                    return;
                }
                $call = $this->dialog($msg) + ['started' => time(), 'final' => 0, 'ip' => $ip, 'port' => $port];
                $calls[$id] = $call;
                $this->reply($call, $ip, $port, 180, 'Ringing');
                $this->SetValue('Caller', $this->callerName($msg));
                $this->SetValue('LastCall', time());
                $this->storeCalls($calls);
                return;

            case 'CANCEL':
            case 'BYE':
                if (!$known) {
                    $this->reply($this->dialog($msg), $ip, $port, 481, 'Call/Transaction Does Not Exist');
                    return;
                }
                $this->reply($this->dialog($msg), $ip, $port, 200, 'OK');
                if ($calls[$id]['final'] === 0) {
                    $this->reply($calls[$id], $ip, $port, 487, 'Request Terminated');
                    $calls[$id]['final'] = 487;
                    $calls[$id]['ended'] = time();
                    $this->storeCalls($calls);
                }
                return;

            case 'ACK':
                return;

            case 'OPTIONS':
            case 'NOTIFY':
                $this->reply($this->dialog($msg), $ip, $port, 200, 'OK');
                return;

            default:
                $this->reply($this->dialog($msg), $ip, $port, 501, 'Not Implemented');
        }
    }

    private function dialog(array $msg): array
    {
        return [
            'via'  => $msg['headers']['via'] ?? [],
            'from' => $this->header($msg, 'from'),
            'to'   => $this->header($msg, 'to'),
            'id'   => $this->header($msg, 'call-id'),
            'cseq' => $this->header($msg, 'cseq'),
        ];
    }

    private function reply(array $d, string $ip, int $port, int $code, string $reason): void
    {
        // Das To-Tag ist aus der Call-ID abgeleitet und damit bei Wiederholungen gleich
        $to = stripos($d['to'], ';tag=') === false ? $d['to'] . ';tag=' . substr(md5($d['id']), 0, 10) : $d['to'];

        $lines = ["SIP/2.0 $code $reason"];
        foreach ($d['via'] as $via) {
            $lines[] = "Via: $via";
        }
        array_push(
            $lines,
            "From: {$d['from']}",
            "To: $to",
            "Call-ID: {$d['id']}",
            "CSeq: {$d['cseq']}",
            'Contact: <' . $this->contactUri() . '>',
            'User-Agent: Symcon SIP Klingel',
            'Content-Length: 0'
        );
        $this->sendTo(implode("\r\n", $lines) . "\r\n\r\n", $ip, $port);
    }

    private function callerName(array $msg): string
    {
        $identity = $this->header($msg, 'p-asserted-identity') ?: $this->header($msg, 'from');
        if (!preg_match('/^\s*(?:"([^"]*)"|([^<"]*?))\s*<?(?:sips?|tel):([^@;>]*)/i', $identity, $m)) {
            return 'Unbekannt';
        }
        $name = trim($m[1] !== '' ? $m[1] : $m[2]);
        $number = $m[3];
        if ($number === '' || strcasecmp($number, 'anonymous') === 0) {
            return $name !== '' && strcasecmp($name, 'anonymous') !== 0 ? $name : 'Unbekannt';
        }
        return $name !== '' && $name !== $number ? "$name ($number)" : $number;
    }

    // =====================================================================
    // Senden
    // =====================================================================

    private function sendRegister(string $authHeader): bool
    {
        $cseq = $this->ReadAttributeInteger('CSeq') + 1;
        $this->WriteAttributeInteger('CSeq', $cseq);

        $domain = $this->ReadPropertyString('Provider');
        $aor = 'sip:' . $this->ReadPropertyString('Username') . '@' . $domain;
        $lines = [
            "REGISTER sip:$domain SIP/2.0",
            'Via: SIP/2.0/UDP ' . $this->contactAddress() . ';rport;branch=z9hG4bK' . bin2hex(random_bytes(8)),
            'Max-Forwards: 70',
            "From: <$aor>;tag=" . $this->ReadAttributeString('Tag'),
            "To: <$aor>",
            'Call-ID: ' . $this->ReadAttributeString('CallID'),
            "CSeq: $cseq REGISTER",
            'Contact: <' . $this->contactUri() . '>',
            'Expires: ' . $this->ReadAttributeInteger('Expires'),
            'Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY',
            'User-Agent: Symcon SIP Klingel',
        ];
        if ($authHeader !== '') {
            $lines[] = $authHeader;
        }
        $lines[] = 'Content-Length: 0';
        return $this->sendTo(implode("\r\n", $lines) . "\r\n\r\n");
    }

    private function sendTo(string $raw, string $ip = '', int $port = 0): bool
    {
        if (!$this->HasActiveParent()) {
            return false;
        }
        if (trim($raw) !== '') {
            $this->SendDebug('TX', preg_replace('/(response=")[^"]*/', '$1***', $raw), 0);
        }
        $this->SendDataToParent(json_encode([
            'DataID'     => self::UDP_TX,
            'Buffer'     => mb_convert_encoding($raw, 'UTF-8', 'ISO-8859-1'),
            'ClientIP'   => $ip,
            'ClientPort' => $port,
            'Broadcast'  => false,
        ]));
        return true;
    }

    private function contactUri(): string
    {
        return 'sip:' . $this->ReadAttributeString('Token') . '@' . $this->contactAddress();
    }

    private function contactAddress(): string
    {
        $public = $this->ReadAttributeString('PublicAddress');
        return $public !== '' ? $public : $this->localIp() . ':' . $this->ReadPropertyInteger('LocalPort');
    }

    private function localIp(): string
    {
        // UDP-connect sendet nichts, liefert aber die Adresse der richtigen Netzwerkkarte
        [$host, $port] = $this->target();
        $socket = @stream_socket_client("udp://$host:$port", $errno, $error, 1);
        $name = $socket ? stream_socket_get_name($socket, false) : false;
        return $name ? explode(':', $name)[0] : gethostbyname(gethostname());
    }

    private function target(): array
    {
        $host = $this->ReadPropertyString('Provider');
        $port = $this->ReadPropertyInteger('Port');
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host, $port ?: 5060];
        }
        if ($port > 0 && gethostbyname($host) !== $host) {
            return [$host, $port];
        }
        $records = @dns_get_record("_sip._udp.$host", DNS_SRV) ?: [];
        usort($records, fn ($a, $b) => $a['pri'] <=> $b['pri']);
        if ($records) {
            return [$records[0]['target'], $records[0]['port']];
        }
        return [$host, $port ?: 5060];
    }

    // =====================================================================
    // Digest-Anmeldung
    // =====================================================================

    private function pickChallenge(array $values): ?array
    {
        foreach ($values as $value) {
            preg_match_all('/(\w+)=(?:"([^"]*)"|([^,\s]+))/', $value, $matches, PREG_SET_ORDER);
            $challenge = [];
            foreach ($matches as $m) {
                $challenge[strtolower($m[1])] = $m[2] !== '' ? $m[2] : ($m[3] ?? '');
            }
            if (isset($challenge['nonce'], $challenge['realm'])
                && in_array(strtoupper($challenge['algorithm'] ?? 'MD5'), ['MD5', 'SHA-256'], true)) {
                return $challenge;
            }
        }
        return null;
    }

    private function digest(string $method, string $uri, string $user, string $password, array $c, string $cnonce, string $nc): string
    {
        $algo = strtoupper($c['algorithm'] ?? 'MD5') === 'SHA-256' ? 'sha256' : 'md5';
        $ha1 = hash($algo, "$user:{$c['realm']}:$password");
        $ha2 = hash($algo, "$method:$uri");
        if ($this->usesQop($c)) {
            return hash($algo, "$ha1:{$c['nonce']}:$nc:$cnonce:auth:$ha2");
        }
        return hash($algo, "$ha1:{$c['nonce']}:$ha2");
    }

    private function usesQop(array $c): bool
    {
        return in_array('auth', array_map('trim', explode(',', $c['qop'] ?? '')), true);
    }

    private function authHeader(int $status, array $c): string
    {
        $user = $this->ReadPropertyString('AuthID') ?: $this->ReadPropertyString('Username');
        $uri = 'sip:' . $this->ReadPropertyString('Provider');
        $cnonce = bin2hex(random_bytes(8));
        $nc = '00000001';
        $response = $this->digest('REGISTER', $uri, $user, $this->ReadPropertyString('Password'), $c, $cnonce, $nc);

        $header = ($status === 401 ? 'Authorization' : 'Proxy-Authorization')
            . ": Digest username=\"$user\", realm=\"{$c['realm']}\", nonce=\"{$c['nonce']}\", uri=\"$uri\", response=\"$response\"";
        if (isset($c['algorithm'])) {
            $header .= ", algorithm={$c['algorithm']}";
        }
        if (isset($c['opaque'])) {
            $header .= ", opaque=\"{$c['opaque']}\"";
        }
        if ($this->usesQop($c)) {
            $header .= ", qop=auth, nc=$nc, cnonce=\"$cnonce\"";
        }
        return $header;
    }

    // =====================================================================
    // Hilfsfunktionen
    // =====================================================================

    private function parse(string $raw): ?array
    {
        $head = explode("\r\n\r\n", str_replace("\n", "\r\n", str_replace("\r\n", "\n", $raw)), 2)[0];
        $head = preg_replace('/\r\n[ \t]+/', ' ', $head);
        $lines = explode("\r\n", $head);
        $first = array_shift($lines);

        if (preg_match('#^SIP/2\.0 (\d{3})#', $first, $m)) {
            $msg = ['status' => (int) $m[1]];
        } elseif (preg_match('#^([A-Z]+) (\S+) SIP/2\.0$#', $first, $m)) {
            $msg = ['method' => $m[1], 'uri' => $m[2]];
        } else {
            return null;
        }

        $msg['headers'] = [];
        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $name = strtolower(trim($parts[0]));
                $msg['headers'][self::COMPACT[$name] ?? $name][] = trim($parts[1]);
            }
        }
        return $msg;
    }

    private function header(array $msg, string $name): string
    {
        return $msg['headers'][$name][0] ?? '';
    }

    private function calls(): array
    {
        return json_decode($this->ReadAttributeString('Calls'), true);
    }

    private function storeCalls(array $calls): void
    {
        $this->WriteAttributeString('Calls', json_encode($calls));
        $this->SetTimerInterval('SIPKCalls', $calls ? 1000 : 0);

        $ringing = count(array_filter($calls, fn ($c) => $c['final'] === 0)) > 0;
        if ($ringing !== $this->GetValue('Ringing')) {
            $this->SetValue('Ringing', $ringing);
            $this->UpdateVisualizationValue(json_encode($this->tilePayload()));
        }
    }

    private function tilePayload(): array
    {
        return [
            'ringing'    => (bool) $this->GetValue('Ringing'),
            'caller'     => (string) $this->GetValue('Caller'),
            'registered' => (bool) $this->GetValue('Registered'),
        ];
    }

    private function isConfigured(): bool
    {
        return $this->ReadPropertyString('Provider') !== ''
            && $this->ReadPropertyString('Username') !== ''
            && $this->ReadPropertyString('Password') !== '';
    }

    // Timer und UDP-Empfang laufen in eigenen Threads
    private function locked(callable $work)
    {
        $name = 'SIPK_' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($name, 3000)) {
            return false;
        }
        try {
            return $work();
        } finally {
            IPS_SemaphoreLeave($name);
        }
    }
}
