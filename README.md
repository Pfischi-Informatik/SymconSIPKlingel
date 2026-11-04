# SIP Klingel

Symcon-Modul, das sich direkt beim SIP-Provider anmeldet und meldet, wenn jemand anruft. Der Anruf wird nicht angenommen: Der Anrufer hört das Freizeichen, bis er auflegt oder der Provider auf eine andere Rufnummer weiterleitet.

## Installation

Der Ordner `SymconSIPKlingel` gehört nach `/Library/Application Support/Symcon/modules/` (Linux/SymBox/Docker: `/var/lib/symcon/modules/`). Danach den Symcon-Dienst neu starten und die Instanz "SIP Klingel" anlegen. Den passenden UDP Socket erzeugt und konfiguriert das Modul selbst.

## Einstellungen

| Feld | Bedeutung |
|---|---|
| SIP-Provider | Domain des Providers, z.B. `sipgate.de` |
| Port | Normalerweise 5060, bei 0 wird der Server per DNS (SRV) gesucht |
| Benutzername, Passwort | SIP-Zugangsdaten des Anschlusses |
| Meldung an Visualisierungen | Liste, beliebig viele: Öffnet die Kachel beim Anruf in den offenen Visualisierungen und schickt einen Push aufs Handy |
| Anmeldename (Experten) | Nur eintragen, wenn der Provider einen abweichenden Namen verlangt |
| Lokaler UDP-Port (Experten) | Standard 5070, pro Instanz ein eigener Port |

## Variablen

| Ident | Typ | Inhalt |
|---|---|---|
| `Ringing` | Boolean | Klingelt gerade. Hier Ereignisse anhängen, um Gong, Licht oder Lautsprecher auszulösen |
| `Caller` | String | Name und Nummer des letzten Anrufers |
| `LastCall` | Integer | Zeitpunkt des letzten Anrufs |
| `Registered` | Boolean | Beim Provider angemeldet |

## Kachel

Die Kachel blinkt beim Anruf und zeigt den Anrufer. Browser geben Ton erst nach einem Klick frei: Die Kachel nach jedem Neuladen einmal antippen, sonst blinkt sie nur. Soll es zuverlässig hörbar klingeln, die Variable `Ringing` per Ereignis an einen Gong oder Lautsprecher koppeln.

Für die Meldung muss die Instanz in jeder gewählten Visualisierung sichtbar sein, sonst schlägt sie dort fehl (siehe Symcon-Log). Ist ein Gerät mehreren Visualisierungen zugeordnet, bekommt es pro Visualisierung einen Push. Push braucht ein aktives Symcon-Abo und ein dort registriertes Gerät; er läuft über Apple/Google und kann sich verzögern.

Das Modul nimmt Anrufe nicht an. Gesprochen wird über ein Telefon oder den Softphone-Client der Anlage.

## Funktionen

```php
SIPK_Register($id);   // sofort neu anmelden
SIPK_TestRing($id);   // 5 Sekunden Klingeln ohne echten Anruf
```

## Test

```bash
php -d zend.assertions=1 -d assert.exception=1 test/live.php
```

Mit echtem Konto, ohne Symcon. Der Port 5070 muss frei sein, und während des Tests darf die Symcon-Instanz nicht laufen:

```bash
SIP_HOST=provider SIP_USER=name SIP_PASS='passwort' SIP_WAIT=120 php -d zend.assertions=1 -d assert.exception=1 test/live.php
```

Während des Wartens die Nummer anrufen: Die Ausgabe zeigt `klingelt=true` und den Anrufer.

## Fehlersuche

| Status | Bedeutung | Vorgehen |
|---|---|---|
| Provider lehnt Zugangsdaten ab | Benutzername oder Passwort falsch | Korrigieren. Das Modul versucht es nur alle 5 Minuten, damit der Provider nicht sperrt |
| Provider antwortet nicht | Keine Antwort auf UDP | Provider und Port prüfen, im Router SIP-ALG ausschalten |
| Angemeldet, aber kein Klingeln | Router verwirft eingehende Pakete | SIP-ALG ausschalten, im Debug der Instanz nach `Verworfen` suchen |

Telefone oder Fritzbox am selben Anschluss klingeln nur weiter, wenn der Provider mehrere Anmeldungen gleichzeitig erlaubt. Sonst gewinnt die letzte Anmeldung.
