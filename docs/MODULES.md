# Pisanie modułów ConWatch

Moduł to zwykły program w dowolnym języku. ConWatch uruchamia go przy starcie
i rozmawia z nim przez **stdin/stdout, jedna wiadomość JSON na linię**.

## Instalacja

Wrzuć katalog modułu do jednego z miejsc:

- `%LOCALAPPDATA%\ConWatch\modules\<nazwa>\` (Windows)
- `./modules/<nazwa>/` (katalog, z którego uruchamiasz `conwatch`)

Sprawdź: `conwatch modules`.

## Manifest `module.toml`

```toml
name = "moj-modul"
version = "0.1.0"
description = "Co robi"
command = "python"          # program do uruchomienia (w katalogu modułu)
args = ["main.py"]
permissions = ["events:read", "alerts:emit"]
```

| Uprawnienie | Znaczenie |
|---|---|
| `events:read` | moduł dostaje zdarzenia na stdin |
| `alerts:emit` | moduł może zgłaszać alerty |

Bez uprawnienia odpowiednia akcja jest po cichu ignorowana.

## Zdarzenia (stdin)

Każda linia to obiekt z polem `type`:

```json
{"type":"connection_opened","proto":"tcp","local_addr":"10.0.0.2","local_port":50000,"remote_addr":"1.2.3.4","remote_port":443,"pid":123,"process":"app.exe","exe":"C:\\app.exe"}
{"type":"connection_closed", ...}
{"type":"app_first_seen","process":"app.exe","exe":"C:\\app.exe"}
{"type":"traffic_sample","rx_bytes":1200,"tx_bytes":300,"interval_ms":1000}
{"type":"device_seen","ip":"192.168.1.20","mac":"aa:bb:cc:dd:ee:ff"}
{"type":"alert","level":"warning","source":"inny-modul","message":"..."}
```

## Akcje (stdout)

```json
{"action":"alert","level":"warning","message":"tekst"}   // level: info | warning | critical
{"action":"log","message":"debug"}                        // trafia na stderr ConWatch
```

Pamiętaj o `flush` po każdej linii. Przykład: [`modules/example-telnet-alert`](../modules/example-telnet-alert).

## Moduły wbudowane (Rust)

Implementują trait `conwatch_core::Module` (`name`, `on_event(&Event, &mut Context)`),
zob. `crates/conwatch-core/src/builtin.rs`.
