# ConWatch

Lekki, otwartoźródłowy monitor sieci dla Windows (macOS w planach), inspirowany
koncepcją narzędzi typu GlassWire: kto łączy się z siecią, dokąd i ile danych
wysyła. Modułowy – użytkownicy mogą pisać własne moduły.

> Status: **wczesny etap (v0.1)**. Działa monitor połączeń per proces w CLI.
> Pełny plan: [docs/PLAN.md](docs/PLAN.md).

## Funkcje (v0.2)

- **Panel w przeglądarce** (`conwatch serve --open`): wykres ruchu na żywo, zużycie dobowe/tygodniowe/miesięczne, aktywne połączenia per aplikacja, urządzenia w sieci (Things), alerty, firewall. Nasłuchuje wyłącznie na 127.0.0.1.
- **Alerty**: nowa aplikacja w sieci, nowe urządzenie w LAN, skok ruchu.
- **Firewall**: blokada aplikacji przez Zaporę Windows (wymaga uprawnień administratora).
- **Moduły użytkownika** w dowolnym języku – zob. [docs/MODULES.md](docs/MODULES.md).
- Historia w SQLite (`%LOCALAPPDATA%\ConWatch\conwatch.db`, retencja 90 dni).

## Użycie

```powershell
cargo run --release -p conwatch-cli -- serve --open   # panel
cargo run -p conwatch-cli -- list                     # połączenia per proces
cargo run -p conwatch-cli -- watch [--json]           # strumień zdarzeń
cargo run -p conwatch-cli -- devices | modules | blocked
cargo run -p conwatch-cli -- block C:\Path\app.exe  # jako Administrator
```

## Moduły

Moduł to proces wymieniający zdarzenia JSON po stdio, opisany plikiem `module.toml`.
Przykład: [`modules/example-telnet-alert`](modules/example-telnet-alert).

## Licencja

Apache License 2.0 – zob. [LICENSE](LICENSE). ConWatch nie jest powiązany z GlassWire.
