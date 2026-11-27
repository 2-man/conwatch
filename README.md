# ConWatch

Lekki, otwartoźródłowy monitor sieci dla Windows (macOS w planach), inspirowany
koncepcją narzędzi typu GlassWire: kto łączy się z siecią, dokąd i ile danych
wysyła. Modułowy – użytkownicy mogą pisać własne moduły.

> Status: **wczesny etap (v0.1)**. Działa monitor połączeń per proces w CLI.
> Pełny plan: [docs/PLAN.md](docs/PLAN.md).

## Wygląd i zakładki (v0.4)

Interfejs wzorowany na koncepcji GlassWire (własna implementacja, bez jego zasobów):
**Traffic** (wykres z zakresami 5 min – 30 dni, podział na aplikacje / hosty / typy ruchu / kraje, licznik, WAN vs LAN),
**Firewall** (tabela aplikacji z osobnym przełącznikiem In/Out, hosty, prędkości, wykres, wybór wielu aplikacji),
**Alerts** (log z grupowaniem po dniach, „NEW”, nieprzeczytane, filtr, szukanie),
**Network** (skaner LAN z producentami z bazy IEEE OUI, Scan i auto-scan),
**System** (CPU, pamięć, dysk) oraz **Settings** (motyw jasny/ciemny/auto, retencja, alerty, pobranie bazy krajów).
Widok **mapy świata** (kolor i kółka wg ruchu do kraju, przybliżanie, przesuwanie, podpowiedzi), **ikony aplikacji** pobierane z plików .exe (z awatarem jako zapasem) i **flagi krajów**.
Brak jeszcze: GPU w zakładce System, ikon aplikacji na macOS.

## Funkcje (v0.3)

- **Aplikacja desktopowa** (`conwatch-app`): natywne okno + ikona w zasobniku z prędkością na żywo; zamknięcie okna chowa je do zasobnika.
- **Ruch per aplikacja** (zakładka Usage): przez ETW, wymaga uruchomienia jako Administrator; bez tego panel działa, ale bez tej tabeli.
- **Panel w przeglądarce** (`conwatch serve --open`): wykres ruchu na żywo, zużycie dobowe/tygodniowe/miesięczne, aktywne połączenia per aplikacja, urządzenia w sieci (Things), alerty, firewall. Nasłuchuje wyłącznie na 127.0.0.1.
- **Alerty**: nowa aplikacja w sieci, nowe urządzenie w LAN, skok ruchu.
- **Firewall**: blokada aplikacji przez Zaporę Windows (wymaga uprawnień administratora).
- **Moduły użytkownika** w dowolnym języku – zob. [docs/MODULES.md](docs/MODULES.md).
- Historia w SQLite (`%LOCALAPPDATA%\ConWatch\conwatch.db`, retencja 90 dni).

- **Ustawienia** (motyw, retencja, próg alertu skoku, alerty o nowych aplikacjach), reverse DNS w zakładce Connections oraz opcjonalnie kraje (wrzuć `GeoLite2-Country.mmdb` do `%LOCALAPPDATA%\ConWatch`).
- **SDK modułów** w `sdk/` (Python, Node) i skrypt instalatora Inno Setup w `installer/`.

## Użycie

```powershell
cargo run --release -p conwatch-app                   # okno + tray
cargo run --release -p conwatch-cli -- serve --open   # panel w przeglądarce
cargo run -p conwatch-cli -- list                     # połączenia per proces
cargo run -p conwatch-cli -- watch [--json]           # strumień zdarzeń
cargo run -p conwatch-cli -- devices | modules | blocked
cargo run -p conwatch-cli -- block C:\Path\app.exe  # jako Administrator
```

## Moduły

Moduł to proces wymieniający zdarzenia JSON po stdio, opisany plikiem `module.toml`.
Przykład: [`modules/example-telnet-alert`](modules/example-telnet-alert).

## Dane i zasoby stron trzecich

- Mapa świata: [Natural Earth](https://www.naturalearthdata.com/) 110m (domena publiczna), wygenerowana skryptem `tools/make_assets.py`.
- Flagi: PNG z [flagcdn.com](https://flagcdn.com/) (wbudowane w program).
- Producenci urządzeń: publiczny rejestr IEEE OUI.
- Kraje hostów: baza [DB-IP Lite](https://db-ip.com/db/lite.php) (CC BY 4.0), pobierana wyłącznie na Twoje żądanie w Ustawieniach.

## Licencja

Apache License 2.0 – zob. [LICENSE](LICENSE). ConWatch nie jest powiązany z GlassWire.
