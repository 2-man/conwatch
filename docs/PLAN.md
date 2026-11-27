# ConWatch – plan budowy

Open-source (Apache-2.0) monitor sieci w stylu GlassWire: lekki, przyjazny, modułowy.
Docelowo Windows + macOS (bez Linuksa). Na start: Windows.

## Założenia

| Obszar | Decyzja | Powód |
|---|---|---|
| Rdzeń | Rust | mały narzut RAM/CPU, jedna binarka, to samo na Win/macOS |
| UI | Tauri 2 + webview (HTML/TS, bez ciężkiego frameworka) | ~10 MB zamiast ~150 MB Electrona, natywny WebView2/WKWebView |
| Dane | SQLite (rusqlite, bundled) | historia ruchu, zapytania do wykresów |
| Moduły | proces zewnętrzny + manifest + JSON-lines po stdio | dowolny język, izolacja, prosty SDK |
| Licencja | Apache-2.0 | |

Warstwa platformowa jest za traitami (`platform::*`), więc port na macOS to
podmiana implementacji, nie przepisywanie.

## Funkcje GlassWire do odtworzenia

1. **Graph** – ruch w czasie (wysyłanie/pobieranie), podział na aplikacje, hosty, ruch/typ; zakresy czasu.
2. **Firewall** – lista aplikacji, blokowanie/zezwalanie per aplikacja, tryb „pytaj o nowe” (Windows Filtering Platform).
3. **Usage** – zużycie danych per aplikacja / host / kraj / dzień-tydzień-miesiąc; limity.
4. **Things** – urządzenia w sieci lokalnej (ARP/mDNS), wykrywanie nowych.
5. **Alerts** – nowa aplikacja łączy się, zmiana pliku aplikacji, skok ruchu, nowe urządzenie w LAN.
6. **Tray / widget** – ikona w zasobniku z bieżącą prędkością, mini-okno.
7. **Ustawienia** – motywy (jasny/ciemny), autostart, retencja danych.

## Architektura

```
conwatch/
  crates/
    conwatch-core/   zdarzenia, trait Module, Engine (bus), monitory, storage
    conwatch-cli/    interfejs tekstowy (testy, headless, debugowanie)
    conwatch-app/    (etap 3) Tauri: okno + tray
    conwatch-sdk/    (etap 5) biblioteka dla autorów modułów (Rust)
  ui/                (etap 3) front-end
  modules/           moduły wbudowane/przykładowe (manifest + kod)
  docs/
```

Przepływ: **monitory (platform) → Event bus → moduły → storage / UI / alerty**.

Zdarzenia (`Event`): `ConnectionOpened/Closed`, `TrafficSample`, `AppFirstSeen`,
`DeviceSeen`, `Alert`. Moduł dostaje strumień zdarzeń, może emitować własne
(np. alert) i rejestrować panel w UI.

### Model modułów

Katalog modułu:
```
modules/my-module/
  module.toml     # nazwa, wersja, uprawnienia, komenda startu, panel UI (opcjonalnie)
  ...             # dowolny kod (exe, python, node...)
```
Protokół: ConWatch uruchamia proces, wysyła zdarzenia jako JSON (1 linia = 1 wiadomość)
na stdin, odbiera akcje (`alert`, `log`, `panel_update`) ze stdout. Uprawnienia
deklarowane w manifeście (`events:read`, `alerts:emit`, `firewall:block`, `net:none`)
i potwierdzane przez użytkownika przy instalacji.
Wbudowane moduły w Rust implementują ten sam trait `Module` bez procesu.

## Etapy

- [x] **0. Szkielet** – repo, licencja, workspace, plan.
- [x] **1. Rdzeń + monitor połączeń (Windows)** – lista połączeń TCP/UDP z procesem, wykrywanie otwarcia/zamknięcia, event bus, trait `Module`, CLI `conwatch watch`.
- [~] **2. Przepustowość** – GOTOWE: ruch całkowity, SQLite, retencja. per aplikacja przez ETW (kod gotowy, wymaga admina – pomiar na żywo do potwierdzenia). ZOSTAJE: reverse DNS, kraj. Oryginalny opis: – ETW `Microsoft-Windows-Kernel-Network` (wymaga admina; usługa pomocnicza), agregacja do SQLite, rozwiązywanie hostów (reverse DNS), kraj (GeoLite/offline DB).
- [~] **3. UI** – GOTOWE: panel webowy (`conwatch serve`, lokalnie 127.0.0.1) z zakładkami. okno + tray (wry/tao/tray-icon, te same elementy co Tauri). autostart (`conwatch autostart on`). ZOSTAJE: motyw ręczny, ekran ustawień. Oryginalny opis: – okno z zakładkami Graph / Usage / Alerts, tray z prędkością, jasny/ciemny motyw.
- [~] **4. Firewall** – GOTOWE: blokada per aplikacja przez netsh (admin). ZOSTAJE: tryb pytania o nowe aplikacje, WFP. Oryginalny opis: – WFP: blokada per aplikacja, tryb pytania, profil.
- [x] **5. Moduły użytkownika** (loader, stdio, uprawnienia, przykład, docs; SDK – później): – loader manifestów, protokół stdio, uprawnienia, SDK + przykłady (Rust/Python/JS), katalog modułów.
- [x] **6. Things (LAN)** + alerty o nowych urządzeniach.
- [~] **7. macOS** – kod monitorów jest wieloplatformowy, CI buduje na macOS; brak firewalla: – implementacje `platform::*` (libproc/`nettop`/NetworkExtension), notarization, instalator.
- [~] **8. Wydania** – CI gotowe (build+test Win/macOS); release.yml buduje zipy na tag v*. ZOSTAJE instalator MSI/NSIS i podpisywanie: – CI GitHub Actions (build, testy, instalator MSI/NSIS), podpisywanie.

## Ryzyka

- Przepustowość per proces na Windows wymaga ETW (admin) – plan: osobna, mała usługa lub uruchamianie z podniesieniem uprawnień.
- Firewall (WFP) wymaga sterownika/usługi i uwagi na bezpieczeństwo; robimy po stabilnym monitoringu.
- macOS: per-app firewall wymaga Network Extension (płatny Apple Developer ID).
- Nie kopiujemy kodu, grafiki ani nazw GlassWire – tylko koncepcje funkcjonalne; własna identyfikacja wizualna.
