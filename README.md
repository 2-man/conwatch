# ConWatch

Lekki, otwartoźródłowy monitor sieci dla Windows (macOS w planach), inspirowany
koncepcją narzędzi typu GlassWire: kto łączy się z siecią, dokąd i ile danych
wysyła. Modułowy – użytkownicy mogą pisać własne moduły.

> Status: **wczesny etap (v0.1)**. Działa monitor połączeń per proces w CLI.
> Pełny plan: [docs/PLAN.md](docs/PLAN.md).

## Użycie (CLI)

```powershell
cargo run -p conwatch-cli -- list          # bieżące połączenia TCP per proces
cargo run -p conwatch-cli -- watch         # strumień zdarzeń (otwarcie/zamknięcie, nowa aplikacja)
cargo run -p conwatch-cli -- watch --json  # to samo jako JSON lines
```

## Moduły

Wbudowane moduły implementują trait `Module` (`conwatch-core`). Moduły
użytkownika będą zewnętrznymi procesami wymieniającymi zdarzenia JSON po stdio
(w przygotowaniu – etap 5 planu).

## Licencja

Apache License 2.0 – zob. [LICENSE](LICENSE). ConWatch nie jest powiązany z GlassWire.
