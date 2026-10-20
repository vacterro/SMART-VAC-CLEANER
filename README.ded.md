# Smart VAC Cleaner

**v2.6.10**

![Version](https://img.shields.io/badge/version-2.6.10-F0D060?style=flat-square)

[English](README.md) · [Русский](README.ru.md) · [Eesti](README.et.md) · [Дед](README.ded.md)

![Smart VAC Cleaner GUI](assets/screenshot.png)

Нормальная чистилка без мусора, портативная. GUI, CLI, планировщик. 

По дефолту — dry-run, пока не впишешь `--delete`. Чекает только те диски, что реально есть, сносит только известную срань. Нет диска — молча идёт дальше, без истерик.

## Че чистим

| Слой | Что именно | Где |
|---|---|---|
| Система | Темпы, дампы, кэш апдейтов винды, DNS, корзина, кэши прог (больше 100 таргетов: браузеры, нода/pip, VS Code, OBS, Дискорд...) | `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%` |
| Глубокая срань (C:) | Ошмётки апдейтеров, `*.exe.tmp`, кэш вайбера, бекапы яндекса, логи ODIS | `%LOCALAPPDATA%`, `%TEMP%` |
| Портабельные | Известный мусор внутри твоих папок с портабельным софтом | `portable_roots` в конфиге |
| Свои правила | Твои личные папки + маски файлов | `custom_rules` в конфиге |

## Защита (чтоб не отстрелить ногу)

- **Dry-run по дефолту** — в GUI жмешь "Снести нахер" (спросит подтверждение), в консоли нужен флаг `--delete`.
- **Запретки**: `C:\`, `C:\Windows`, `USERPROFILE`, Program Files, папка самого скрипта — юзерский корень (portable/custom) не может быть запрещённым путём или его подкаталогом; внутренние проверенные системные цели имеют свою явную область и сидят внутри своего корня SafetyGuard.
- **Минимальная глубина**: короткие пути (меньше 5 уровней) шлём лесом.
- **Живые процессы**: если прога сейчас открыта — её кэш не трогаем.
- **Симлинки идут лесом**; `..` канонизируется, итоговый путь сидит внутри своего корня и перепроверяется — наружу не выпустим.
- **Никогда не сносим**: `login data`, `bookmarks`, `cookies`, `database` и т.д.
- **Исключения**: `exclude_patterns` / `exclude_paths` в конфиге.
- **Бэкапы**: обычные `.bak`-файлы отката (типа `app.asar.bak`) автоматом не трогаем.
- Всё идёт через `SafetyGuard`; ошибки считаем, но не падаем.

## Че надо

- Windows 10/11
- Python 3.10+

## Установка

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Или пакетом (появится команда `vac-cleaner`):

```bat
pip install .
vac-cleaner --status
```

Нет питона? Качай `SmartVACCleaner.exe` из [Releases](https://github.com/vacterro/SMART-VAC-CLEANER/releases) — портативная сборка, конфиг и логи будут рядом.

## Собрать exe самому

```bat
powershell -ExecutionPolicy Bypass -File build_exe.ps1
```

Выплюнет `dist\SmartVACCleaner.exe` (PyInstaller). На каждом теге `v*` CI сама собирает exe-шник.

## GUI

```bat
python _SMART_VAC_CLEANER.py
```

Семь кнопок: **Снести нахер** (снесёт реально — сначала спросит), **Тормози**, **Глянь сперва** (полностью read-only, покажет, что снесёт), **Вшить автозапуск**, **В фон** (запустит тихую зачистку без окон), **Не трогать** (твои исключения) и **Системные цели** (включить рискованное — Корзину, кэш DNS, кэш Windows Update; выбор помнится в конфиге). Прогресс-бары, логи. Все запуски пишутся в `logs\clean_*.log`.

## Консоль (CLI)

В консоли **dry-run по дефолту** — просто покажет, сколько говна нашлось.
Добавь `--delete`, если реально хочешь снести. `--dry-run` перебивает `--delete` и заставляет просто показать.

| Флаг | Чё делает |
|---|---|
| `--cli` | Железно консольный режим |
| `--portable` / `--system` / `--custom` | Выбор слоёв (по дефолту просто покажет) |
| `--all` | Все слои разом |
| `--delete` | **УДАЛЯЕТ** (без этого просто покажет) |
| `--dry-run` | Перебивает delete, тупо превью |
| `--status` | Показывает сколько мусора лежит; ничего не удаляет |
| `--analyze-caches` | Ищет кэши в AppData тяжелее 5 МБ |
| `--sys-targets` | Переопределить системные таргеты через запятую |
| `--exclude` | Доп исключения (`--exclude "*.db,*.tmp"`) |
| `--hidden` | Прячет консоль (для планировщика) |
| `--install-task` | Вшивает тихую чистку в планировщик |
| `--time HH:MM` | Во сколько запускать (дефолт `09:00`) |

Примеры:

```bat
REM показать всё
python _SMART_VAC_CLEANER.py --cli --all

REM снести всё
python _SMART_VAC_CLEANER.py --cli --all --delete

REM сунул оба флага - отработает как превью
python _SMART_VAC_CLEANER.py --cli --all --delete --dry-run
```

Глянуть че там скопилось:

```bat
python _SMART_VAC_CLEANER.py --status
```

### Авто-чистка (Планировщик)

```bat
python _SMART_VAC_CLEANER.py --install-task --time 09:00
```

Вшивает задачу `SmartVACCleaner` (высшие права, скрыто). Снести задачу:

```bat
python _SMART_VAC_CLEANER.py --uninstall-task
```

Сносит и базовую `SmartVACCleaner`, и юзерскую `SmartVACCleaner_<USERNAME>`, если такая встала.

## Конфиг

`cleaner_config.json` создаётся с дефолтами, когда поднимается GUI или впервые идёт реальное удаление. Исходники и портативный exe держат его рядом с приложением; поставленный wheel пишет в `%LOCALAPPDATA%\SmartVACCleaner` (`SMARTVAC_DATA_DIR` перебивает путь). Read-only превью и `--status` отсутствующий конфиг не создают. Логи запусков — `logs\clean_YYYYMMDD_HHMMSS.log` там же, последние 14 штук. Все пути нормализуются: слеши, `..`, защитные блеклисты (C:\, Windows, профиль) — всё проверяется. Пример:

```json
{
  "portable_roots": [],
  "custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}],
  "exclude_patterns": ["*.db"],
  "exclude_paths": ["C:\\Users\\me\\AppData\\Local\\Important"],
  "auto_clean_interval_hours": 0,
  "lang": "en",
  "window_geometry": "",
  "system_targets": {}
}
```

- `portable_roots`: папки, внутри которых ищем мусорные шаблоны (Cache, Temp, Logs). Остальное не трогаем.
- `custom_rules`: `path` (папка) + `pattern` (маска, `*` = всё).
- `exclude_patterns` / `exclude_paths`: что не трогать.
- `auto_clean_interval_hours`: автопереуборка GUI, `0` = off.
- `lang`: язык — `en` (дефолт), `ru`, `et`, `ded`. Файлики `strings/*.json` лежат рядом (или вшиты в exe). Кинь свой `<lang>.json`, чтоб добавить.
- `system_targets`: галочки диалога System Targets; `window_geometry`: последний размер/место окна.

## Тесты

```bat
python -m pytest -q
```

Пашут в офлайне, срут только во временные папки.

## Доки

Все мануалы в [docs/](docs/Home.md): [Safety](docs/Safety.md), [CLI Reference](docs/CLI-Reference.md), [Configuration](docs/Configuration.md), [Build & Install](docs/Build-and-Install.md), [FAQ](docs/FAQ.md).

## Важно

- Для планировщика нужны права админа (`/rl HIGHEST`).
- Портабельные папки на других дисках чистятся и без админа (схема VAC).
- Утилита не от вендоров; пути собраны руками, проги сами их пересоздадут.
<!-- source-digest: README.md sha256:985cd37683a869ea119a10cc0d142a330462d1ffda197a8fafe0590fdec2d019 -->
