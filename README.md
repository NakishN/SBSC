# SBSC сканер читов

SBSC анализирует Minecraft-моды и ищет читы по коду, а не только по именам файлов. Поддерживаются JAR, ZIP, DLL, EXE и CLASS.

## Возможности

- Декомпиляция JAR через CFR и анализ Java-кода.
- Анализ байткода: классы, методы, вызовы, строки, Mixin.
- Детекторы читов: KillAura, Aimbot, HitBox, Reach, Velocity, Fly, NoFall, Scaffold, Nuker, ESP, XRay, AutoClicker, ChestStealer, Backtrack, Disabler, AntiAim, Timer, Phase, AutoTotem, AutoPot, CrystalAura, BedAura, AutoTrap, packet-exploit.
- Поиск AI-аима: ONNX, CatBoost, GRU, NeuroModel, rotation-predictor.
- Анализ DLL и EXE: PE-заголовки, импорты, экспорты, строки, энтропия, инъекции, хуки, JNI.
- Точные хеши известных образцов. При совпадении SHA-256 вердикт не зависит от имени файла.
- Сканирование папок, отдельных файлов и целых дисков.
- HTML и JSON отчеты.
- Сортировка таблицы по клику на заголовок колонки.
- Категории и вердикты в таблице на английском.
- Встроенная Java работает как скрытый SBSC-worker.exe. Одновременно запускается один worker, без отдельных окон.

## Требования

- Windows 10 или Windows 11, x64.
- Для исходной сборки нужен Go 1.22 или новее.
- Java устанавливать не нужно. JRE 8 и CFR уже входят в exe.

## Быстрый старт

1. Запустить `SBSC.exe`.
2. Перетащить JAR или DLL в окно.
3. Нажать `+ Папка` и выбрать папку модов, например `...\.minecraft\mods`.
4. Или нажать `+ Диск` и выбрать диски для полного сканирования.
5. Нажать `Сканировать`.

Первый глубокий скан может занять больше времени, потому что распаковывается встроенная Java.

Файлы отчетов по умолчанию находятся в `SBSC-data` рядом с exe. Если папка недоступна для записи, используется `%LOCALAPPDATA%\SBSC`.

## CLI

```bat
SBSC.exe --cli mods
SBSC.exe --cli "Wurst Client.jar" --html report.html --json report.json
SBSC.exe --cli mods --no-deep
SBSC.exe --cli mods --deep-all
SBSC.exe --cli "C:\Windows\System32" --include-system
SBSC.exe --cli libraries --scan-libraries
```

Флаги:

| Флаг | Значение |
|---|---|
| `--cli` | консольный режим |
| `--gui` | GUI с предзагрузкой файлов |
| `--no-deep` | без декомпиляции и анализа исходников |
| `--deep-all` | декомпилировать все jar, включая крупные |
| `--no-decompile` | не декомпилировать |
| `--no-native` | не анализировать DLL и EXE |
| `--all-dll` | анализировать DLL из белого списка |
| `--include-system` | сканировать Windows и Java runtime |
| `--scan-libraries` | сканировать обычные Java-библиотеки |
| `--all-files` | искать JAR/PE/class по сигнатуре даже с чужим расширением (медленнее на диске) |
| `--workers <n>` | сколько файлов анализировать параллельно, 0 — авто по CPU и RAM |
| `--out <dir>` | папка отчетов и исходников |
| `--java <path>` | своя Java, по умолчанию встроенная |
| `--max-mb <n>` | лимит размера файла, по умолчанию 512 МБ |
| `--max-files <n>` | лимит количества файлов, 0 означает без лимита |

## Вердикты

- `подтверждено`: точное совпадение SHA-256 или несколько независимых сильных находок в коде.
- `вероятно`: одна сильная находка в коде.
- `возможно`: только контекст или слабые эвристики.
- `недостаточно данных`: обфускация или упаковка, код не подтвердил.
- `чисто`: доказательств читов нет.

Вердикты в таблице:

- `ЧИСТО`.
- `ВОЗМОЖНЫ ЧИТЫ`.
- `ПОДОЗРИТЕЛЬНО`.
- `ЧИТ-КЛИЕНТ`.

Поле `Доказательство` показывает `файл:строка`, фрагмент кода и вес правила.

## Что анализируется

- JAR и ZIP: константный пул классов, ссылки, строки, Manifest, Fabric, Quilt, Forge и NeoForge metadata, Mixin-конфиги, вложенные jar, встроенные DLL.
- Декомпилированный Java: классы, методы, вызовы, циклы, присваивания, строки, аннотации `@Mixin`, `@Inject`, `@Redirect`.
- AI-аим: `*.onnx`, `*.cbm`, `neuro`-профили, `NeuroModel`, GRU и rotation-predictor.
- DLL и EXE: PE-заголовки, импорты, экспорты, строки, энтропия, Authenticode, инъекции, хуки, JNI, overlay, anti-debug.
- Известная база и каталог модулей используются как контекст и подсказки. Вердикт подтверждается кодом.

RAR напрямую не читается. Распакуйте архив и сканируйте JAR.

## Переименованные файлы

Расширению больше не нужно доверять. При сканировании папки SBSC проверяет первые байты файла и находит JAR/ZIP, DLL/EXE и CLASS даже с именем `config.dat`, `readme.txt` или `d3d9.dll` (если внутри JAR). Для полного диска этот режим включается флагом `--all-files`.

Библиотечный мод (`fabric-api`, `guava`, `kotlin` и т.п.) пропускается только по совокупности содержимого архива и метаданных, а не по одному имени файла. Переименованный чит вида `guava-client.jar` анализируется как обычный мод.

## Скорость

Файлы сканируются параллельно (`--workers`, по умолчанию до 8). Внутри одного большого JAR правила проверяются по классам с учетом литеральных подсказок, поэтому обычные классы библиотек не прогоняются через все регулярные выражения. Результаты декомпиляции кэшируются по SHA-256 и пути файла: повторный скан того же JAR заметно быстрее.

## Автоподстройка под компьютер

По умолчанию SBSC сам выбирает режим:

- число файловых воркеров — по количеству CPU и доступной RAM (4 ГБ доступно → 4 воркера, 2 ГБ → 2, 1 ГБ → 1);
- мягкий лимит памяти Go — около 55% RAM и не больше 70% доступной, с запасом под Windows и Java;
- большие JAR (от 64 МБ) обрабатываются не более чем по 1–2 одновременно;
- CFR получает 1 ГБ heap на нормальной машине и 512 МБ при RAM меньше 6 ГБ или доступной памяти меньше 2 ГБ;
- одновременно запускается не больше 2 CFR.

`--workers N` отключает автотюнинг воркеров. Переменная `GOMEMLIMIT` имеет приоритет над автоматическим лимитом памяти. Эффективные значения (`Авто: ...`) печатаются в CLI.

Сканер анализирует код модов. Исходный Go-код самого SBSC не сканируется.

## Скан диска

Кнопка `+ Диск` находит все локальные и съемные диски, а не только `C:\`.

- Проверяются только `.jar`, `.zip`, `.dll`, `.exe`, `.class`.
- Сначала обходятся `Downloads`, `Desktop`, `.minecraft`, `Users`, `home`, `Games`, затем остальное.
- При скане диска пропускаются `Windows`, `Program Files`, `ProgramData`, Java, JRE, JDK, кеши, `node_modules`, `.git` и служебные каталоги.
- Лимита по количеству файлов нет. При необходимости его можно задать через `--max-files`.
- Если чит лежит внутри `Program Files`, выберите эту папку вручную через `+ Папка`.

Полный скан диска может занять много времени. Для быстрого прохода снимите `Глубокий анализ кода` или используйте `--no-deep`.

## Сортировка

Сортировка выполняется кликом по заголовку колонки:

- `Файл`.
- `Вердикт`.
- `Риск`.
- `Категории`.
- `Модули`.
- `Тип`.
- `Размер`.
- `Время`.

Повторный клик меняет направление сортировки. Колонка `#` не сортируется.

## Категории

Категории в деталях и HTML-отчете:

- `Combat`.
- `Movement`.
- `World`.
- `Render`.
- `Player`.
- `Misc`.
- `Exploit`.
- `Client`.
- `Hitbox`.
- `Ghost`.
- `AutoBuy`.
- `Native`.
- `Obfuscation`.
- `Mixin`.
- `Utility`.
- `Trusted`.

## Wine

Если под Wine окно пустое или не перерисовывается, запустите через виртуальный рабочий стол:

```bash
cd dist
wine explorer /desktop=SBSC,1100x700 SBSC.exe
```

Для Wayland:

```bash
WAYLAND_DISPLAY= DISPLAY=:0 wine explorer /desktop=SBSC,1100x700 SBSC.exe
```

Причина обычно в полноэкранной игре в фоне или в Wayland. Закройте игру или переключите ее в оконный режим.

## Если не запускается

- Нужна 64-битная Windows 10 или 11. На 32-битной системе exe не стартует.
- SmartScreen: нажмите `Подробнее`, затем `Выполнить в любом случае`. Или откройте свойства exe и нажмите `Разблокировать`.
- Антивирус может удалить новый unsigned exe. Проверьте историю защиты и добавьте папку в исключения.
- Лог запуска: `%LOCALAPPDATA%\SBSC\startup.log`.
- Если лога нет, Windows или антивирус заблокировали процесс до запуска.
- GUI работает в одном экземпляре. Повторный запуск покажет сообщение, а не создаст второе окно.
- Закройте старые процессы `SBSC.exe` в диспетчере задач.

## Релизы

В релизе есть два варианта:

- `SBSC.exe` - один файл со встроенной JRE.
- `SBSC-lite.zip` - `SBSC-lite.exe` и папка `jre8` рядом. Exe меньше, антивирусные эвристики иногда срабатывают реже.

Контрольные суммы лежат в `SHA256SUMS.txt`.

## Проверка релиза

GitHub attestation, нужен gh 2.60 или новее:

```bash
gh attestation verify SBSC.exe --repo NakishN/SBSC
```

Модули Go внутри exe:

```bash
go version -m SBSC.exe
```

Контрольные суммы:

```bash
sha256sum -c SHA256SUMS.txt
```

Подпись кода сейчас отсутствует. Без сертификата Code Signing часть антивирусов может давать ложные срабатывания на неподписанный self-contained exe.

## Ложные срабатывания

Некоторые ML-движки антивирусов реагируют на большой неподписанный exe со встроенной JRE и строками для поиска инжекторов. Это не malware.

Что помогает:

- проверка исходников и сборка из них;
- `SBSC-lite.zip` без встроенной JRE;
- отправка файла вендору как false positive;
- Code Signing сертификат.

VirusTotal Reanalyze не заменяет обращение к вендору.

Куда отправить false positive:

- Microsoft: https://www.microsoft.com/en-us/wdsi/filesubmission
- Bkav: https://www.bkav.com/contact
- CrowdStrike: https://www.crowdstrike.com/contact-us/
- Cynet: https://www.cynet.com/contact-us/
- Elastic: https://www.elastic.co/contact

Текст обращения:

```text
This file is an open-source Minecraft cheat scanner. The detection is a false positive.
Source: https://github.com/NakishN/SBSC
Release: https://github.com/NakishN/SBSC/releases/tag/v1.0.2
Please whitelist the file or update the signature.
```

## Сборка

Нужен Go 1.22 или новее. Бинарные файлы CFR и JRE в репозиторий не входят.

```bash
mkdir -p assets/tools
curl -L -o assets/tools/cfr.jar https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar
curl -L -o assets/tools/jre8-win64.zip https://api.adoptium.net/v3/binary/latest/8/ga/windows/x64/jre/hotspot/normal/eclipse
```

Сборка Windows:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H windowsgui" -o dist/SBSC.exe ./cmd/sbsc
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/SBSC-CLI.exe ./cmd/sbsc
```

Linux-сборка для тестов:

```bash
go build -o sbsc ./cmd/sbsc
./sbsc --cli --no-deep /path/to/mods
```

## Проверка

```bash
gofmt -l .
go vet ./...
go test ./...
```

## Структура

```text
cmd/sbsc               CLI и GUI entrypoint
internal/engine        анализ JAR, class, PE, декомпиляция, скоринг
internal/ui            Windows GUI на walk
internal/applog        лог запуска
assets/rules           правила клиентов, модулей, поведения, native, known
assets/tools           cfr.jar и JRE для Windows, скачиваются при сборке
licenses               тексты лицензий сторонних компонентов
```

## Репозиторий

В git входят только исходники, правила, README, go.mod, go.sum и тексты лицензий.

Исключены через `.gitignore`:

- `dist` и готовые exe/zip;
- `corpus` с локальными тестовыми клиентами;
- `assets/tools` с CFR и JRE, они скачиваются при сборке;
- скрипты сборки, их в репозитории нет.

## Third-party components

- CFR, Java decompiler. MIT. Copyright 2011-2018 Lee Benfield. https://www.benf.org/other/cfr. Текст лицензии: `licenses/CFR-LICENSE.txt`.
- Eclipse Temurin JRE 8 Windows x64. GPLv2 with Classpath Exception. Copyright Eclipse Adoptium и OpenJDK contributors. https://adoptium.net. Тексты лицензий: `licenses/TEMURIN-JRE-LICENSE.txt`, `licenses/TEMURIN-ASSEMBLY-EXCEPTION.txt`, `licenses/TEMURIN-THIRD-PARTY-README.txt`.
- Go standard library и `golang.org/x/sys`. BSD-3-Clause. Copyright The Go Authors.
- `github.com/lxn/walk` и `github.com/lxn/win`. BSD-3-Clause. Copyright walk/win contributors.
- `github.com/Knetic/govaluate`. MIT. Используется через walk.

SBSC не связан с Mojang, Microsoft или AC-провайдерами. Код Minecraft не входит в сборку.

## Деобфускация

Полной деобфускации нет. Сканер не переименовывает классы обратно и не восстанавливает исходную структуру программы.

Что есть:

- декомпиляция CFR и анализ байткода;
- нормализация имен классов и методов, удаление служебных префиксов;
- поиск строк, вызовов, циклов, присваиваний и Mixin;
- детектор расшифровки строк и reflection;
- анализ AI-моделей и нативных DLL.

Чего нет:

- автоматической расшифровки строк;
- разворачивания control-flow;
- эмуляции class loader;
- динамического запуска sample.

Поэтому сильно обфусцированный чит без строк и характерных вызовов может дать только `ВОЗМОЖНЫ ЧИТЫ` или `недостаточно данных`. Для таких файлов нужен ручной разбор или запуск в изолированной VM.

## Ограничения

- Это статический анализатор, а не runtime-AC. Он не ловит читы, которые появляются только в памяти или после инжекта.
- Полностью обфусцированный чит без строк и характерных вызовов может дать только `ВОЗМОЖНЫ ЧИТЫ`.
- Нативные DLL анализируются по PE, импортам и строкам. Полная декомпиляция x86 не входит.
- Отчет рекомендательный. Решение о бане принимает человек.
# SBSC
