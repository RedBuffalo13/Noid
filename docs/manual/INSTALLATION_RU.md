# Noid Messenger — Мануал по установке и настройке

## Требования

| Компонент | Минимум | Рекомендуется |
|-----------|---------|---------------|
| ОС | Windows 10+, Linux (glibc 2.31+), Android 10+ | Windows 11, Debian 12/Ubuntu 24.04, Android 12+ |
| ОЗУ | 1 ГБ | 2 ГБ |
| Диск | 200 МБ | 500 МБ |
| Инструменты | Rust stable, Node 20+, Tauri CLI | последний stable-тулчейн |

## Десктоп — из исходников

```bash
git clone <repo> && cd noid
npm install
npm run tauri dev          # разработка
npm run tauri build        # релизный бандл
cargo build --release --bin noid  # только бинарь → target/release/noid[.exe]
```

## VPS / headless-узел Linux

```bash
git clone <repo> /opt/noid && cd /opt/noid
npm install
cd src-tauri && cargo build --release --bin noid
# запуск (GUI-сессия :10 или виртуальный дисплей):
DISPLAY=:10 XAUTHORITY=/root/.Xauthority NOID_LOG=debug \
  nohup ./target/release/noid > /root/noid-app.log 2>&1 &
# firewall
ufw allow 4020/tcp && ufw allow 4021/tcp && ufw allow 4020/udp
```

Публичному узлу нужны порты **4020/tcp+udp** (QUIC/TCP) и **4021/tcp**
(WebSocket). Один процесс обслуживает релей, mailbox и DHT — **не**
запускайте отдельный релей-демон.

## Android

```bash
npm run tauri android init              # один раз — генерирует каркас gen/android
npm run tauri android build -- --apk    # APK в gen/android/app/build/outputs/apk/
adb install -r <apk-path>
```

**Обход для Windows (ошибка symlink).** `tauri android build` на Windows без
Developer Mode падает на шаге symlink `.so`. Рабочий обход:

```bash
# Rust-либа уже собрана предыдущим шагом — копируем вручную:
cp src-tauri/target/aarch64-linux-android/release/libnoid_lib.so    src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/
# дальше упаковываем APK напрямую через gradle (без таска rustBuild):
cd src-tauri/gen/android
ANDROID_HOME="$LOCALAPPDATA/Android/Sdk" JAVA_HOME="C:/Program Files/Android/Android Studio/jbr" ./gradlew.bat assembleArm64Release -x rustBuildArm64Release
# -> app/build/outputs/apk/arm64/release/app-arm64-release-unsigned.apk
```

Полные детали: `docs/ANDROID_BUILD.md` (версии SDK/NDK, заметки по FGS).

## Первый запуск

1. Запуск → задайте **TruePIN** (8–64 символа). По желанию задайте
   **KillPIN** — ввод его вместо PIN стирает все локальные данные.
2. После разблокировки нода стартует: листенеры и bootstrap-сиды
   соединяются автоматически. Добавляйте контакты инвайтом
   (`noid:<peerId>@<addr>`) или поиском по имени.
3. Отправка: при первом контакте приложение запрашивает подписанный
   prekey-бандл пира (прямой запрос, DHT как запасной путь), выполняет
   X3DH и шифрует Double Ratchet. Офлайн-пир получит конверт со своего
   mailbox-узла.

## Конфигурация

| Файл | Расположение | Назначение |
|------|--------------|------------|
| `relay_config.json` | каталог данных | роль (auto/relay/client), приватность, порты |
| `bootstrap_nodes.json` | каталог данных | дополнительные seed-узлы (встроенные — в бинаре) |
| `noid.db` | каталог данных | зашифрованное локальное хранилище |
| `noid.log` | каталог логов | UTC-логи с редактированием (`NOID_LOG=debug`) |

Роли релея: `auto` (релеит только при публичной достижимости),
`relay` (принудительный публичный узел), `client` (никогда не релеит).
Приватность: `direct` (по умолчанию) или `relayed_only` (скрывает ваш IP
от собеседников — релеи его всё равно видят).

## Обновление существующего узла

Замените бинарник и перезапустите приложение. База, ключи, контакты и
ratchet-сессии сохраняются. Не запускайте два экземпляра на одном
каталоге данных (single-instance блокировка всё равно откажет второму).
