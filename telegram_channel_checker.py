import asyncio
import os
import re
import urllib.parse
from telethon import TelegramClient
from telethon import connection
from telethon import errors
import sys
import logging

# Импортируем настройки из settings.py
from settings import CHANNELS, API_ID, API_HASH, CONFIG_FILE, WORKING_FILE, HTML_FILE

# 1. Глушим стандартный логгер Telethon
logging.getLogger('telethon').setLevel(logging.CRITICAL)

# 2. Перехватываем прямой вывод ошибок Telethon в консоль
class FilteredStderr:
    def __init__(self, original_stderr):
        self.original_stderr = original_stderr

    def write(self, message):
        # Если в сообщении есть технический спам от Telethon — просто игнорируем его
        if "Server closed the connection" in message or "bytes read on a total of" in message:
            return
        # Все остальные важные ошибки Python выводим как обычно
        self.original_stderr.write(message)

    def flush(self):
        self.original_stderr.flush()

# Подменяем системный вывод ошибок на наш фильтр
sys.stderr = FilteredStderr(sys.stderr)

# 3. Подавляем ошибки ConnectionResetError от asyncio проактатора на Windows
def _suppress_connection_reset():
    """Подавление фоновых ошибок подключения в asyncio"""
    import asyncio.proactor_events
    original_call = asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost
    
    def patched_call(self, exc):
        if exc and "ConnectionResetError" in str(type(exc)) or "WinError 10054" in str(exc):
            return
        try:
            original_call(self, exc)
        except ConnectionResetError:
            pass
    
    asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = patched_call

_suppress_connection_reset()

proxy_pool = []

# --- Регулярное выражение для валидации MTProto секретов ---
MT_SECRET_RE = re.compile(
    r"^(?:"
    r"(?:[dD][dD])?[0-9A-Fa-f]{32,256}"  # classic hex / dd-prefixed hex
    r"|"
    r"[eE][eE][A-Za-z0-9+/=_-]{8,512}"  # FakeTLS (ee + base64/base64url payload)
    r")$"
)


def _normalize_secret(value):
    """Нормализация секрета: удаление префикса 0x, обрезка пробелов"""
    if not value:
        return None
    cleaned = value.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


def _safe_int(value):
    """Безопасное преобразование строки в int"""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _looks_like_secret(value):
    """Проверка, похож ли строка на валидный MTProto секрет"""
    cleaned = value.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return bool(MT_SECRET_RE.fullmatch(cleaned))


def load_proxies_from_file(filename):
    """Загрузка прокси из файла с валидацией"""
    proxies = []
    if not os.path.exists(filename):
        return proxies
    
    with open(filename, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Пропускаем строки с метаданными (содержат |), если это не URL
            if "|" in line and "://" not in line:
                line = line.split("|")[0].strip()
            elif "|" in line:
                # Для URL берем первую часть до пробела или разделителя
                line = line.split()[0] if line.split() else line

            server_val, port_val, secret_val = None, None, None

            # 1. ТЕЛЕГРАМ ССЫЛКИ
            if "tg://proxy" in line.lower() or "t.me/proxy" in line.lower():
                parsed = urllib.parse.urlparse(line)
                params = urllib.parse.parse_qs(parsed.query)
                server_val = (params.get("server", [None])[0] or "").strip().rstrip(".")
                port_val = _safe_int(params.get("port", [None])[0])
                secret_val = _normalize_secret(params.get("secret", [None])[0])
                
            # 2. URL-СТИЛЬ
            elif "://" in line:
                parsed = urllib.parse.urlparse(line)
                server_val = (parsed.hostname or "").strip().rstrip(".")
                port_val = parsed.port
                secret_val = _normalize_secret(urllib.parse.parse_qs(parsed.query).get("secret", [None])[0])

            # 3. КЛАССИЧЕСКИЙ ФОРМАТ
            else:
                parts = [p.strip() for p in line.split(":")]
                if len(parts) >= 2:
                    server_val = parts[0].rstrip(".")
                    port_val = _safe_int(parts[1])
                    if len(parts) >= 3 and _looks_like_secret(parts[2]):
                        secret_val = _normalize_secret(parts[2])

            if not server_val or not port_val:
                continue
            if not (1 <= port_val <= 65535):
                continue
            if secret_val and not _looks_like_secret(secret_val):
                continue

            proxies.append({
                "server": server_val,
                "port": port_val,
                "secret": secret_val,
                "fails": 0
            })
    return proxies


def load_proxies_from_config():
    """Загрузка прокси из CONFIG_FILE и WORKING_FILE с удалением дубликатов"""
    proxies = []
    seen = set()
    for f in [CONFIG_FILE, WORKING_FILE]:
        for p in load_proxies_from_file(f):
            proxy_key = (p["server"].lower(), p["port"], p["secret"] or "")
            if proxy_key not in seen:
                seen.add(proxy_key)
                proxies.append(p)
    return proxies



def save_proxies_to_config():
    """Сохранение только живых прокси обратно в файл config.txt"""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        for p in proxy_pool:
            f.write(f"{p['server']}:{p['port']}:{p['secret']}\n")
    print(f"[*] Пул прокси сохранен в {CONFIG_FILE}")

def get_first_working_proxy():
    """Возвращает первый рабочий прокси для подключения самого клиента"""
    for p in proxy_pool:
        if p["fails"] < 3 and p.get("secret"):
            return (p["server"], p["port"], p["secret"])
    return None

async def parse_channels_via_telegram(tg_client):
    """Сбор MTProto-ссылок из постов и инлайн-кнопок (последние 50 сообщений)"""
    new_proxies = []
    for channel in CHANNELS:
        print(f"\n[*] Подключаемся к каналу: {channel}...")
        try:
            count = 0
            # Строгий лимит на 30 последних постов
            async for message in tg_client.iter_messages(channel, limit=50):
                count += 1
                found_links_in_post = []

                # 1. СБОР ИЗ ТЕКСТА (если он есть)
                if message.text:
                    found_links_in_post.extend(
                        re.findall(r'(?:tg://proxy\?|t\.me/proxy\?)[^\s"\'><]+', message.text)
                    )

                # 2. СБОР ИЗ ИНЛАЙН-КНОПОК (основной источник для вашего канала)
                if message.reply_markup and message.reply_markup.rows:
                    for row in message.reply_markup.rows:
                        for button in row.buttons:
                            # Проверяем, есть ли у кнопки URL-адрес
                            if hasattr(button, 'url') and button.url:
                                if "proxy?" in button.url:
                                    found_links_in_post.append(button.url)

                if found_links_in_post:
                    print(f"  [Пост {count}] Найдено прокси-ссылок: {len(found_links_in_post)}")

                                               # 3. ОБРАБОТКА И ВАЛИДАЦИЯ ВСЕХ НАЙДЕННЫХ ССЫЛОК
                for href in found_links_in_post:
                    if href.startswith("http://") or href.startswith("https://"):
                        href = "tg://" + href.split("t.me/")[-1] if "t.me/" in href else href
                        
                    parsed = urllib.parse.urlparse(href)
                    params = urllib.parse.parse_qs(parsed.query)
                    
                    if 'server' in params and 'port' in params and 'secret' in params:
                        try:
                            server_val = params['server'][0].strip().rstrip(".")
                            port_val = _safe_int(params['port'][0])
                            secret_val = _normalize_secret(params['secret'][0])
                            
                            # Валидация полей
                            if not server_val or not port_val:
                                continue
                            if not (1 <= port_val <= 65535):
                                continue
                            if secret_val and not _looks_like_secret(secret_val):
                                continue

                            new_proxies.append({
                                "server": server_val,
                                "port": port_val,
                                "secret": secret_val,
                                "fails": 0
                            })
                        except (IndexError, ValueError):
                            continue




                            
            print(f"[*] Канал {channel} обработан. Всего постов проверено: {count}")
        except Exception as e:
            print(f"[-] Ошибка чтения канала {channel}: {e}")
            
    return new_proxies


async def test_and_add_proxy(proxy_candidate, semaphore):
    """Проверка прокси-кандидата на работоспособность с улучшенной валидацией"""
    async with semaphore:  # Ограничение параллелизма
        # Проверка на дубликаты
        if any(p["server"].lower() == proxy_candidate["server"].lower() and 
               p["port"] == proxy_candidate["port"] for p in proxy_pool):
            return

        # Для MTProto секрета обязательны
        if not proxy_candidate.get("secret"):
            return
        if not _looks_like_secret(proxy_candidate["secret"]):
            return

        proxy_config = (proxy_candidate["server"], proxy_candidate["port"], proxy_candidate["secret"])
        test_client = TelegramClient(
            None, 
            API_ID, 
            API_HASH, 
            connection=connection.ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=proxy_config, 
            connection_retries=1, 
            timeout=5
        )

        try:
            await asyncio.wait_for(test_client.connect(), timeout=5.0)
            if test_client.is_connected():
                print(f"[+] НАЙДЕН ЖИВОЙ: {proxy_candidate['server']}:{proxy_candidate['port']}")
                proxy_pool.append(proxy_candidate)
        except Exception:
            pass
        finally:
            # Гарантированное корректное отключение
            try:
                await test_client.disconnect()
            except Exception:
                pass

def generate_html_page():
    """Генерация кликабельной веб-страницы"""
    html_content = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Мой Пул Живых MTProto Прокси</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; }
        h1 { color: #2481cc; font-size: 24px; margin-bottom: 5px; text-align: center; }
        .update-time { font-size: 13px; color: #666; margin-bottom: 20px; }
        .container { width: 100%; max-width: 500px; display: flex; flex-direction: column; gap: 12px; }
        .proxy-card { background: white; padding: 15px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; border-left: 5px solid #2481cc; }
        .info { display: flex; flex-direction: column; gap: 4px; }
        .ip { font-weight: bold; font-size: 16px; color: #222; }
        .port { font-size: 13px; color: #777; }
        .btn { background-color: #2481cc; color: white; text-decoration: none; padding: 8px 16px; border-radius: 8px; font-weight: bold; font-size: 14px; transition: background 0.2s; }
        .btn:hover { background-color: #1a66a6; }
        .no-proxies { text-align: center; color: #999; margin-top: 4px; }
    </style>
</head>
<body>
    <h1>Живые MTProto Прокси</h1>
    <div class="update-time">Список обновляется автоматически из файла конфигурации</div>
    <div class="container">
"""
    if not proxy_pool:
        html_content += '        <div class="no-proxies">Нет доступных прокси в пуле...</div>\n'
    else:
        for p in proxy_pool:
            tg_link = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"
            html_content += f"""        <div class="proxy-card">
            <div class="info">
                <span class="ip">{p['server']}</span>
                <span class="port">Порт: {p['port']}</span>
            </div>
            <a href="{tg_link}" class="btn">Подключить</a>
        </div>\n"""

    html_content += "</div></body></html>"
    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)

async def main_loop():
    global proxy_pool
    
    # 1. Загружаем прокси из сохраненного файла config.txt
    proxy_pool = load_proxies_from_config()
    
    if not proxy_pool:
        print("[-] Критическая ошибка: Файл config.txt пуст или отсутствует!")
        print("Пожалуйста, добавьте туда хотя бы один рабочий стартовый прокси.")
        return

    # 2. Умный перебор прокси из файла для первоначального подключения
    client = None
    for p in proxy_pool:
        print(f"[*] Пробуем подключиться к Telegram через: {p['server']}:{p['port']}...")
        try:
            proxy_config = (p['server'], p['port'], p['secret'])
            
            # Создаем клиент со встроенным пингом, чтобы сокет не засыпал
            client = TelegramClient(
                'my_account', 
                API_ID, 
                API_HASH, 
                connection=connection.ConnectionTcpMTProxyRandomizedIntermediate,
                proxy=proxy_config,
                device_model="PC 64bit",
                system_version="Windows 11",
                app_version="4.16.2 x64"
            )
            client.ping_delay = 60  # Пинговать сервер каждую минуту
            
            # Пытаемся подключиться с таймаутом 10 секунд
            await asyncio.wait_for(client.connect(), timeout=10.0)
            
            if client.is_connected():
                print(f"[+] Успешное подключение к серверам Telegram через {p['server']}!")
                break  # Рабочий прокси найден, выходим из цикла перебора
        except Exception:
            print("[-] Этот прокси не ответил. Пробуем следующий...")
            if client:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            p["fails"] += 3  # Штрафуем нерабочий прокси для удаления
            client = None
            continue

    # Если перебрали весь файл, но подключиться так и не смогли
    if not client or not client.is_connected():
        print("\n[-] КРИТИЧЕСКАЯ ОШИБКА: Ни один прокси из config.txt не смог подключиться к Telegram!")
        print("Пожалуйста, замените хотя бы один адрес в config.txt на свежий рабочий прокси вручную.")
        return

    # 3. Проверка авторизации учетной записи (сработает один раз, создаст сессию)
    if not await client.is_user_authorized():
        print("\n[!] Требуется авторизация. Вход по QR-коду:")
        qr_login = await client.qr_login()
        
        encoded_url = urllib.parse.quote(qr_login.url)
        web_qr_url = f"https://qrserver.com{encoded_url}"
        print(f"\nВариант А. Ссылка на QR-код для браузера:\n{web_qr_url}\n")
        
        print("Вариант Б. Отсканируйте код прямо из консоли:")
        import qrcode
        qr = qrcode.QRCode()
        qr.add_data(qr_login.url)
        qr.make(fit=True)
        qr.print_tty()
        
        print("\nИнструкция: Откройте Telegram на телефоне -> Настройки -> Устройства -> Подключить устройство.")
        print("Ожидание сканирования (у вас есть 2 минуты)...")
        
        try:
            await qr_login.wait(timeout=120)
            print("[+] Успешный вход по QR-коду!")
        except asyncio.TimeoutError:
            print("\n[-] Время ожидания истекло. Пожалуйста, запустите скрипт еще раз.")
            return
        except errors.rpcerrorlist.SessionPasswordNeededError:
            print("\n[!] На вашем аккаунте установлен Облачный пароль.")
            password = input("Пожалуйста, введите ваш Облачный пароль Telegram: ")
            await client.sign_in(password=password)
            print("[+] Пароль принят! Успешный вход.")

    print("[+] Сессия активна и сохранена.")
    
    # 4. Один цикл обновления пула (без бесконечного повторения)
    print("\n=== Круг обновления пула ===")
    candidates = await parse_channels_via_telegram(client)
    
    # Добавляем в кандидаты прокси из WORKING_FILE для повторной проверки
    working_file_candidates = load_proxies_from_file(WORKING_FILE)
    candidates.extend(working_file_candidates)
    
    # Удаляем прокси из WORKING_FILE из текущего пула, чтобы они были проверены заново
    # (test_and_add_proxy пропускает дубликаты, уже присутствующие в proxy_pool)
    if working_file_candidates:
        proxy_pool = [p for p in proxy_pool if not any(
            p["server"].lower() == c["server"].lower() and 
            p["port"] == c["port"]
            for c in working_file_candidates
        )]
        
    print(f"Найдено {len(candidates)} потенциальных адресов (включая {len(working_file_candidates)} из WORKING_FILE).")

    # Ограничиваем параллелизм до 5 одновременных подключений
    semaphore = asyncio.Semaphore(5)
    # Асинхронно тестируем всех кандидатов с ограничением
    tasks = [test_and_add_proxy(c, semaphore) for c in candidates]
    
    # Индикация прогресса тестирования
    total = len(tasks)
    completed = 0
    print(f"\n[*] Запускаем тестирование {total} кандидатов...")
    
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception:
            pass
        completed += 1
        if completed % 10 == 0 or completed == total:
            print(f"Протестировано кандидатов    {completed} из {total} ")

    # Очистка пула от устаревших (где fails >= 3)
    proxy_pool = [p for p in proxy_pool if p["fails"] < 3]

    # Записываем живые прокси в текстовый конфиг и в HTML
    save_proxies_to_config()
    generate_html_page()
    print(f"[+] Обновление завершено. Всего рабочих прокси в пуле: {len(proxy_pool)}")
    
    # Отключаемся от Telegram
    try:
        await client.disconnect()
    except Exception:
        pass

if __name__ == "__main__":
    import warnings
    # Подавляем предупреждения от asyncio на Windows
    warnings.filterwarnings('ignore', category=ResourceWarning)
    
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем")
    except Exception as e:
        print(f"\n[-] Критическая ошибка: {e}")
    finally:
        print("\nНажмите клавишу ввода для выхода...")
        input()


