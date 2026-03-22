# DHCP Server (Вариант Б)

DHCP-ответчик на C с батчинговой обработкой через **RAW-сокет** (`AF_PACKET`) и REST API на Python (FastAPI) для управления маппингами MAC→IP через Redis.

---

## Стек технологий

| Компонент | Технология |
|-----------|-----------|
| DHCP-сервер | C, `AF_PACKET` RAW socket, `recvmmsg` |
| Хранилище | Redis 6.0+ (хеш `dhcp:mappings`) |
| Redis-клиент (C) | hiredis |
| REST API | Python 3.11+, FastAPI, redis-py |
| ОС | Linux (ядро 4.4+) |

---

## Структура проекта

```
.
├── api/
│   ├── restapi.py          # FastAPI REST API
│   ├── requirements.txt    # Python-зависимости
│   └── venv/               # Виртуальное окружение
└── dhcp_server/
    ├── dhcp_server.c       # Основной DHCP-сервер
    ├── dhcp_config.txt     # Конфигурационный файл
    └── dhcp_server         # Скомпилированный бинарник
```

---

## Конфигурационный файл

Файл `dhcp_server/dhcp_config.txt` в формате `ключ:значение`:
>Без лишних пробельных символов!

Пример:
```
subnet:192.168.100.0
netmask:255.255.255.0
lease_time:60
dns_servers:8.8.8.8,8.8.4.4
```

| Параметр | Описание |
|----------|----------|
| `subnet` | Адрес подсети |
| `netmask` | Маска подсети |
| `lease_time` | Время аренды адреса (секунды) |
| `dns_servers` | DNS-серверы через запятую (до 'MAX_DNS' штук) |

> Изменение конфига требует перезапуска сервера.

---

## Сборка и запуск

### Зависимости

```bash
# Ubuntu / Debian
sudo apt install gcc libhiredis-dev redis-server python3 python3-pip python3-venv
```

### DHCP-сервер (C)

```bash
cd dhcp_server

# Скомпилировать
gcc -o dhcp_server dhcp_server.c -lhiredis

# Запустить (требуются права root — RAW-сокет)
sudo ./dhcp_server
```

> **Важно:** в коде интерфейс задан константой `ETH_NAME "veth0"` (строка 19 `dhcp_server.c`). Перед запуском убедитесь, что интерфейс с таким именем существует, или измените значение на нужное

### Запуск Redis

```bash
sudo systemctl start redis
# проверить
redis-cli ping

#ожидаемый ответ - PONG
```

### REST API (Python)

```bash
cd api

# Создать окружение и установить зависимости
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Запустить (Redis должен быть запущен на localhost:6379)
uvicorn restapi:app --host 0.0.0.0 --port 8000
```

---

## REST API

Swagger UI доступен по адресу: `http://localhost:8000/docs`
| Запрос | Действие |
|--------|----------|
|POST /mappings | добавить новую пару (MAC, IP).|
|GET /mappings | получить все маппинги (или по MAC через query-параметр).|
|GET /mappings/{mac} | получить IP для конкретного MAC.|
|PUT /mappings/{mac} | обновить IP для указанного MAC.|
|DELETE /mappings/{mac} | удалить пару|
---

### Коды ответов

| Код | Значение |
|-----|----------|
| 200 | Успех |
| 409 | MAC уже существует (POST) |
| 404 | MAC не найден (GET/PUT/DELETE) |
| 422 | Ошибка валидации формата MAC или IP |

---

## Архитектура DHCP-сервера

### Приём пакетов ('packet_parser(), dhcp_receiver()')

Сервер использует **RAW-сокет** (`AF_PACKET, SOCK_RAW`) и системный вызов `recvmmsg` для пакетного приёма до 'VLEN' пакетов за раз. Для каждого пакета выполняется ручной разбор:

1. **Ethernet-заголовок** (14 байт) — пропускается
2. **IP-заголовок** — проверка версии (IPv4), протокола (UDP), адреса назначения
3. **UDP-заголовок** — проверка портов (src=68, dst=67)
4. **DHCP-payload** — извлечение MAC (`chaddr`), `xid`, типа сообщения (опция 53)

### Кольцевой буфер и батчинг

Принятые DHCP DISCOVER/REQUEST-запросы накапливаются в кольцевом буфере (`MAX_RING_BUF_SIZE'). Обработка батча запускается при:
- заполнении буфера до `RING_BUF_TRIGGER_COUNT`
- истечении таймаута `RING_BUF_TIMEOUT`
- заполнении буфера полностью

В рамках батча все запросы к Redis отправляются через **pipelining** (`redisAppendCommand` + `redisGetReply`)

### Формирование ответа

Для каждого MAC из батча, найденного в Redis, сервер:
- формирует DHCP OFFER (на DISCOVER) или DHCP ACK (на REQUEST) ('dhcp_sender()')
- заполняет Ethernet, IP и UDP заголовки вручную, считает IP checksum ('packet_formater()')
- отправляет ответ через тот же RAW-сокет с `sendto`
---

## Тестирование
### Виртуальная сеть для тестирования
1. **Создание veth пары**
```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

sudo ip addr add 192.168.100.1/24 dev veth0
```
Проверка
```bash
ip addr show veth0
# должен отображаться IP 192.168.100.1
ip link show veth1
# должен быть UP
```
2. **Запуск Redis и RESTAPI**
```bash
sudo systemctl start redis
cd dhcp_proj/api
source venv/bin/activate
uvicorn restapi:app --reload --host 0.0.0.0 --port 8000
```
3. **Добавить в Redis mac-адрес veth1**
```bash
ip link show veth1 | grep link/ether
# получить mac
```
-отправить POST запрос через SWAGGER

4. **Запуск**
   DHCP
```bash
cd dhcp_proj/dhcp_server
gcc -o dhcp_server dhcp_server.c -lhiredis
sudo ./dhcp_server
```
dhclient
```bash
#-v подробный вывод
sudo dhclient -v veth1
```
