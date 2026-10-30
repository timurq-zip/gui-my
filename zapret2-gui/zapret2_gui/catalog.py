"""Каталог известных desync-функций и их параметров (по zapret-antidpi.lua / README zapret2).

Каталог нужен для подсказок в UI и для проверки синтаксиса. Если в системе найден каталог lua/ zapret2,
список ФУНКЦИЙ дополнительно считывается из реальных .lua-файлов (см. validator.discover_lua_functions),
так что новые функции апстрима не будут считаться ошибкой.
"""
from __future__ import annotations
from dataclasses import dataclass, field

BUILTIN_BLOBS = ["fake_default_tls", "fake_default_http", "fake_default_quic"]
POS_MARKERS = ["method", "host", "endhost", "sld", "midsld", "endsld", "sniext", "extlen"]
TLS_MODS = ["rnd", "rndsni", "dupsid", "padencap", "sni=", "padding"]
L7_KNOWN = ["http", "tls", "quic", "stun", "wireguard", "discord", "dht", "xmpp", "mtproto", "unknown"]
PAYLOAD_KNOWN = [
    "all", "known", "unknown", "empty", "http_req", "http_reply", "tls_client_hello", "tls_server_hello",
    "quic_initial", "wireguard_initiation", "wireguard_cookie", "wireguard_reply", "stun",
    "discord_ip_discovery", "dht", "xmpp_stream", "mtproto_initial",
]


@dataclass(frozen=True)
class Param:
    kind: str            # flag|int|sint|str|pos|blob|tlsmod|autottl|enum|payload
    help: str = ""
    lo: int | None = None
    hi: int | None = None
    choices: tuple[str, ...] = ()
    required: bool = False


@dataclass(frozen=True)
class Func:
    desc: str
    tcp: bool = True
    udp: bool = True
    params: dict[str, Param] = field(default_factory=dict)
    needs_lua: str = "zapret-antidpi.lua"


# Стандартные параметры (fooling, отправка, фильтры), общие для многих функций.
COMMON: dict[str, Param] = {
    "repeats": Param("int", "Сколько раз отправить фейк/сегмент.", 1, 100),
    "ip_ttl": Param("int", "TTL IPv4 для фейка (фейк должен «не дожить» до сервера).", 0, 255),
    "ip6_ttl": Param("int", "hop limit IPv6 (для IPv6 ttl отдельно!).", 0, 255),
    "ip_autottl": Param("autottl", "Авто-TTL IPv4: delta,min-max, например -2,3-20."),
    "ip6_autottl": Param("autottl", "Авто-TTL IPv6: delta,min-max."),
    "tcp_md5": Param("flag", "Fooling: добавить TCP MD5 option (сервер отбросит пакет)."),
    "badsum": Param("flag", "Fooling: испорченная контрольная сумма."),
    "tcp_ts_up": Param("flag", "Поднять TCP timestamp option на первое место."),
    "tcp_seq": Param("sint", "Сдвиг sequence number (например -10000)."),
    "tcp_ack": Param("sint", "Сдвиг ack number (например -66000)."),
    "tcp_ts": Param("sint", "Сдвиг TCP timestamp (например -1000)."),
    "tcp_flags_set": Param("str", "Установить TCP-флаги (например psh)."),
    "tcp_flags_unset": Param("str", "Снять TCP-флаги (например ack)."),
    "dir": Param("enum", "Направление, в котором работает инстанс.", choices=("in", "out", "any")),
    "payload": Param("payload", "Типы payload, на которые реагирует ЭТА функция (по умолчанию known)."),
}
FOOLING_KEYS = ["ip_ttl", "ip6_ttl", "ip_autottl", "ip6_autottl", "tcp_md5", "badsum", "tcp_ts_up",
                "tcp_seq", "tcp_ack", "tcp_ts", "tcp_flags_set", "tcp_flags_unset"]

_SPLIT = {
    "pos": Param("pos", "Позиции разреза: числа и маркеры (1,midsld,host+2,endhost-1)."),
    "seqovl": Param("int", "Перекрытие sequence (seqovl) в байтах.", 0, 1000000),
    "seqovl_pattern": Param("blob", "Чем заполнить seqovl: blob или 0xHEX."),
}
_FAKED = {
    "pos": Param("pos", "Один маркер разреза (например method+2 или midsld)."),
    "pattern": Param("blob", "Блоб-паттерн для фейковых сегментов."),
    "nofake1": Param("flag", "Не отправлять фейк №1."),
    "nofake2": Param("flag", "Не отправлять фейк №2."),
    "nofake3": Param("flag", "Не отправлять фейк №3."),
    "nofake4": Param("flag", "Не отправлять фейк №4."),
}

FUNCS: dict[str, Func] = {
    "fake": Func("Отправляет фейковый пакет (из блоба) перед настоящим. Основа почти любой стратегии.",
                 params={"blob": Param("blob", "Блоб-источник фейка: имя блоба, fake_default_* или 0xHEX.", required=True),
                         "tls_mod": Param("tlsmod", "Модификации TLS-фейка на лету: rnd,rndsni,dupsid,padencap,sni=<host>.")}),
    "multisplit": Func("Режет TCP-запрос на сегменты по позициям, шлёт по порядку.", udp=False, params=dict(_SPLIT)),
    "multidisorder": Func("Как multisplit, но сегменты уходят в обратном порядке.", udp=False, params=dict(_SPLIT)),
    "fakedsplit": Func("Разрез на 2 части с вмешиванием фейковых сегментов.", udp=False, params=dict(_FAKED)),
    "fakeddisorder": Func("fakedsplit с обратным порядком сегментов.", udp=False, params=dict(_FAKED)),
    "hostfakesplit": Func("Разрез по имени хоста с фейковым хостом.", udp=False,
                          params={"host": Param("str", "Подставляемое фейковое имя хоста."),
                                  "midhost": Param("pos", "Маркер разреза внутри хоста."),
                                  "blob": Param("blob", "Блоб, из которого берётся запрос."),
                                  "nofake1": Param("flag"), "nofake2": Param("flag")}),
    "tcpseg": Func("Отправляет диапазон payload одним TCP-сегментом (можно с seqovl). Оригинал не дропает.", udp=False,
                   params={"pos": Param("pos", "Диапазон из двух маркеров: 0,-1 = весь payload.", required=True),
                           "seqovl": Param("int", "seqovl в байтах.", 0, 1000000),
                           "seqovl_pattern": Param("blob")}),
    "oob": Func("Отправка байта urgent (OOB).", udp=False, params={}),
    "syndata": Func("Данные внутри SYN-пакета («нулевая фаза»).", udp=False,
                    params={"blob": Param("blob"), "tls_mod": Param("tlsmod")}),
    "wssize": Func("Подмена TCP window size/scale. Ставьте ПЕРЕД syndata/multisplit.", udp=False,
                   params={"wsize": Param("int", "Размер окна.", 0, 65535, required=True),
                           "scale": Param("int", "Window scale (0..14).", 0, 14)}),
    "pktmod": Func("Применить fooling/модификации к текущему пакету (без отправки новых).", params={}),
    "send": Func("Отправить текущий пакет с модификаторами (оригинал не дропается).", params={
        "ipfrag": Param("str", "Функция IP-фрагментации (по умолчанию ipfrag2).")}),
    "drop": Func("Дропнуть текущий пакет (вердикт DROP).", params={}),
    "luaexec": Func("Выполнить Lua-код на лету (для продвинутых).",
                    params={"code": Param("str", "Lua-код. Двоеточие ':' внутри кода ломает разбор параметров!", required=True)}),
    "http_methodeol": Func("HTTP: добавляет EOL перед методом.", udp=False, params={}),
    "udp2icmp": Func("Обфускация: UDP в ICMP (нужен zapret-obfs.lua).", tcp=False, needs_lua="zapret-obfs.lua",
                     params={"ccode": Param("int", "icmp code клиента", 0, 255), "scode": Param("int", "icmp code сервера", 0, 255),
                             "ctype": Param("int", "icmp type клиента", 0, 255), "stype": Param("int", "icmp type сервера", 0, 255)}),
}

STANDARD_L7_HELP = {
    "http": "HTTP (порт 80)", "tls": "TLS/HTTPS (порт 443)", "quic": "QUIC (UDP 443, HTTP/3)",
    "stun": "STUN (голосовые/видеозвонки)", "wireguard": "WireGuard", "discord": "Discord (UDP IP discovery)",
}
