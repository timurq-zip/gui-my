"""Справочник desync-функций из zapret-antidpi.lua / zapret-lib.lua.
Используется для подсказок в UI и эвристической проверки. Список НЕ исчерпывающий:
неизвестная функция/параметр даёт предупреждение, а не ошибку (пользователь может писать свой Lua)."""
from dataclasses import dataclass, field


@dataclass
class P:
    name: str
    kind: str      # int | str | flag | blob | pos | ttl | autottl
    hint: str = ""


COMMON = [P("payload", "str", "known | all | tls_client_hello,http_req ... (на уровне инстанса)"),
          P("dir", "str", "in | out | any")]

FOOL = [
    P("ip_ttl", "int", "TTL фейка для IPv4, например 4"),
    P("ip6_ttl", "int", "TTL фейка для IPv6 (для v6 пишется отдельно!)"),
    P("ip_autottl", "autottl", "delta,min-max, например -2,3-20"),
    P("ip6_autottl", "autottl", "delta,min-max"),
    P("tcp_md5", "flag", "добавить TCP MD5SIG option (фулинг)"),
    P("tcp_seq", "int", "сдвиг seq, например -10000"),
    P("tcp_ack", "int", "сдвиг ack, например -66000"),
    P("tcp_ts", "int", "сдвиг TCP timestamp"),
    P("tcp_ts_up", "flag", "переместить timestamp в начало опций"),
    P("tcp_flags_set", "str", "например psh"),
    P("tcp_flags_unset", "str", "например ack"),
    P("badsum", "flag", "испортить контрольную сумму"),
]

SPLIT = [P("pos", "pos", "маркеры: 1,midsld | method+2 | host,endhost-1 | 0,-1"),
         P("seqovl", "int", "перекрытие seq, байт (или #blob)"),
         P("seqovl_pattern", "blob", "блоб-шаблон для seqovl")]


@dataclass
class FuncSpec:
    desc: str
    params: list = field(default_factory=list)


FUNCS = {
    "fake": FuncSpec("Отправляет поддельный пакет перед оригиналом (оригинал уходит дальше).",
                     [P("blob", "blob", "fake_default_tls | fake_default_http | fake_default_quic | 0xHEX | имя блоба"),
                      P("repeats", "int", "сколько раз отправить фейк, напр. 2..11"),
                      P("tls_mod", "str", "rnd,rndsni,dupsid,sni=www.google.com,padencap")] + FOOL),
    "multisplit": FuncSpec("Режет пейлоад в маркерах pos на несколько сегментов.", SPLIT + FOOL),
    "multidisorder": FuncSpec("Как multisplit, но отправляет сегменты в обратном порядке.", SPLIT + FOOL),
    "fakedsplit": FuncSpec("Сплит с фейковыми частями.",
                           [P("pos", "pos", "method+2"), P("pattern", "blob", "блоб для фейка"),
                            P("nofake1", "flag"), P("nofake2", "flag"), P("nofake3", "flag"), P("nofake4", "flag")] + FOOL),
    "fakeddisorder": FuncSpec("Disorder с фейковыми частями.",
                              [P("pos", "pos"), P("pattern", "blob"),
                               P("nofake1", "flag"), P("nofake2", "flag"), P("nofake3", "flag"), P("nofake4", "flag")] + FOOL),
    "hostfakesplit": FuncSpec("Сплит вокруг имени хоста с фейковым хостом.",
                              [P("host", "str", "подставное имя хоста"), P("midhost", "str"),
                               P("nofake1", "flag"), P("nofake2", "flag"), P("disorder_after", "str")] + FOOL),
    "tcpseg": FuncSpec("Отправляет один TCP-сегмент — часть пейлоада (pos=диапазон из двух маркеров). Оригинал НЕ дропает.",
                       SPLIT + FOOL),
    "oob": FuncSpec("Вставляет urgent/OOB байт.", [P("urp", "str", "позиция urgent pointer")] + FOOL),
    "udplen": FuncSpec("Меняет длину UDP-датаграммы.", [P("increment", "int"), P("pattern", "blob")]),
    "wssize": FuncSpec("Переписывает TCP window size и scale factor (применять с SYN,ACK).",
                       [P("wsize", "int", "размер окна, напр. 1"), P("scale", "int", "0..14, напр. 6")]),
    "syndata": FuncSpec("Добавляет данные в SYN (вызывать ПОСЛЕ wssize).", [P("blob", "blob")] + FOOL),
    "rst": FuncSpec("Отправляет поддельный RST.", FOOL),
    "pktmod": FuncSpec("Применяет фулинг к текущему пакету (VERDICT_MODIFY).", FOOL),
    "send": FuncSpec("Отправляет текущий пакет с модификаторами, не дропая оригинал.",
                     FOOL + [P("ipfrag", "str", "ipfrag2 или своя функция"),
                             P("ipfrag_pos_tcp", "int"), P("ipfrag_pos_udp", "int", "напр. 8")]),
    "drop": FuncSpec("Дропает текущий пакет (VERDICT_DROP). По умолчанию работает с любыми пейлоадами.", []),
    "luaexec": FuncSpec("Выполняет Lua-код на лету (например desync.rnd=brandom_az(7)).",
                        [P("code", "str", "Lua-код")]),
}

PAYLOAD_TYPES = ["all", "known", "unknown", "empty", "http_req", "http_reply", "tls_client_hello",
                 "tls_server_hello", "quic_initial", "wireguard_initiation", "wireguard_response",
                 "wireguard_cookie", "wireguard_keepalive", "wireguard_data", "stun",
                 "discord_ip_discovery", "dht", "dns_query", "dns_response", "mtproto_initial",
                 "xmpp_stream", "xmpp_starttls", "xmpp_proceed", "xmpp_features"]

BUILTIN_BLOBS = ["fake_default_tls", "fake_default_http", "fake_default_quic"]
