# -*- coding: utf-8 -*-
"""Generate Noid presentation slides (SVG, EN+RU) into docs/manual/slides/."""
import pathlib

OUT = pathlib.Path(__file__).parent
BG = "#0a0a0b"; SURF = "#121216"; VIO = "#8b5cf6"; GRN = "#10b981"
TXT = "#e8e8ec"; MUT = "#9a9aa5"


def wrap(text, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 <= width:
            cur = (cur + " " + w).strip()
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


TOTAL = 10


def slide(num, tr, te, br, be, icon, accent_ru="", accent_en="", caption=""):
    for lang, title, body, accent in (
            ("ru", tr, br, accent_ru), ("en", te, be, accent_en)):
        t = wrap(title, 34 if lang == "ru" else 38)
        b = wrap(body, 62 if lang == "ru" else 68)
        svg = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720">',
            '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/>'
            '</linearGradient></defs>' % (VIO, GRN),
            '<rect width="1280" height="720" fill="%s"/>' % BG,
            '<rect x="40" y="40" width="1200" height="640" rx="20" fill="%s"/>' % SURF,
            '<text x="120" y="90" font-family="Segoe UI,Arial" font-size="18" fill="%s">'
            'Noid Messenger · %02d/%02d · %s · v0.2.0</text>'
            % (MUT, num, TOTAL, lang.upper()),
            '<text x="1160" y="90" text-anchor="end" font-family="Segoe UI,Arial" '
            'font-size="18" fill="%s">noid</text>' % VIO,
        ]
        for i, line in enumerate(t):
            svg.append(
                '<text x="120" y="%d" font-family="Segoe UI,Arial" font-size="44" '
                'font-weight="700" fill="%s">%s</text>' % (120 + i * 52, TXT, line))
        by = 120 + len(t) * 52 + 30
        for i, line in enumerate(b):
            svg.append(
                '<text x="120" y="%d" font-family="Segoe UI,Arial" font-size="26" '
                'fill="%s">%s</text>' % (by + i * 34, MUT, line))
        ay = by + len(b) * 34 + 14
        if accent:
            svg.append(
                '<text x="120" y="%d" font-family="Segoe UI,Arial" font-size="24" '
                'fill="%s">%s</text>' % (ay, VIO, accent))
        svg.append('<circle cx="1020" cy="380" r="150" fill="none" '
                   'stroke="url(#g)" stroke-width="4"/>')
        svg.append(icon)
        if caption:
            svg.append(
                '<text x="1020" y="600" text-anchor="middle" '
                'font-family="Consolas,monospace" font-size="20" '
                'fill="%s">%s</text>' % (MUT, caption))
        svg.append('<rect x="120" y="640" width="200" height="6" rx="3" fill="url(#g)"/>')
        svg.append('</svg>')
        (OUT / ("slide%02d_%s.svg" % (num, lang))).write_text(
            "\n".join(svg), encoding="utf-8")


ICONS = {
    1: '<circle cx="1020" cy="380" r="70" fill="none" stroke="%s" stroke-width="6"/>'
       '<path d="M975 380 l30 30 60 -60" fill="none" stroke="%s" stroke-width="8" '
       'stroke-linecap="round"/>' % (VIO, GRN),
    2: '<rect x="960" y="335" width="120" height="90" rx="8" fill="none" stroke="%s" '
       'stroke-width="5"/><path d="M960 335 l60 40 60 -40" fill="none" stroke="%s" '
       'stroke-width="5"/>' % (VIO, GRN),
    3: ''.join(
        '<rect x="%d" y="%d" width="70" height="70" rx="12" fill="none" stroke="%s" '
        'stroke-width="4"/>' % (x, y, c)
        for x, y, c in [(930, 290, VIO), (1040, 290, GRN), (930, 400, GRN), (1040, 400, VIO)]),
    4: '<path d="M1020 295 l70 28 v57 c0 40 -30 68 -70 80 c-40 -12 -70 -40 -70 -80 '
       'v-57 z" fill="none" stroke="%s" stroke-width="6"/>'
       '<path d="M990 375 l22 22 44 -48" fill="none" stroke="%s" stroke-width="7" '
       'stroke-linecap="round"/>' % (VIO, GRN),
    5: ''.join('<circle cx="%d" cy="%d" r="16" fill="%s"/>' % (x, y, c)
               for x, y, c in [(950, 320, VIO), (1090, 320, GRN), (950, 440, GRN), (1090, 440, VIO)])
       + '<circle cx="1020" cy="380" r="18" fill="%s"/>' % TXT
       + '<g stroke="%s" stroke-width="3"><line x1="964" y1="330" x2="1005" y2="370"/>'
       '<line x1="1076" y1="330" x2="1035" y2="370"/><line x1="964" y1="430" x2="1005" y2="392"/>'
       '<line x1="1076" y1="430" x2="1035" y2="392"/></g>' % MUT,
    6: '<rect x="955" y="335" width="130" height="90" rx="10" fill="none" stroke="%s" '
       'stroke-width="5"/><path d="M955 335 l65 45 65 -45" fill="none" stroke="%s" '
       'stroke-width="5"/>' % (GRN, VIO),
    7: ''.join('<rect x="%d" y="340" width="55" height="80" rx="8" fill="none" stroke="%s" '
               'stroke-width="4"/>' % (x, c)
               for x, c in [(930, VIO), (1010, GRN), (1090, VIO)]),
    8: '<rect x="940" y="300" width="70" height="160" rx="8" fill="none" stroke="%s" '
       'stroke-width="5"/><rect x="1030" y="300" width="70" height="160" rx="8" fill="none" '
       'stroke="%s" stroke-width="5"/>' % (VIO, GRN)
       + '<text x="957" y="390" font-family="Consolas,monospace" font-size="30" '
       'fill="%s">&gt;_</text>' % GRN
       + '<text x="1047" y="390" font-family="Consolas,monospace" font-size="30" '
       'fill="%s">{ }</text>' % VIO,
    9: '<circle cx="1020" cy="380" r="105" fill="none" stroke="%s" stroke-width="3" '
        'opacity="0.55"/><circle cx="1020" cy="380" r="60" fill="none" stroke="%s" '
        'stroke-width="3" opacity="0.7"/><circle cx="1020" cy="380" r="18" '
        'fill="%s"/>' % (VIO, GRN, TXT),
    10: '<circle cx="1020" cy="380" r="85" fill="none" stroke="url(#g)" stroke-width="7"/>'
        '<path d="M945 380 h40 l10 -25 14 50 10 -25 h40" fill="none" stroke="%s" '
        'stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>' % TXT,
}

S = [
    (1, "Ваши сообщения — только на ваших устройствах",
     "Your messages live on your devices only",
     "P2P-мессенджер со сквозным шифрованием. Нет центрального сервера — "
     "нет точки сбоя и слежки.",
     "End-to-end encrypted P2P messenger. No central server — "
     "no single point of failure or surveillance."),
    (2, "Почтовые отделения читают письма", "Post offices read your letters",
     "Централизованные серверы хранят plaintext, метаданные и контакты "
     "навсегда — и их можно изъять.",
     "Centralized servers store plaintext, metadata and contacts forever — "
     "and they can be seized."),
    (3, "Один бинарник — все роли", "One binary — every role",
     "Клиент, узел DHT, релей и офлайн-почтовый ящик в одном файле. "
     "Ничего не нужно поднимать отдельно.",
     "Chat client, DHT node, relay and offline mailbox in one executable. "
     "Nothing else to deploy."),
    (4, "Безопасность в глубину", "Defense in depth",
     "PIN → Argon2id → AES-256-GCM. X3DH → Double Ratchet. "
     "KillPIN стирает всё мгновенно.",
     "PIN → Argon2id → AES-256-GCM. X3DH → Double Ratchet. "
     "KillPIN wipes everything instantly."),
    (5, "Пиры находят друг друга через DHT", "Peers find each other via DHT",
     "Kademlia: имена, подписанные prekey-бандлы, указатели mailbox. "
     "Инвайт-код — и вы на связи.",
     "Kademlia: usernames, signed prekey bundles, mailbox pointers. "
     "Share an invite code — and talk."),
    (6, "Офлайн? Не проблема", "Offline? No problem",
     "Шифрованные конверты ждут на mailbox-узле — сообщения переживают "
     "NAT и недели офлайна.",
     "Encrypted envelopes wait on a mailbox node — messages survive NAT, "
     "reboots and weeks offline."),
    (7, "Один код — все платформы", "One codebase — all platforms",
     "Windows, Linux/VPS, Android: одно ядро Rust, одна криптография, один формат.",
     "Windows, Linux/VPS, Android: one Rust core, one crypto stack, one format."),
    (8, "Открыт и проверяем", "Open and auditable",
     "Rust + Svelte + Tauri. Тестируемая криптография, документированная "
     "модель угроз.",
     "Rust + Svelte + Tauri. Testable crypto, documented threat model — "
     "verify yourself."),
    (9, "Onion внутри", "Onion inside",
     "Встроенный Arti Tor — стабильная .onion-идентичность у каждого "
     "узла, дозвоны по onion3, работа под DPI. Без демона и Orbot.",
     "Embedded Arti Tor — every node gets a stable .onion identity, "
     "dials peers over onion3, survives DPI. No daemon, no Orbot."),
    (10, "Сообщения, принадлежащие вам", "Messaging that belongs to you",
     "Noid — ваша переписка, ваши ключи, ваша сеть. "
     "Децентрализация как принцип.",
     "Noid — your correspondence, your keys, your network. "
     "Decentralization as a principle."),
]

EXTRAS = {
    9: ("off · additional · tor_only — по согласию, fail-closed.",
         "off · additional · tor_only — consent-gated, fail-closed.",
         "….onion:4020"),
}

for n, tr, te, br, be in S:
    ar, ae, cap = EXTRAS.get(n, ("", "", ""))
    slide(n, tr, te, br, be, ICONS[n], ar, ae, cap)

print("slides:", len(list(OUT.glob("slide*.svg"))))
