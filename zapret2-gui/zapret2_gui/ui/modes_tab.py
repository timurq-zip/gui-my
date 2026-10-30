from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QFormLayout, QRadioButton, QGroupBox, QCheckBox, QLineEdit, QSpinBox, QLabel)


class ModesTab(QWidget):
    changed = Signal()

    def __init__(self, state):
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        g = QGroupBox("Режим обхода (какие из ВАШИХ профилей активны и какой трафик перехватывается)")
        v = QVBoxLayout(g)
        self.r = {"tcp": QRadioButton("TCP — только профили с --filter-tcp"),
                  "udp": QRadioButton("UDP (QUIC/STUN/WireGuard/Discord Voice) — только профили с --filter-udp"),
                  "both": QRadioButton("TCP + UDP — все включённые профили")}
        for k, b in self.r.items():
            v.addWidget(b); b.toggled.connect(self._collect)
        self.r[state.mode].setChecked(True)
        lay.addWidget(g)
        gg = QGroupBox("GameFilter (эмуляция: в zapret2 готового нет)")
        gl = QFormLayout(gg)
        self.ge = QCheckBox("Включить (действует в режимах UDP и TCP+UDP)"); self.ge.setChecked(state.game.enabled)
        self.gp = QLineEdit(state.game.ports); self.gp.setPlaceholderText("напр. 27015-27030,3074,50000-50100")
        self.gb = QLineEdit(state.game.blob)
        self.gr = QSpinBox(); self.gr.setRange(1, 20); self.gr.setValue(state.game.repeats)
        gl.addRow(self.ge); gl.addRow("UDP-порты/диапазоны:", self.gp); gl.addRow("Блоб (0xHEX):", self.gb); gl.addRow("repeats:", self.gr)
        gl.addRow(QLabel("Генерируется профиль: --filter-udp=<порты> --payload=all --lua-desync=fake:blob=…:repeats=…:payload=all\n"
                         "Он ставится ПЕРВЫМ в списке профилей."))
        lay.addWidget(gg)
        gs = QGroupBox("Настройки"); sl = QFormLayout(gs)
        s = state.settings
        self.zd = QLineEdit(s.zapret2_dir); self.nb = QLineEdit(s.nfqws2_path); self.nb.setPlaceholderText("пусто = автопоиск")
        self.q = QSpinBox(); self.q.setRange(0, 65535); self.q.setValue(s.qnum)
        self.dbg = QCheckBox("--debug"); self.dbg.setChecked(s.debug)
        self.pl = QSpinBox(); self.pl.setRange(1, 1000); self.pl.setValue(s.packet_limit)
        self.rep = QCheckBox("Перехватывать входящие ответы (ct reply)"); self.rep.setChecked(s.intercept_replies)
        self.ifc = QLineEdit(s.iface); self.ifc.setPlaceholderText("пусто = все интерфейсы")
        for lbl, w in (("Каталог zapret2:", self.zd), ("Путь к nfqws2:", self.nb), ("Номер очереди --qnum:", self.q), ("", self.dbg),
                       ("Перехват первых N пакетов (ct packets 1-N):", self.pl), ("", self.rep), ("Интерфейс:", self.ifc)):
            sl.addRow(lbl, w)
        lay.addWidget(gs); lay.addStretch()
        for w in (self.gp, self.gb, self.zd, self.nb, self.ifc):
            w.textEdited.connect(self._collect)
        for w in (self.ge, self.dbg, self.rep):
            w.toggled.connect(self._collect)
        for w in (self.gr, self.q, self.pl):
            w.valueChanged.connect(self._collect)

    def _collect(self, *_):
        if not hasattr(self, "ifc"):
            return
        st = self.state
        st.mode = next(k for k, b in self.r.items() if b.isChecked()) if any(b.isChecked() for b in self.r.values()) else st.mode
        st.game.enabled, st.game.ports, st.game.blob, st.game.repeats = self.ge.isChecked(), self.gp.text(), self.gb.text().strip(), self.gr.value()
        s = st.settings
        s.zapret2_dir, s.nfqws2_path, s.qnum, s.debug = self.zd.text().strip(), self.nb.text().strip(), self.q.value(), self.dbg.isChecked()
        s.packet_limit, s.intercept_replies, s.iface = self.pl.value(), self.rep.isChecked(), self.ifc.text().strip()
        self.changed.emit()
