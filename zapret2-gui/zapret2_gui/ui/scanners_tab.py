import json
import subprocess
import threading
import yaml
from PySide6.QtCore import Signal, QObject
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QComboBox, QLineEdit, QPushButton, QPlainTextEdit,
                               QTableWidget, QTableWidgetItem, QProgressBar, QLabel, QFileDialog, QMessageBox, QHeaderView)
from ..models import Profile
from ..scanners.core import ScanRunner
from ..scanners.strategies import DEFAULTS, merge_defaults, GENERATORS


class Bridge(QObject):
    progress = Signal(str, int, int, object)
    done = Signal(str, str)


class ScannersTab(QWidget):
    apply_profile = Signal(object)

    def __init__(self, main):
        super().__init__()
        self.main, self.cands, self.stop_flag, self.results = main, [], False, []
        self.bridge = Bridge(); self.bridge.progress.connect(self.on_progress); self.bridge.done.connect(self.on_done)
        lay = QVBoxLayout(self)
        self.kind = QComboBox()
        self.kind.addItem("А. UDP (QUIC / STUN / WireGuard)", "udp"); self.kind.addItem("Б. Игры (GameFilter Seeker)", "game")
        self.kind.addItem("В. Discord стрим (UDP 19294-19344)", "discord")
        lay.addWidget(self.kind)
        f = QFormLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText("домен или IP сервера-цели")
        self.port = QLineEdit(); self.port.setPlaceholderText("порт (UDP) или порты/диапазон (игры, Discord)")
        self.l7 = QComboBox(); self.l7.addItems(["quic", "stun", "wireguard"])
        self.rmin = QLineEdit(); self.rmax = QLineEdit(); self.blobs = QLineEdit(); self.maxc = QLineEdit()
        self.blobs.setPlaceholderText("через запятую: fake_default_quic, 0x0000…  (пусто = по умолчанию)")
        self.rmin.setPlaceholderText("repeats от"); self.rmax.setPlaceholderText("repeats до"); self.maxc.setPlaceholderText("макс. кандидатов")
        for l, w in (("Цель:", self.host), ("Порт(ы):", self.port), ("l7 (только UDP-сканер):", self.l7), ("repeats от:", self.rmin),
                     ("repeats до:", self.rmax), ("Блобы:", self.blobs), ("Макс. кандидатов:", self.maxc)):
            f.addRow(l, w)
        lay.addLayout(f)
        row = QHBoxLayout()
        self.start = QPushButton("Старт"); self.stop = QPushButton("Стоп"); self.stop.setEnabled(False)
        ly = QPushButton("Загрузить YAML…"); sy = QPushButton("Сохранить YAML…"); self.apply = QPushButton("Применить выбранную как профиль")
        op = QPushButton("Открыть папку сессии")
        for b in (self.start, self.stop, ly, sy, self.apply, op):
            row.addWidget(b)
        lay.addLayout(row)
        self.bar = QProgressBar(); self.status = QLabel("")
        lay.addWidget(self.bar); lay.addWidget(self.status)
        self.table = QTableWidget(0, 4); self.table.setHorizontalHeaderLabels(["Статус", "Стратегия", "RTT, мс", "Заметки"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch); self.table.setSelectionBehavior(QTableWidget.SelectRows)
        lay.addWidget(self.table)
        self.start.clicked.connect(self.do_start); self.stop.clicked.connect(lambda: setattr(self, "stop_flag", True))
        ly.clicked.connect(self.load_yaml); sy.clicked.connect(self.save_yaml); self.apply.clicked.connect(self.do_apply)
        op.clicked.connect(lambda: self.session and subprocess.Popen(["xdg-open", self.session]))
        self.kind.currentIndexChanged.connect(self.fill_defaults)
        self.session = ""; self.fill_defaults()

    def fill_defaults(self):
        self.set_cfg(DEFAULTS[self.kind.currentData()])

    def set_cfg(self, c):
        i = self.kind.findData(c["scanner"]); self.kind.blockSignals(True); self.kind.setCurrentIndex(i); self.kind.blockSignals(False)
        t = c.get("target", {}); r = c.get("space", {}).get("repeats", {})
        self.host.setText(t.get("host", "")); self.port.setText(str(t.get("port", t.get("ports", ""))))
        self.l7.setCurrentText(c.get("l7", "quic")); self.rmin.setText(str(r.get("min", ""))); self.rmax.setText(str(r.get("max", "")))
        self.blobs.setText(", ".join(c.get("space", {}).get("blobs", []) or [])); self.maxc.setText(str(c.get("limits", {}).get("max_candidates", 40)))
        self._extra = c

    def get_cfg(self) -> dict:
        k = self.kind.currentData()
        c = merge_defaults({"scanner": k})
        c["target"]["host"] = self.host.text().strip()
        if k == "udp":
            c["target"]["port"] = int(self.port.text() or 443); c["l7"] = self.l7.currentText()
        else:
            c["target"]["ports"] = self.port.text().strip()
        sp = c["space"]
        if self.rmin.text() and self.rmax.text():
            sp["repeats"] = {"min": int(self.rmin.text()), "max": int(self.rmax.text()), "step": sp.get("repeats", {}).get("step", 1)}
        if self.blobs.text().strip():
            sp["blobs"] = [b.strip() for b in self.blobs.text().split(",") if b.strip()]
        c["limits"]["max_candidates"] = int(self.maxc.text() or 40)
        for key in ("probe", "limits", "runtime"):  # сохранить значения, загруженные из YAML
            c[key].update(getattr(self, "_extra", {}).get(key, {}) if key != "limits" else {})
        return c

    def load_yaml(self):
        p, _ = QFileDialog.getOpenFileName(self, "YAML сканера", "", "YAML (*.yaml *.yml)")
        if p:
            self.set_cfg(merge_defaults(yaml.safe_load(open(p, encoding="utf-8"))))

    def save_yaml(self):
        p, _ = QFileDialog.getSaveFileName(self, "Сохранить YAML", "scan.yaml")
        if p:
            open(p, "w", encoding="utf-8").write(yaml.safe_dump(self.get_cfg(), allow_unicode=True, sort_keys=False))

    def do_start(self):
        try:
            cfg = self.get_cfg()
        except ValueError as e:
            QMessageBox.warning(self, "Параметры", str(e)); return
        if not self.main.ensure_helper("Сканер временно создаст таблицу nftables, запустит nfqws2 и сделает бэкап правил."):
            return
        self.stop_flag = False; self.table.setRowCount(0); self.results = []
        self.start.setEnabled(False); self.stop.setEnabled(True)
        runner = ScanRunner(cfg, self.main.state, self.main.helper,
                            lambda m, i, n, r=None: self.bridge.progress.emit(m, i, n, r), lambda: self.stop_flag)
        def work():
            try:
                self.session = str(runner.run()); self.bridge.done.emit(self.session, "")
            except Exception as e:  # noqa
                self.session = str(getattr(runner, "dir", "")); self.bridge.done.emit(self.session, str(e))
        threading.Thread(target=work, daemon=True).start()

    def on_progress(self, msg, i, n, res):
        self.status.setText(msg); self.bar.setMaximum(max(n, 1)); self.bar.setValue(i)
        if res:
            self.results.append(res)
            r = self.table.rowCount(); self.table.insertRow(r)
            for c, t in enumerate((res["status"], res["name"], str(res.get("rtt_ms") or ""), " | ".join(res.get("notes", [])))):
                self.table.setItem(r, c, QTableWidgetItem(t))

    def on_done(self, d, err):
        self.start.setEnabled(True); self.stop.setEnabled(False)
        self.status.setText(f"Готово. Папка: {d}")
        if err:
            QMessageBox.critical(self, "Ошибка сканера", err)

    def do_apply(self):
        r = self.table.currentRow()
        if r < 0:
            return
        cfg = self.get_cfg()
        for c in GENERATORS[cfg["scanner"]](cfg):
            if c.name == self.results[r]["name"]:
                p = c.profile; p.name = f"{p.name} ({c.name})"[:80]
                self.apply_profile.emit(p); return
