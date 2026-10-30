import copy
import subprocess
from datetime import datetime
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QPlainTextEdit, QMessageBox,
                               QSplitter)
from PySide6.QtCore import Qt
from ..cli_builder import build_state_args, to_shell, active_profiles, intercept_ports
from ..nft import build_ruleset, TABLE
from ..paths import BACKUP_DIR, STATE_DIR, ensure_dirs
from ..privilege import RootHelper, HelperError
from ..storage import load_state, save_state
from ..validator import validate_args, has_errors, dry_run
from .modes_tab import ModesTab
from .profiles_tab import ProfilesTab
from .scanners_tab import ScannersTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ensure_dirs()
        self.setWindowTitle("zapret2-gui — управление nfqws2"); self.resize(1100, 820)
        self.state, self.helper, self.pid, self.last_backup = load_state(), RootHelper(), None, None
        self.tabs = QTabWidget()
        self.ptab = ProfilesTab(self.state); self.mtab = ModesTab(self.state); self.stab = ScannersTab(self)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        self.tabs.addTab(self.ptab, "Профили и мультистратегия"); self.tabs.addTab(self.mtab, "Режимы обхода")
        self.tabs.addTab(self.stab, "Сканеры"); self.tabs.addTab(self.log, "Журнал")
        self.preview = QPlainTextEdit(); self.preview.setReadOnly(True); self.preview.setMaximumHeight(170)
        bar = QHBoxLayout()
        for text, fn in (("Проверить конфигурацию", self.check), ("Применить nftables и запустить", self.start_nfqws),
                         ("Остановить и убрать правила", self.stop_nfqws), ("Восстановить nftables из бэкапа", self.restore_backup),
                         ("Показать nfqws2 --debug", self.show_log)):
            b = QPushButton(text); b.clicked.connect(fn); bar.addWidget(b)
        box = QWidget(); l = QVBoxLayout(box); l.addLayout(bar); l.addWidget(self.preview)
        sp = QSplitter(Qt.Vertical); sp.addWidget(self.tabs); sp.addWidget(box); sp.setStretchFactor(0, 4)
        self.setCentralWidget(sp)
        for t in (self.ptab, self.mtab):
            t.changed.connect(self.on_change)
        self.stab.apply_profile.connect(self.add_scanned)
        self.timer = QTimer(self); self.timer.timeout.connect(self.tail_log); self.timer.start(1500); self._logpos = 0
        self.refresh_preview()

    # ---- состояние ----
    def on_change(self):
        save_state(self.state); self.refresh_preview()

    def refresh_preview(self):
        st = self.state
        self.preview.setPlainText(to_shell(build_state_args(st), st.settings.nfqws2_bin() or "nfqws2"))

    def say(self, msg):
        self.log.appendPlainText(f"[{datetime.now():%H:%M:%S}] {msg}")

    def add_scanned(self, prof):
        self.state.profiles.append(prof); self.ptab.profiles.reload(); self.on_change()
        self.tabs.setCurrentIndex(0); self.say(f"Из сканера добавлен профиль «{prof.name}»")

    # ---- права ----
    def ensure_helper(self, why: str) -> bool:
        if self.helper.running:
            return True
        if QMessageBox.question(self, "Нужны права администратора",
                                f"{why}\n\nБудет запущен привилегированный помощник через pkexec/sudo. "
                                "Он умеет только: управлять nftables-таблицей, менять один sysctl и запускать nfqws2.\n\nПродолжить?") != QMessageBox.Yes:
            return False
        try:
            self.helper.start(); self.say("Привилегированный помощник запущен"); return True
        except HelperError as e:
            QMessageBox.critical(self, "Нет прав", str(e)); return False

    # ---- действия ----
    def check(self) -> bool:
        st = self.state
        args = build_state_args(st)
        if not active_profiles(st):
            QMessageBox.warning(self, "Проверка", "Нет активных профилей: создайте профиль или включите GameFilter."); return False
        issues = validate_args(args, [b.name for b in st.blobs])
        lines = [str(i) for i in issues]
        status, out = dry_run(st.settings.nfqws2_bin(), args)
        lines.append(f"[nfqws2 --dry-run] {status}: {out[:600]}")
        if not issues and status in ("ok", "unsupported", "missing"):
            lines.insert(0, "Эвристическая проверка: замечаний нет.")
        self.say("Проверка конфигурации:\n  " + "\n  ".join(lines))
        bad = has_errors(issues) or status == "fail"
        (QMessageBox.critical if bad else QMessageBox.information)(self, "Результат проверки", "\n".join(lines))
        return not bad

    def start_nfqws(self):
        st = self.state
        if self.pid:
            QMessageBox.information(self, "Запуск", "Уже запущено. Сначала остановите."); return
        if not st.settings.nfqws2_bin():
            QMessageBox.warning(self, "nfqws2", "Бинарник nfqws2 не найден. Укажите каталог zapret2 в «Режимы обхода → Настройки»."); return
        if not self.check():
            return
        profs = active_profiles(st); tcp, udp = intercept_ports(profs)
        try:
            script = build_ruleset(tcp, udp, st.settings.qnum, st.settings.packet_limit, st.settings.intercept_replies, st.settings.iface)
        except ValueError as e:
            QMessageBox.warning(self, "nftables", str(e)); return
        if QMessageBox.question(self, "Подтверждение", "Будут применены правила nftables:\n\n" + script + "\nПеред этим сохранится бэкап. Продолжить?") != QMessageBox.Yes:
            return
        if not self.ensure_helper("Для применения nftables и запуска nfqws2 нужен root."):
            return
        bk = BACKUP_DIR / f"nft-{datetime.now():%Y%m%d-%H%M%S}.nft"
        r = self.helper.call("nft_backup", path=str(bk))
        if not r.get("ok"):
            QMessageBox.critical(self, "Бэкап", f"Бэкап не удался, запуск отменён: {r.get('err')}"); return
        self.last_backup = bk; self.say(f"Бэкап nftables: {bk}")
        self.old_liberal = self.helper.call("sysctl_liberal", value=1).get("old")
        r = self.helper.call("nft_apply", script=script)
        if not r.get("ok"):
            QMessageBox.critical(self, "nftables", r.get("err", "")); return
        self.logfile = STATE_DIR / "nfqws2_main.log"; self.logfile.write_text(""); self._logpos = 0
        r = self.helper.call("start", argv=[st.settings.nfqws2_bin()] + build_state_args(st), log=str(self.logfile))
        if not r.get("ok"):
            self.helper.call("nft_delete", table=TABLE); QMessageBox.critical(self, "nfqws2", r.get("err", "")); return
        self.pid = r["pid"]; self.say(f"nfqws2 запущен, pid={self.pid}")

    def stop_nfqws(self):
        if self.helper.running:
            if self.pid:
                self.helper.call("stop", pid=self.pid)
            self.helper.call("nft_delete", table=TABLE)
            if getattr(self, "old_liberal", None) is not None:
                self.helper.call("sysctl_liberal", value=self.old_liberal)
        self.pid = None; self.say("Остановлено, таблица nftables удалена")

    def restore_backup(self):
        bk = self.last_backup or (sorted(BACKUP_DIR.glob("nft-*.nft")) or [None])[-1]
        if not bk:
            QMessageBox.information(self, "Бэкап", "Бэкапов нет."); return
        if QMessageBox.question(self, "Восстановление", f"Полностью заменить текущий ruleset содержимым\n{bk}?") != QMessageBox.Yes:
            return
        if self.ensure_helper("Восстановление правил nftables."):
            r = self.helper.call("nft_restore", path=str(bk)); self.say(f"restore: {r}")

    def tail_log(self):
        f = getattr(self, "logfile", None)
        if f and f.exists():
            with open(f, "rb") as fh:
                fh.seek(self._logpos); data = fh.read(); self._logpos = fh.tell()
            if data:
                self.log.appendPlainText(data.decode("utf-8", "replace").rstrip())

    def show_log(self):
        self.tabs.setCurrentWidget(self.log)

    def closeEvent(self, e):
        try:
            self.stop_nfqws(); self.helper.stop()
        finally:
            super().closeEvent(e)
