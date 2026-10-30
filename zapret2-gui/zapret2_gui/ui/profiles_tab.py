from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QFormLayout, QListWidget, QListWidgetItem, QPushButton,
                               QLineEdit, QCheckBox, QComboBox, QTableWidget, QTableWidgetItem, QTabWidget, QPlainTextEdit,
                               QLabel, QInputDialog, QMessageBox, QFileDialog, QHeaderView, QGroupBox)
from ..models import Profile, Step, Blob, LuaInit, L7_PROTOCOLS
from .. import storage
from .dialogs import StepDialog


class ProfilesPage(QWidget):
    changed = Signal()

    def __init__(self, state):
        super().__init__()
        self.state, self.cur, self._loading = state, None, False
        root = QHBoxLayout(self)
        left = QVBoxLayout()
        self.lst = QListWidget(); left.addWidget(self.lst)
        for text, fn in (("Новый профиль", self.add_profile), ("Удалить", self.del_profile),
                         ("Вверх", lambda: self.move_profile(-1)), ("Вниз", lambda: self.move_profile(1))):
            b = QPushButton(text); b.clicked.connect(fn); left.addWidget(b)
        left.addWidget(QLabel("Порядок важен: срабатывает первый\nподходящий профиль (--new)."))
        root.addLayout(left, 1)
        right = QVBoxLayout()
        form = QFormLayout()
        self.name = QLineEdit(); self.ftcp = QLineEdit(); self.fudp = QLineEdit()
        self.ftcp.setPlaceholderText("--filter-tcp, напр. 80,443"); self.fudp.setPlaceholderText("--filter-udp, напр. 443 или 19294-19344")
        self.hl = QComboBox(); self.hlx = QComboBox()
        form.addRow("Название:", self.name); form.addRow("--filter-tcp:", self.ftcp); form.addRow("--filter-udp:", self.fudp)
        l7row = QHBoxLayout(); self.l7 = {}
        for p in L7_PROTOCOLS:
            c = QCheckBox(p); self.l7[p] = c; l7row.addWidget(c); c.toggled.connect(self._collect)
        form.addRow("--filter-l7:", l7row)
        form.addRow("--hostlist:", self.hl); form.addRow("--hostlist-exclude:", self.hlx)
        right.addLayout(form)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["--payload", "--in-range", "--out-range", "--lua-desync"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.doubleClicked.connect(self.edit_step)
        right.addWidget(self.table)
        row = QHBoxLayout()
        for text, fn in (("+ Добавить --lua-desync", self.add_step), ("Изменить", self.edit_step), ("Удалить", self.del_step),
                         ("↑", lambda: self.move_step(-1)), ("↓", lambda: self.move_step(1))):
            b = QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        right.addLayout(row)
        root.addLayout(right, 3)
        for w in (self.name, self.ftcp, self.fudp):
            w.textEdited.connect(self._collect)
        self.hl.currentTextChanged.connect(self._collect); self.hlx.currentTextChanged.connect(self._collect)
        self.lst.currentRowChanged.connect(self.select)
        self.lst.itemChanged.connect(self._item_checked)
        self.refresh_lists(); self.reload()

    def refresh_lists(self):
        names = [""] + storage.list_names()
        for cb in (self.hl, self.hlx):
            cur = cb.currentText(); cb.blockSignals(True); cb.clear(); cb.addItems(names); cb.setCurrentText(cur); cb.blockSignals(False)

    def reload(self):
        self.lst.blockSignals(True); self.lst.clear()
        for p in self.state.profiles:
            it = QListWidgetItem(p.name); it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if p.enabled else Qt.Unchecked); self.lst.addItem(it)
        self.lst.blockSignals(False)
        self.lst.setCurrentRow(0 if self.state.profiles else -1)
        self.select(self.lst.currentRow())

    def select(self, row):
        self._loading = True
        self.cur = self.state.profiles[row] if 0 <= row < len(self.state.profiles) else None
        p = self.cur or Profile()
        self.setEnabled(True)
        self.name.setText(p.name if self.cur else ""); self.ftcp.setText(p.filter_tcp); self.fudp.setText(p.filter_udp)
        for k, c in self.l7.items():
            c.setChecked(k in p.filter_l7)
        self.refresh_lists(); self.hl.setCurrentText(p.hostlist); self.hlx.setCurrentText(p.hostlist_exclude)
        self.fill_steps(); self._loading = False

    def fill_steps(self):
        self.table.setRowCount(0)
        for s in (self.cur.steps if self.cur else []):
            r = self.table.rowCount(); self.table.insertRow(r)
            for c, t in enumerate((s.payload, s.in_range, s.out_range, s.desync_arg())):
                self.table.setItem(r, c, QTableWidgetItem(t))

    def _collect(self, *_):
        if self._loading or not self.cur:
            return
        p = self.cur
        p.name, p.filter_tcp, p.filter_udp = self.name.text(), self.ftcp.text(), self.fudp.text()
        p.filter_l7 = [k for k, c in self.l7.items() if c.isChecked()]
        p.hostlist, p.hostlist_exclude = self.hl.currentText(), self.hlx.currentText()
        self.lst.item(self.lst.currentRow()).setText(p.name)
        self.changed.emit()

    def _item_checked(self, it):
        self.state.profiles[self.lst.row(it)].enabled = it.checkState() == Qt.Checked; self.changed.emit()

    def add_profile(self):
        self.state.profiles.append(Profile(name=f"Профиль {len(self.state.profiles) + 1}"))
        self.reload(); self.lst.setCurrentRow(len(self.state.profiles) - 1); self.changed.emit()

    def del_profile(self):
        r = self.lst.currentRow()
        if r >= 0:
            del self.state.profiles[r]; self.reload(); self.changed.emit()

    def move_profile(self, d):
        r, n = self.lst.currentRow(), self.lst.currentRow() + d
        if 0 <= r < len(self.state.profiles) and 0 <= n < len(self.state.profiles):
            ps = self.state.profiles; ps[r], ps[n] = ps[n], ps[r]; self.reload(); self.lst.setCurrentRow(n); self.changed.emit()

    def add_step(self):
        if not self.cur:
            QMessageBox.information(self, "Профиль", "Сначала создайте профиль."); return
        dlg = StepDialog(Step(), [b.name for b in self.state.blobs], self)
        if dlg.exec():
            self.cur.steps.append(dlg.get_step()); self.fill_steps(); self.changed.emit()

    def edit_step(self, *_):
        r = self.table.currentRow()
        if self.cur and r >= 0:
            dlg = StepDialog(self.cur.steps[r], [b.name for b in self.state.blobs], self)
            if dlg.exec():
                self.cur.steps[r] = dlg.get_step(); self.fill_steps(); self.changed.emit()

    def del_step(self):
        r = self.table.currentRow()
        if self.cur and r >= 0:
            del self.cur.steps[r]; self.fill_steps(); self.changed.emit()

    def move_step(self, d):
        r, n = self.table.currentRow(), self.table.currentRow() + d
        if self.cur and 0 <= r < len(self.cur.steps) and 0 <= n < len(self.cur.steps):
            s = self.cur.steps; s[r], s[n] = s[n], s[r]; self.fill_steps(); self.table.selectRow(n); self.changed.emit()


class ListsPage(QWidget):
    changed = Signal()

    def __init__(self):
        super().__init__()
        lay = QHBoxLayout(self)
        left = QVBoxLayout(); self.lst = QListWidget(); left.addWidget(self.lst)
        for t, f in (("Новый список", self.new), ("Удалить", self.delete)):
            b = QPushButton(t); b.clicked.connect(f); left.addWidget(b)
        lay.addLayout(left, 1)
        right = QVBoxLayout()
        right.addWidget(QLabel("Один домен на строку (без http://). Поддомены включены автоматически."))
        self.edit = QPlainTextEdit(); right.addWidget(self.edit)
        b = QPushButton("Сохранить список"); b.clicked.connect(self.save); right.addWidget(b)
        lay.addLayout(right, 3)
        self.lst.currentTextChanged.connect(lambda n: self.edit.setPlainText(storage.read_list(n) if n else ""))
        self.reload()

    def reload(self, select=None):
        self.lst.clear(); self.lst.addItems(storage.list_names())
        if select:
            for i in range(self.lst.count()):
                if self.lst.item(i).text() == select:
                    self.lst.setCurrentRow(i)

    def new(self):
        n, ok = QInputDialog.getText(self, "Новый хостлист", "Имя (латиница, цифры, _ . -):")
        if ok and n:
            try:
                storage.write_list(n, ""); self.reload(n); self.changed.emit()
            except ValueError as e:
                QMessageBox.warning(self, "Имя", str(e))

    def save(self):
        n = self.lst.currentItem().text() if self.lst.currentItem() else ""
        if n:
            storage.write_list(n, self.edit.toPlainText()); self.edit.setPlainText(storage.read_list(n)); self.changed.emit()

    def delete(self):
        if self.lst.currentItem():
            storage.delete_list(self.lst.currentItem().text()); self.reload(); self.changed.emit()


class BlobsLuaPage(QWidget):
    changed = Signal()

    def __init__(self, state):
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        g1 = QGroupBox("--blob=имя:0xHEX  или  имя:@файл"); v1 = QVBoxLayout(g1)
        self.bt = QTableWidget(0, 2); self.bt.setHorizontalHeaderLabels(["Имя", "Значение (0xHEX или @/путь/к/файлу)"])
        self.bt.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch); v1.addWidget(self.bt)
        r = QHBoxLayout()
        for t, f in (("+ Блоб", lambda: self._add(self.bt)), ("Файл…", self._file), ("Удалить", lambda: self._del(self.bt))):
            b = QPushButton(t); b.clicked.connect(f); r.addWidget(b)
        v1.addLayout(r); lay.addWidget(g1)
        g2 = QGroupBox("Свои --lua-init (стандартные zapret-lib.lua и zapret-antidpi.lua подключаются автоматически)")
        v2 = QVBoxLayout(g2)
        self.lt = QTableWidget(0, 2); self.lt.setHorizontalHeaderLabels(["Тип: file | code", "Путь к файлу или Lua-код"])
        self.lt.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch); v2.addWidget(self.lt)
        r = QHBoxLayout()
        for t, f in (("+ Lua", lambda: self._add(self.lt, "file")), ("Удалить", lambda: self._del(self.lt))):
            b = QPushButton(t); b.clicked.connect(f); r.addWidget(b)
        v2.addLayout(r); lay.addWidget(g2)
        for b in state.blobs:
            self._add(self.bt, b.name, b.value, False)
        for l in state.luas:
            self._add(self.lt, l.kind, l.value, False)
        self.bt.itemChanged.connect(self._collect); self.lt.itemChanged.connect(self._collect)

    def _add(self, t, a="", b="", emit=True):
        t.blockSignals(True); r = t.rowCount(); t.insertRow(r)
        t.setItem(r, 0, QTableWidgetItem(a)); t.setItem(r, 1, QTableWidgetItem(b)); t.blockSignals(False)
        if emit:
            self._collect()

    def _del(self, t):
        if t.currentRow() >= 0:
            t.removeRow(t.currentRow()); self._collect()

    def _file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Файл блоба")
        if p:
            self._add(self.bt, "myblob", "@" + p)

    def _collect(self, *_):
        txt = lambda t, r, c: (t.item(r, c).text().strip() if t.item(r, c) else "")
        self.state.blobs = [Blob(txt(self.bt, r, 0), txt(self.bt, r, 1)) for r in range(self.bt.rowCount())]
        self.state.luas = [LuaInit(txt(self.lt, r, 0) or "file", txt(self.lt, r, 1)) for r in range(self.lt.rowCount())]
        self.changed.emit()


class ProfilesTab(QTabWidget):
    changed = Signal()

    def __init__(self, state):
        super().__init__()
        self.profiles = ProfilesPage(state); self.lists = ListsPage(); self.blobs = BlobsLuaPage(state)
        self.addTab(self.profiles, "Профили"); self.addTab(self.lists, "Хостлисты"); self.addTab(self.blobs, "Блобы и Lua")
        self.profiles.changed.connect(self.changed); self.blobs.changed.connect(self.changed)
        self.lists.changed.connect(lambda: (self.profiles.refresh_lists(), self.changed.emit()))
