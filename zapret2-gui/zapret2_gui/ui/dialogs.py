from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QComboBox, QLineEdit, QLabel,
                               QTableWidget, QTableWidgetItem, QPushButton, QDialogButtonBox, QMessageBox, QHeaderView)
from ..functions_db import FUNCS, PAYLOAD_TYPES
from ..models import Step
from ..validator import validate_desync, has_errors


class StepDialog(QDialog):
    """Редактор одного --lua-desync."""
    def __init__(self, step: Step, blob_names, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Инстанс --lua-desync")
        self.resize(640, 520)
        self.blob_names = set(blob_names)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.func = QComboBox(); self.func.setEditable(True)
        self.func.addItems(list(FUNCS)); self.func.setCurrentText(step.func)
        self.desc = QLabel(); self.desc.setWordWrap(True)
        self.payload = QComboBox(); self.payload.setEditable(True)
        self.payload.addItems([""] + PAYLOAD_TYPES); self.payload.setCurrentText(step.payload)
        self.inr = QLineEdit(step.in_range); self.inr.setPlaceholderText("напр. a  или  -d10  (пусто = как у предыдущего шага)")
        self.outr = QLineEdit(step.out_range); self.outr.setPlaceholderText("напр. -d10  или  n2-n6")
        form.addRow("Функция:", self.func); form.addRow("", self.desc)
        form.addRow("--payload:", self.payload); form.addRow("--in-range:", self.inr); form.addRow("--out-range:", self.outr)
        lay.addLayout(form)
        self.table = QTableWidget(0, 2); self.table.setHorizontalHeaderLabels(["Параметр", "Значение (пусто = флаг)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        for k, v in step.params:
            self._row(k, v)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        self.known = QComboBox(); self.known.setMinimumWidth(180)
        add_known = QPushButton("Добавить известный параметр"); add_empty = QPushButton("Пустая строка")
        rm = QPushButton("Удалить строку")
        for w in (self.known, add_known, add_empty, rm):
            row.addWidget(w)
        lay.addLayout(row)
        self.hint = QLabel(); self.hint.setWordWrap(True); lay.addWidget(self.hint)
        self.preview = QLineEdit(); self.preview.setReadOnly(True); lay.addWidget(self.preview)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel); lay.addWidget(bb)
        bb.accepted.connect(self._ok); bb.rejected.connect(self.reject)
        self.func.currentTextChanged.connect(self._func_changed)
        add_known.clicked.connect(self._add_known); add_empty.clicked.connect(lambda: self._row("", ""))
        rm.clicked.connect(lambda: self.table.removeRow(self.table.currentRow()))
        self.known.currentTextChanged.connect(self._show_hint)
        self.table.itemChanged.connect(self._update_preview)
        self.func.currentTextChanged.connect(self._update_preview)
        self._func_changed(step.func); self._update_preview()

    def _row(self, k, v):
        self.table.blockSignals(True)
        r = self.table.rowCount(); self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(k)); self.table.setItem(r, 1, QTableWidgetItem(v))
        self.table.blockSignals(False)
        self._update_preview()

    def _func_changed(self, name):
        spec = FUNCS.get(name)
        self.desc.setText(spec.desc if spec else "Нестандартная функция (из вашего --lua-init?). Параметры не проверяются по справочнику.")
        self.known.clear()
        if spec:
            self.known.addItems([p.name for p in spec.params])
        self._show_hint()

    def _show_hint(self, *_):
        spec = FUNCS.get(self.func.currentText())
        if spec:
            for p in spec.params:
                if p.name == self.known.currentText():
                    self.hint.setText(f"{p.name} ({p.kind}): {p.hint}")
                    return
        self.hint.setText("")

    def _add_known(self):
        if self.known.currentText():
            self._row(self.known.currentText(), "")

    def get_step(self) -> Step:
        params = []
        for r in range(self.table.rowCount()):
            k = (self.table.item(r, 0).text() if self.table.item(r, 0) else "").strip()
            v = (self.table.item(r, 1).text() if self.table.item(r, 1) else "").strip()
            if k:
                params.append([k, v])
        return Step(self.func.currentText().strip(), params, self.payload.currentText().strip(),
                    self.inr.text().strip(), self.outr.text().strip())

    def _update_preview(self, *_):
        self.preview.setText("--lua-desync=" + self.get_step().desync_arg())

    def _ok(self):
        s = self.get_step()
        issues = validate_desync(s.desync_arg(), self.blob_names, set())
        errs = [i for i in issues if i.level == "error"]
        warns = [i for i in issues if i.level == "warn"]
        if errs:
            QMessageBox.critical(self, "Ошибка параметров", "\n".join(i.msg for i in errs)); return
        if warns and QMessageBox.question(self, "Предупреждения", "\n".join(i.msg for i in warns) + "\n\nВсё равно сохранить?") != QMessageBox.Yes:
            return
        self.accept()
