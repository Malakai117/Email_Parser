# ParserUI.py
# A PySide6 GUI application to manage parsing rules, run the email parser,
# and display a live-updating feed of captured billing data.

import sys
import os
import subprocess
import socket
import threading
import json
import yaml
import re
import time
import pandas as pd
from rulemaker import (
    add_provider,
    add_rule,
    remove_rule,
    remove_provider,
    create_initial_config,
    load_config,
    save_config,
)
from MyParser5 import (main as MyParser5)
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableView, QTextEdit, QFileDialog,
    QMessageBox, QComboBox, QSpinBox, QGroupBox, QFormLayout, QHeaderView,
    QProgressBar, QSplitter, QScrollArea
)
from PySide6.QtCore import Qt, QAbstractTableModel, QTimer, Signal, QObject
from PySide6.QtGui import QStandardItemModel, QStandardItem, QFont

# Paths (assuming all scripts are in the same directory as this UI)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FOLDER = os.path.join(SCRIPT_DIR, f"Pentex_Reports")
RULES_FOLDER = os.path.join(SCRIPT_DIR, "Parsing_Rules")
os.makedirs(RULES_FOLDER, exist_ok=True)  # Create folder if missing
# PARSER_SCRIPT = os.path.join(SCRIPT_DIR, "MyParser5.py")
# RULES_FILE = os.path.join(REPORT_FOLDER, "rules.yaml")

DEFAULT_CONFIG_NAME = "parsing_rules"  # Default filename inside folder


class Communicate(QObject):
    """Simple signal container for thread communication"""
    log_update = Signal(str)
    progress_update = Signal(int, int)  # current, total
    data_update = Signal(list)         # new rows
    finished = Signal(str)             # final message


class PandasModel(QAbstractTableModel):
    """Simple read-only table model for pandas DataFrame"""
    """
    A read-only Qt table model that wraps a pandas DataFrame for display in a QTableView.

    Purpose:
        Allows real-time display of captured billing data in the "Live Captured Billing Data" table.
        Efficiently handles dynamic updates when new rows are parsed and appended during parsing.

    Why this class exists:
        Qt's QTableView requires a model that inherits from QAbstractTableModel.
        Direct use of QStandardItemModel is slow and memory-heavy for growing datasets.
        This custom model is lightweight, supports large DataFrames, and updates efficiently.

    Key Features:
        - Read-only (users cannot edit cells)
        - Supports dynamic refresh (replace entire DataFrame efficiently)
        - Proper header display (column names from DataFrame)
        - Centered text alignment
        - Works seamlessly with pandas DataFrame (including mixed types: str, float, int)

    Usage in your project:
        Instantiated in ParserUI.init_ui():
            self.table_model = PandasModel()
            self.table_view.setModel(self.table_model)

        Updated in real-time via:
            self.table_model.refresh(self.df)
    """
    def __init__(self, dataframe=pd.DataFrame(), parent=None):
        """
        Initialize the model with an optional initial DataFrame.

        Args:
            dataframe (pd.DataFrame): Initial data to display (default: empty DataFrame)
            parent (QObject, optional): Parent object (usually None)
        """
        super().__init__(parent)
        self._dataframe = dataframe

    def rowCount(self, parent=None):
        return len(self._dataframe)

    def columnCount(self, parent=None):
        return len(self._dataframe.columns)

    def data(self, index, role=Qt.DisplayRole):
        """
        Return data for a given index and role.

        Supported roles:
            - Qt.DisplayRole: The actual value as string
            - Qt.TextAlignmentRole: Center-aligned text

        Args:
            index (QModelIndex): The cell index
            role (Qt.ItemDataRole): The role requested by the view

        Returns:
            str or int or None: Value for DisplayRole, alignment flag, or None
        """
        if not index.isValid():
            return None
        if role == Qt.DisplayRole or role == Qt.TextAlignmentRole:
            value = self._dataframe.iloc[index.row(), index.column()]
            return str(value) if role == Qt.DisplayRole else Qt.AlignCenter
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        """
        Return header text for columns (horizontal) or rows (vertical).

        Args:
            section (int): Column or row number
            orientation (Qt.Orientation): Horizontal for columns, Vertical for rows
            role (Qt.ItemDataRole): Usually DisplayRole

        Returns:
            str or None: Header text or None
        """
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return str(self._dataframe.columns[section])
            if orientation == Qt.Vertical:
                return str(self._dataframe.index[section])
        return None

    def refresh(self, new_df):
        """
        Efficiently replace the entire DataFrame with new data.

        This is the key method used for live updates.
        It triggers a full model reset (fast enough for hundreds/thousands of rows).

        How it's used in your code:
            self.df = pd.DataFrame(self.current_data)
            self.table_model.refresh(self.df)

        Args:
            new_df (pd.DataFrame): The new complete DataFrame to display
        """
        self.beginResetModel()
        self._dataframe = new_df
        self.endResetModel()


class ParserUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Utility Bill Email Parser")

        screen = QApplication.primaryScreen()
        screen_size = screen.availableGeometry()

        screen_width = screen_size.width()
        screen_height = screen_size.height()

        # Define desired proportions of the screen
        desired_width_ratio = 0.75
        desired_height_ratio = 0.75

        # Calculate window size
        window_width = int(screen_width * desired_width_ratio)
        window_height = int(screen_height * desired_height_ratio)


        self.resize(window_width, window_height)
        self.setMinimumSize(screen_width * .25, screen_height * .35)

        self.setup = self.setup(self)

        self.c = Communicate()
        self.c.log_update.connect(self.append_log)
        self.c.progress_update.connect(self.update_progress)
        self.c.data_update.connect(self.append_new_rows)
        self.c.finished.connect(self.on_parser_finished)

        self.current_data = []  # list of dicts for the DataFrame window
        self.df = pd.DataFrame() # set DataFrame as 'df'

        self.process = None  # Will hold the subprocess for potential future stop

        # make rules line here so we can use it as config directory
        self.config_edit = QComboBox()
        self.config_edit.setEditable(True)
        self.config_edit.setToolTip("Path to the rules YAML file (relative or absolute)")
        self.config_edit.currentTextChanged.connect(self.refresh_providers)


        self.init_ui()
    #=============Build The UI
    class setup:
        def __init__(self, ui):
            self.ui = ui   # short alias for the outer instance

        #============== Tab Logic


        #============== Tab #1
        def parser_config_group(self, parent_layout: QVBoxLayout):
            config_group = QGroupBox("Parser Configuration")
            config_layout = QFormLayout(config_group)

            self.ui.sender_edit = QLineEdit("Autofilled")
            self.ui.sender_edit.setReadOnly(True)
            self.ui.limit_spin = QSpinBox()
            self.ui.limit_spin.setRange(1, 10000)
            self.ui.limit_spin.setValue(200)

            self.ui.provider_combo = QComboBox()

            self.ui.provider_combo.currentTextChanged.connect(self.ui.update_sender_from_provider)

            config_layout.addRow("Sender email:", self.ui.sender_edit)
            config_layout.addRow("Max emails:", self.ui.limit_spin)
            config_layout.addRow("Provider:", self.ui.provider_combo)
            config_layout.addRow("Rules file:", self.ui.config_edit)


            parent_layout.addWidget(config_group)

        def run_buttons(self, parent_layout: QVBoxLayout):
            btn_layout = QHBoxLayout()
            self.ui.run_btn = QPushButton("Run Parser")
            self.ui.run_btn.clicked.connect(self.ui.start_parser)
            self.ui.stop_btn = QPushButton("Stop")
            self.ui.stop_btn.setEnabled(False)
            self.ui.stop_btn.clicked.connect(self.ui.stop_parser)

            btn_layout.addWidget(self.ui.run_btn)
            btn_layout.addWidget(self.ui.stop_btn)
            btn_layout.addStretch()

            parent_layout.addLayout(btn_layout)

        def progress_bar(self, parent_layout: QVBoxLayout):
            self.ui.progress_bar = QProgressBar()
            self.ui.progress_bar.setRange(0, 0)
            parent_layout.addWidget(self.ui.progress_bar)

        def live_feed_splitter(self, parent_layout: QVBoxLayout):
            # Splitter for log and data table
            # --------------------- DATA TABLE WITH TITLE ---------------------
            table_group = QGroupBox("Live Captured Billing Data")
            table_layout = QVBoxLayout(table_group)

            self.ui.table_view = QTableView()
            self.ui.table_model = PandasModel()
            self.ui.table_view.setModel(self.ui.table_model)
            self.ui.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.ui.table_view.setAlternatingRowColors(True)
            self.ui.table_view.setGridStyle(Qt.SolidLine)
            table_layout.addWidget(self.ui.table_view)

            # --------------------- LOG VIEWER WITH TITLE ---------------------
            log_group = QGroupBox("Parser Log Output")
            log_layout = QVBoxLayout(log_group)


            self.ui.log_text = QTextEdit()
            self.ui.log_text.setReadOnly(True)
            self.ui.log_text.setFont(QFont("Consolas", 9))
            self.ui.log_text.setFont(QFont("Consolas", 10))  # Slightly larger for better readability in dark

            # === DARK MODE STYLESHEET (professional & eye-friendly) ===
            self.ui.log_text.setStyleSheet("""
                QTextEdit {
                    background-color: #1e1e1e;     /* Deep dark grey (like VS Code) */
                    color: #d4d4d4;                /* Soft light grey text */
                    border: 1px solid #3f3f3f;
                    padding: 10px;
                    selection-background-color: #264f78;  /* Pleasant blue selection */
                    selection-color: white;
                    gridline-color: #3f3f3f;       /* Subtle grid if any */
                }
                QScrollBar:vertical {
                    background: #2d2d2d;
                    width: 12px;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #4a4a4a;
                    min-height: 20px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #5a5a5a;
                }
            """)

            self.ui.log_text.setViewportMargins(0, 0, 0, 0)

            log_layout.addWidget(self.ui.log_text)

            # --------------------- ADD TO SPLITTER ---------------------
            splitter = QSplitter(Qt.Vertical)
            splitter.addWidget(table_group)
            splitter.addWidget(log_group)
            splitter.setSizes([500, 500])

            parent_layout.addWidget(splitter, stretch=1)

        #============= Tab #2
        def rules_management_buttons(self, parent_layout: QVBoxLayout):
            rules_btn_layout = QHBoxLayout()
            init_btn = QPushButton("Reset to Initial Config")
            init_btn.clicked.connect(lambda: self.ui.run_rulemaker(["init"]))

            rules_btn_layout.addWidget(init_btn)
            rules_btn_layout.addStretch()

            parent_layout.addLayout(rules_btn_layout)

        def add_rule_inputs(self, parent_layout: QVBoxLayout):
            add_rule_group = QGroupBox("Add New Rule")
            add_rule_layout = QFormLayout(add_rule_group)

            self.ui.add_provider_input = QComboBox()
            self.ui.add_provider_input.setEditable(True)
            self.ui.add_provider_input.setPlaceholderText("Select or Add new Provider")

            self.ui.add_description_input = QLineEdit()
            self.ui.add_description_input.setPlaceholderText("Required only for New Provider")

            self.ui.add_email_input = QLineEdit()
            self.ui.add_email_input.setPlaceholderText("Provider's Email address")

            self.ui.add_label_input = QLineEdit()
            self.ui.add_label_input.setPlaceholderText("e.g. Account")

            self.ui.add_pattern_input = QLineEdit()
            self.ui.add_pattern_input.setPlaceholderText("e.g. ... (r'' not needed in ui)")

            self.ui.add_type_input = QComboBox()
            self.ui.add_type_input.addItem("str")
            self.ui.add_type_input.addItem("int")
            self.ui.add_type_input.addItem("float")
            self.ui.add_type_input.setCurrentIndex(0)

            add_rule_layout.addRow("Provider", self.ui.add_provider_input)
            add_rule_layout.addRow("Description", self.ui.add_description_input)
            add_rule_layout.addRow("Email", self.ui.add_email_input)
            add_rule_layout.addRow("Label", self.ui.add_label_input)
            add_rule_layout.addRow("Pattern", self.ui.add_pattern_input)
            add_rule_layout.addRow("Type", self.ui.add_type_input)

            button_layout = QHBoxLayout()

            add_rule_btn = QPushButton("Add Rule")
            add_rule_btn.clicked.connect(self.ui.add_rule_from_ui)  # make an add rule function to put here

            add_provider_btn = QPushButton("Add New Provider")
            add_provider_btn.clicked.connect(self.ui.add_provider_from_ui)

            remove_rule_btn = QPushButton("Remove Rule")
            remove_rule_btn.clicked.connect(self.ui.remove_rule_from_ui)

            remove_provider_btn = QPushButton("Remove Provider")
            remove_provider_btn.clicked.connect(self.ui.remove_provider_from_ui)

            button_layout.addWidget(add_rule_btn)
            button_layout.addWidget(add_provider_btn)
            button_layout.addWidget(remove_rule_btn)
            button_layout.addWidget(remove_provider_btn)
            button_layout.addStretch()

            add_rule_layout.addRow(button_layout)

            parent_layout.addWidget(add_rule_group)
            # Populate provider combo after widget creation
            self.ui.refresh_provider_input()

        def rules_editor(self, parent_layout: QVBoxLayout):
            self.ui.rules_text = QTextEdit()
            self.ui.rules_text.setFont(QFont("Consolas", 10))
            self.ui.load_rules_into_editor()
            parent_layout.addWidget(self.ui.rules_text)

            save_rules_btn = QPushButton("Save Rules & Refresh Providers")
            save_rules_btn.clicked.connect(self.ui.save_rules)
            parent_layout.addWidget(save_rules_btn)



    def setup_run_tab(self, tabs: QTabWidget):
        run_tab = QWidget()
        run_layout = QVBoxLayout(run_tab)

        self.setup.parser_config_group(run_layout)
        self.setup.run_buttons(run_layout)
        self.setup.progress_bar(run_layout)
        self.setup.live_feed_splitter(run_layout)
        self.refresh_providers()

        tabs.addTab(run_tab, "Run & Feed")

    def setup_rules_tab(self, tabs: QTabWidget):
        rules_tab = QWidget()
        rules_layout = QVBoxLayout(rules_tab)

        self.setup.rules_management_buttons(rules_layout)
        self.setup.add_rule_inputs(rules_layout)
        self.setup.rules_editor(rules_layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(rules_tab)

        tabs.addTab(scroll_area, "Edit Rules")

    #=============Run The UI
    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # =============== This is where we will build the Tabs ==================
        tabs = QTabWidget()
        main_layout.addWidget(tabs, stretch=1)

        self.setup_run_tab(tabs)
        self.setup_rules_tab(tabs)
        self.refresh_config_edit()

        tabs.currentChanged.connect(self.on_tab_change)


    #==============Functions for UI

    def on_tab_change(self, index):
        if index == 0:  # Tab #1 Run & Feed
            self.update_sender_from_provider
            # self.append_log("tab 1 refreshed")


        elif index == 1:  # Tab #2 Rule Editor Tab
            self.refresh_provider_input
            self.load_rules_into_editor()
            # self.append_log("tab 2 refreshed")

    def refresh_config_edit(self):
        if not hasattr(self, 'config_edit'):
            return

        # Remember current selection/typed text
        current_text = self.config_edit.currentText().strip()

        self.config_edit.blockSignals(True)  # Prevent unwanted triggers
        self.config_edit.clear()

        try:
            files = []
            if os.path.exists(RULES_FOLDER):
                files = [f for f in os.listdir(RULES_FOLDER) if f.lower().endswith(('.yaml', '.yml'))]
                files.sort(key=str.lower)
            self.config_edit.addItems(files)

            # Ensure the currently used file is in the list (even if just typed/created)
            active_filename = os.path.basename(self.current_config_path())
            if active_filename not in [self.config_edit.itemText(i) for i in range(self.config_edit.count())]:
                self.config_edit.addItem(active_filename)

            # Restore selection
            self.config_edit.setCurrentText(active_filename)

        except Exception as e:
            self.append_log(f"Error refreshing config list: {e}")
        finally:
            self.config_edit.blockSignals(False)

    def refresh_providers(self):
        self.provider_combo.clear()
        config_path = self.current_config_path()

        if not os.path.exists(config_path):
            self.append_log(f"Config file not found: {config_path}")
            self.provider_combo.addItem("No Providers")
            return


        try:
            with open(config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}

            providers = list(config.keys())
            self.append_log(f"Loaded providers: {providers or None}")

            if providers:
                self.provider_combo.addItems(providers)
            else:
                self.provider_combo.addItem("No providers")

        except yaml.YAMLError as e:
            self.append_log(f"YAML parsing error in {config_path}: {e}")
            self.provider_combo.addItem("Invalid YAML")
        except Exception as e:
            self.append_log(f"Error refreshing provider list: {e}")
            self.provider_combo.addItem("Error Loading Providers")

    def refresh_provider_input(self):
        self.add_provider_input.clear()
        if os.path.exists(self.current_config_path()):
            try:
                with open(self.current_config_path(), "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
                self.add_provider_input.addItems(config.keys())
            except Exception as e:
                self.append_log(f"Error loading providers_input: {e}")

        if self.add_provider_input.count() == 0:
            self.add_provider_input.addItem("No Providers")

    def load_rules_into_editor(self):
        if os.path.exists(self.current_config_path()):
            try:
                with open(self.current_config_path(), "r", encoding="utf-8") as f:
                    content = f.read()
                self.rules_text.setPlainText(content)
            except Exception as e:
                self.rules_text.setPlainText(f"# Error reading file: {e}")
        else:
            self.rules_text.setPlainText("# parsing_rules.yaml not found")

    def update_sender_from_provider(self):
        """Update the sender_edit field based on the currently selected provider."""
        provider = self.provider_combo.currentText().strip()
        if not provider:
            self.sender_edit.clear()
            return

        config_path = self.current_config_path()
        if not os.path.exists(config_path):
            self.sender_edit.clear()
            return

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

            provider_config = config.get(provider)
            if provider_config and 'email' in provider_config:
                sender_email = provider_config['email']
                self.sender_edit.setText(sender_email)
                self.sender_edit.setToolTip(f"Sender email from {provider} config")
            else:
                self.sender_edit.clear()
                self.sender_edit.setToolTip("No 'email' defined for this provider")

        except Exception as e:
            self.append_log(f"Error reading sender email for {provider}: {e}")
            self.sender_edit.clear()


    #==============Functions for the Operations

    def current_config_filename(self) -> str:
        """Get the filename (selected or typed) from the combo."""
        text = self.config_edit.currentText().strip()
        if not text:
            text = DEFAULT_CONFIG_NAME
        if not text.lower().endswith(('.yaml', '.yml')):
            text += ".yaml"
        return text

    def current_config_path(self) -> str:
        """Full path to the currently selected/typed config file."""
        filename = self.current_config_filename()
        return os.path.join(RULES_FOLDER, filename)

    def add_rule_from_ui(self):
        """Handle the 'Add Rule' button click."""
        provider = self.add_provider_input.currentText().strip()
        label = self.add_label_input.text().strip()
        pattern = self.add_pattern_input.text().strip()
        type_ = self.add_type_input.currentText()
        config_path = self.current_config_path()

        try:
            add_rule(
                provider=provider,
                label=label,
                pattern=pattern,
                type_=type_,
                config_file=config_path,
            )

            self.append_log(f"Successfully added rule '{label}' to provider '{provider}'")
            self.load_rules_into_editor()
            self.refresh_providers()  # updates the Run tab combo
            self.refresh_provider_input()  # updates this tab's combo
            self.refresh_config_edit()

            # Clear rule-specific fields
            self.add_provider_input.clear()
            self.add_description_input.clear()
            self.add_email_input.clear()
            self.add_label_input.clear()
            self.add_pattern_input.clear()
            self.add_type_input.setCurrentIndex(0)


        except re.error as e:
            QMessageBox.critical(self, "Invalid Regex", f"The pattern is not a valid regular expression:\n{e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add rule:\n{e}")

    def add_provider_from_ui(self):
        """Handle the 'Add Rule' button click."""
        provider = self.add_provider_input.currentText().strip()
        description = self.add_description_input.text().strip()
        label = self.add_label_input.text().strip()
        pattern = self.add_pattern_input.text().strip()
        type_ = self.add_type_input.currentText()
        email = self.add_email_input.text().strip()
        config_path = self.current_config_path()


        if label:
            try:
                add_provider(
                    provider=provider,
                    description=description,
                    email=email,
                    rules=[
                        {"label": label,"pattern": pattern,"type": type_}
                    ],
                    config_file=config_path,
                )
                self.append_log(f"Successfully added rule '{label}' to provider '{provider}'")
            except re.error as e:
                QMessageBox.critical(self, "Invalid Regex", f"The pattern is not a valid regular expression:\n{e}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add provider:\n{e}")
        else:
            try:
                add_provider(
                    provider=provider,
                    description=description,
                    email=email,
                    rules=[],
                    config_file=config_path,
                )
                self.append_log(f"Successfully added provider '{provider}'")
            except re.error as e:
                QMessageBox.critical(self, "Invalid Regex", f"The pattern is not a valid regular expression:\n{e}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add rule:\n{e}")


            self.load_rules_into_editor()
            self.refresh_providers()  # updates the Run tab combo
            self.refresh_provider_input()  # updates this tab's combo
            self.refresh_config_edit()


            # Clear rule-specific fields
            self.add_provider_input.clear()
            self.add_description_input.clear()
            self.add_email_input.clear()
            self.add_label_input.clear()
            self.add_pattern_input.clear()
            self.add_type_input.setCurrentIndex(0)

    def remove_provider_from_ui(self):
        provider = self.add_provider_input.currentText().strip()
        config_path = self.current_config_path()

        try:
            remove_provider(provider, config_path)
        except Exception as e:
            QMessageBox.critical(self, "Invalid Provider", f"Could not remove provider:\n{e}")

        self.append_log(f"Successfully removed provider '{provider}'")
        self.load_rules_into_editor()
        self.refresh_providers()  # updates the Run tab combo
        self.refresh_provider_input()  # updates this tab's combo
        self.refresh_config_edit()

        # Clear rule-specific fields
        self.add_provider_input.clear()
        self.add_description_input.clear()
        self.add_email_input.clear()
        self.add_label_input.clear()
        self.add_pattern_input.clear()
        self.add_type_input.setCurrentIndex(0)

    def remove_rule_from_ui(self):
        provider = self.add_provider_input.currentText().strip()
        label = self.add_label_input.text().strip()
        config_path = self.current_config_path()

        try:
            remove_rule(provider, label, config_path)
        except Exception as e:
            QMessageBox.critical(self, "Invalid Rule", f"Could not remove rule:\n{e}")

        self.append_log(f"Successfully removed rule '{label}' to provider '{provider}'")
        self.load_rules_into_editor()
        self.refresh_providers()  # updates the Run tab combo
        self.refresh_provider_input()  # updates this tab's combo
        self.refresh_config_edit()

        # Clear rule-specific fields
        self.add_provider_input.clear()
        self.add_description_input.clear()
        self.add_email_input.clear()
        self.add_label_input.clear()
        self.add_pattern_input.clear()
        self.add_type_input.setCurrentIndex(0)

    def save_rules(self):
        try:
            yaml.safe_load(self.rules_text.toPlainText())  # basic validation
            with open(self.current_config_path(), "w", encoding="utf-8") as f:
                f.write(self.rules_text.toPlainText())
            self.append_log("Rules saved successfully.")
            self.refresh_providers()
            self.refresh_config_edit()

        except Exception as e:
            QMessageBox.critical(self, "Invalid YAML", f"Could not save rules:\n{e}")

    def run_rulemaker(self, args):
        config_path = self.current_config_path()
        try:
            create_initial_config(config_path)
            self.load_rules_into_editor()
            self.refresh_providers()
            self.refresh_config_edit()

        except Exception as e:
            self.append_log(f"Error running rulemaker: {e}")

    def append_log(self, text):
        self.log_text.append(text.strip())

    def append_new_rows(self, new_rows):
        if new_rows:
            self.current_data.extend(new_rows)
            self.df = pd.DataFrame(self.current_data)

            # Force model reset and view update
            self.table_model.refresh(self.df)

            # NEW: Ensure the view scrolls to the bottom and repaints
            QApplication.processEvents()  # Safe here since called from signal
            self.table_view.scrollToBottom()

    def update_progress(self, current, total):
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
        else:
            self.progress_bar.setRange(0, 0)


    def on_parser_finished(self, message):
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.append_log(message)

    #===============Primary/Critical services
    def socket_listener(self, port=12345):
        buffer = ""
        client = None

        # Connect (with retry)
        while not client:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(('127.0.0.1', port))
                self.c.log_update.emit("Connected to parser – receiving live data")
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)
                continue

        client.setblocking(False)  # IMPORTANT: Non-blocking mode

        try:
            while True:
                try:
                    data = client.recv(4096)
                    if not data:  # Connection closed by parser
                        self.c.log_update.emit("Parser closed connection.")
                        break

                    buffer += data.decode('utf-8', errors='replace')

                    # Process all complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            msg = json.loads(line)
                            if msg["type"] == "progress":
                                self.c.progress_update.emit(msg["current"], msg["total"])
                            elif msg["type"] == "data":
                                self.c.data_update.emit([msg["row"]])
                            elif msg["type"] == "log":
                                self.c.log_update.emit(msg["message"])
                        except json.JSONDecodeError:
                                # Fallback: treat non-JSON lines as log (in case of errors)
                                self.c.log_update.emit(line)

                except BlockingIOError:
                    # No data ready — normal in non-blocking mode
                    pass
                except ConnectionResetError:
                    self.c.log_update.emit("Connection lost.")
                    break
                except Exception as e:
                    self.c.log_update.emit(f"Socket error {e}")
                    break

                time.sleep(0.01)  # Tiny sleep to avoid 100% CPU

        finally:
            if client:
                client.close()
            self.c.finished.emit("Live feed ended.")

    def start_parser(self):
        """
        This method is triggered when you click the "Run Parser" button in the UI.
        Its job is to prepare everything and then launch your MyParser5.py script
        in the background (without freezing the GUI).
        """
        #1 set the provider for ----
        provider = self.provider_combo.currentText().strip()
        if not provider or provider == 'No Providers':
            QMessageBox.warning(self, "Error", "No provider selected")
            return

        # 3. Prepare the UI for a long-running task
        self.run_btn.setEnabled(False)  # Disable "Run" button so user can't click it again
        self.stop_btn.setEnabled(True)  # Enable "Stop" button (placeholder for future kill feature)

        # Clear any previous results
        self.current_data.clear()  # Empty the list that holds parsed rows
        self.table_model.refresh(pd.DataFrame())  # Clear the table view
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)

        # This log line shows you exactly what command is being executed
        self.append_log(f"Starting parser for provider '{provider}' (limit: {self.limit_spin.value()})")
        # self.append_log(f"Launching: python {PARSER_SCRIPT} {' '.join(args)}")

        # start listening for progress server on its own thread before running parser thread
        self.socket_thread = threading.Thread(
            target=self.socket_listener,
            daemon=True
        )
        self.socket_thread.start()

        # 4. Start the actual parsing work in a separate thread
        self.parser_thread = threading.Thread(
            target=self.run_parser_thread,
            daemon=True
        )
        self.parser_thread.start()
        #self.c.log_update.emit("Parser started")  # both seem to work, must figure out difference
        self.append_log("Parser started")

        # As soon as .start() is called, this method (start_parser) finishes immediately,
        # and the UI stays responsive while the background thread does the heavy work.

    def run_parser_thread(self):
        self.process = None
        limit = self.limit_spin.value()
        provider = self.provider_combo.currentText().strip()
        config_path = self.current_config_path()
        try:
            #cmd = ["python", PARSER_SCRIPT] + args
            self.process = subprocess.Popen(
                MyParser5(limit, provider, config_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                errors='replace'
            )

            for line in self.process.stdout:
                line = line.rstrip()
                if line and not line.startswith("{"): # filters out the debug prints
                    if "Found" in line or "Loaded" in line or "Processing" in line or "Exported" in line:
                        self.c.log_update.emit(line)

            self.process.wait()
            return_code = self.process.returncode
            if return_code == 0:
                self.c.log_update.emit("Parsing finished.")
            else:
                self.c.log_update.emit(f"Parser failed with return code {return_code}")

        except Exception as e:
            self.c.log_update.emit(f"Parser failed with exception {e}")
        finally:
            self.process = None
            # Signal completion (in case socket disconnected early)
            QTimer.singleShot(1000, lambda: self.c.finished.emit("Parsing complete."))

    def stop_parser(self):
        # Subprocess termination is tricky on all platforms; for simplicity just warn
        QMessageBox.information(self, "Stop", "Stop not fully implemented – close the app if needed.")
        # In a production version you would track the subprocess and kill it


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion") # Clean, scalable style (better than Windows default on high-DPI)
    window = ParserUI()
    window.show()
    sys.exit(app.exec())
