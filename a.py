#!/usr/bin/env python3
"""
notebook_gui.py

یک برنامهٔ سادهٔ دفترچهٔ متنی با Tkinter
ویژگی‌ها:
- منوی File: New, Open, Save, Save As, Exit
- منوی Edit: Undo, Redo, Cut, Copy, Paste, Find
- منوی View: Toggle Wrap, Increase/Decrease Font Size
- وضعیت (status bar): تعداد کلمات و حروف
- میانبرهای کیبورد
- بدون وابستگی خارجی (فقط tkinter)
"""

import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, simpledialog, font

import os

APP_TITLE = "دفترچهٔ ساده"
DEFAULT_FONT_FAMILY = "Helvetica"
DEFAULT_FONT_SIZE = 12


class SimpleNotebook(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x600")

        # State
        self.filepath = None
        self.wrap_enabled = True
        self.font_family = DEFAULT_FONT_FAMILY
        self.font_size = DEFAULT_FONT_SIZE

        # Configure UI
        self._create_widgets()
        self._create_menus()
        self._bind_shortcuts()
        self._update_title()
        self._update_status()

    def _create_widgets(self):
        # Main frame
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Text widget with scrollbar
        text_frame = ttk.Frame(self)
        text_frame.grid(row=0, column=0, sticky="nsew")

        self.text_font = font.Font(family=self.font_family, size=self.font_size)
        self.text = tk.Text(
            text_frame,
            wrap="word" if self.wrap_enabled else "none",
            undo=True,
            font=self.text_font,
            relief="flat",
        )
        self.v_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=self.v_scroll.set)

        self.text.grid(row=0, column=0, sticky="nsew")
        self.v_scroll.grid(row=0, column=1, sticky="ns")

        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        # Status bar
        self.status_var = tk.StringVar()
        self.status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        self.status.grid(row=1, column=0, sticky="we")

        # Bind events to update status
        self.text.bind("<<Modified>>", self._on_modified)
        self.text.bind("<KeyRelease>", lambda e: self._update_status())

    def _create_menus(self):
        menubar = tk.Menu(self)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="جدید    Ctrl+N", command=self.new_file)
        file_menu.add_command(label="باز کردن    Ctrl+O", command=self.open_file)
        file_menu.add_command(label="ذخیره    Ctrl+S", command=self.save_file)
        file_menu.add_command(label="ذخیره به عنوان...", command=self.save_as)
        file_menu.add_separator()
        file_menu.add_command(label="خروج", command=self.on_exit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Undo    Ctrl+Z", command=lambda: self.text.event_generate("<<Undo>>"))
        edit_menu.add_command(label="Redo    Ctrl+Y", command=lambda: self.text.event_generate("<<Redo>>"))
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut    Ctrl+X", command=lambda: self.text.event_generate("<<Cut>>"))
        edit_menu.add_command(label="Copy    Ctrl+C", command=lambda: self.text.event_generate("<<Copy>>"))
        edit_menu.add_command(label="Paste    Ctrl+V", command=lambda: self.text.event_generate("<<Paste>>"))
        edit_menu.add_separator()
        edit_menu.add_command(label="Find    Ctrl+F", command=self.find_text)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Wrap", command=self.toggle_wrap)
        view_menu.add_command(label="Increase Font Size    Ctrl++", command=lambda: self.change_font_size(1))
        view_menu.add_command(label="Decrease Font Size    Ctrl+-", command=lambda: self.change_font_size(-1))
        menubar.add_cascade(label="View", menu=view_menu)

        # Help
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _bind_shortcuts(self):
        self.bind_all("<Control-n>", lambda e: self.new_file())
        self.bind_all("<Control-o>", lambda e: self.open_file())
        self.bind_all("<Control-s>", lambda e: self.save_file())
        self.bind_all("<Control-f>", lambda e: self.find_text())
        self.bind_all("<Control-plus>", lambda e: self.change_font_size(1))
        self.bind_all("<Control-minus>", lambda e: self.change_font_size(-1))

    # File operations
    def new_file(self):
        if self._confirm_discard_changes():
            self.text.delete("1.0", tk.END)
            self.filepath = None
            self._update_title()
            self._update_status()

    def open_file(self):
        if not self._confirm_discard_changes():
            return
        path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.text.delete("1.0", tk.END)
                self.text.insert("1.0", content)
                self.filepath = path
                self._update_title()
                self.text.edit_modified(False)
                self._update_status()
            except Exception as e:
                messagebox.showerror("خطا", f"باز کردن فایل ممکن نشد:\n{e}")

    def save_file(self):
        if self.filepath:
            self._write_to_path(self.filepath)
        else:
            self.save_as()

    def save_as(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self._write_to_path(path)
            self.filepath = path
            self._update_title()

    def _write_to_path(self, path):
        try:
            text = self.text.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.rstrip("\n"))
            self.text.edit_modified(False)
            self._update_status()
        except Exception as e:
            messagebox.showerror("خطا", f"ذخیرهٔ فایل ممکن نشد:\n{e}")

    def _confirm_discard_changes(self):
        if self.text.edit_modified():
            answer = messagebox.askyesnocancel("ذخیره تغییرات؟", "تغییراتی وجود دارد. ذخیره شود؟")
            if answer is None:
                return False
            if answer:
                self.save_file()
        return True

    def on_exit(self):
        if self._confirm_discard_changes():
            self.destroy()

    # Status, modified tracking
    def _on_modified(self, event=None):
        # Reset modified flag and update status
        self.text.edit_modified(False)
        self._update_status()
        self._update_title(dirty=True)

    def _update_title(self, dirty=False):
        name = os.path.basename(self.filepath) if self.filepath else "بدون نام"
        dirty_mark = "*" if self.text.edit_modified() else ""
        self.title(f"{name}{dirty_mark} - {APP_TITLE}")

    def _update_status(self):
        content = self.text.get("1.0", "end-1c")
        chars = len(content)
        words = len(content.split())
        line, col = self._get_cursor_line_col()
        self.status_var.set(f"خط: {line}    ستون: {col}    |    کلمات: {words}    حروف: {chars}")

    def _get_cursor_line_col(self):
        index = self.text.index(tk.INSERT)
        parts = index.split(".")
        return parts[0], parts[1]

    # Find dialog
    def find_text(self):
        FindDialog(self, self.text)

    # View options
    def toggle_wrap(self):
        self.wrap_enabled = not self.wrap_enabled
        self.text.config(wrap="word" if self.wrap_enabled else "none")

    def change_font_size(self, delta):
        self.font_size = max(6, self.font_size + delta)
        self.text_font.configure(size=self.font_size)

    def show_about(self):
        messagebox.showinfo("About", f"{APP_TITLE}\nنسخهٔ نمونه — ساخته شده با Tkinter")


class FindDialog(tk.Toplevel):
    def __init__(self, parent, text_widget):
        super().__init__(parent)
        self.title("Find")
        self.transient(parent)
        self.text_widget = text_widget
        self.geometry("350x80")
        self.resizable(False, False)

        self._build()
        self.bind("<Return>", lambda e: self.find_next())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="متن:").grid(row=0, column=0, sticky="w")
        self.query_var = tk.StringVar()
        self.entry = ttk.Entry(frm, textvariable=self.query_var, width=30)
        self.entry.grid(row=0, column=1, sticky="we", padx=6)
        self.entry.focus_set()

        self.case_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Case sensitive", variable=self.case_var).grid(row=1, column=0, sticky="w", pady=6)

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=0, column=2, rowspan=2, padx=4)
        ttk.Button(btn_frame, text="Find Next", command=self.find_next).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Close", command=self._on_close).pack(fill="x", pady=2)

    def find_next(self):
        query = self.query_var.get()
        if not query:
            return
        start_pos = self.text_widget.index(tk.INSERT)
        flags = "" if self.case_var.get() else "nocase"
        idx = self.text_widget.search(query, start_pos, nocase=not self.case_var.get(), stopindex=tk.END)
        if not idx:
            # try from top
            idx = self.text_widget.search(query, "1.0", nocase=not self.case_var.get(), stopindex=tk.END)
            if not idx:
                messagebox.showinfo("Find", "متن یافت نشد.")
                return
        end = f"{idx}+{len(query)}c"
        self.text_widget.tag_remove("find_match", "1.0", tk.END)
        self.text_widget.tag_add("find_match", idx, end)
        self.text_widget.tag_config("find_match", background="yellow")
        self.text_widget.mark_set(tk.INSERT, end)
        self.text_widget.see(idx)

    def _on_close(self):
        self.text_widget.tag_remove("find_match", "1.0", tk.END)
        self.destroy()


def main():
    app = SimpleNotebook()
    app.mainloop()


if __name__ == "__main__":
    main()