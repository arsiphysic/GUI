#!/usr/bin/env python3
"""
serial_terminal.py

Serial port terminal GUI (Tkinter + pyserial)

This version restores the Full_Self_Test set of action buttons that were present in the earlier
version (Full_Self_Test, Fire, Self_Test, Save Sent, Save Received, Clear All, Clear Received, Clear Sent,
Save Log (combined), Stop All, etc.). It also keeps:
- vertical split view (Received | Sent)
- Time Interval in milliseconds (live update)
- repeat (Full_Self_Test/Fire/Self_Test) with indicators
- input validation for Vc, H and Time Interval
- Save/Clear helpers for each pane and combined save
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import queue
import time
import sys

try:
    import serial
    import serial.tools.list_ports
except Exception:
    serial = None  # handle later

APP_TITLE = "F4_180_S | Serial Terminal"
DEFAULT_ENCODING = "utf-8"

COMMON_BAUDRATES = [
    "300", "1200", "2400", "4800", "9600", "14400", "19200", "38400", "57600", "115200", "230400", "460800",
    "921600"
]
DATA_BITS = ["5", "6", "7", "8"]
PARITIES = ["N", "E", "O", "M", "S"]
STOP_BITS = ["1", "1.5", "2"]
FLOW_CONTROLS = ["None", "RTS/CTS", "XON/XOFF"]

READ_TIMEOUT = 0.1  # seconds


def crc16_ccitt_false(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    crc = init
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) & 0xFFFF) ^ poly
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


class SerialTerminal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x720")  # default larger window

        # Serial
        self.serial_port = None
        self.reader_thread = None
        self.alive = threading.Event()
        self.rx_queue = queue.Queue()

        # UI state
        self.encoding = DEFAULT_ENCODING
        self.show_hex = tk.BooleanVar(value=False)
        self.show_timestamp = tk.BooleanVar(value=False)
        self.append_newline = tk.BooleanVar(value=False)
        self.send_as_hex = tk.BooleanVar(value=False)

        # Fire controls
        self.ready_var = tk.BooleanVar(value=False)
        self.tar_det_var = tk.BooleanVar(value=False)
        self.exp_var = tk.BooleanVar(value=False)
        self.vc_var = tk.StringVar(value="0")
        self.h_var = tk.StringVar(value="0")

        # Time interval ms
        self.time_interval_var = tk.StringVar(value="0")

        # Repeat state
        self._repeat_after_ids = {"Full_Self_Test": None, "Fire": None, "Self_Test": None}
        self._repeat_running = {"Full_Self_Test": False, "Fire": False, "Self_Test": False}

        # Build UI
        self._setup_style()
        self._build_widgets()
        self._bind_shortcuts()

        # init
        self.refresh_ports()
        self.after(100, self._process_rx_queue)

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 11, "bold"))

    def _build_widgets(self):
        # Top bar
        top_frame = ttk.Frame(self, padding=(8, 8))
        top_frame.pack(fill="x", side="top")

        ttk.Label(top_frame, text="Port:", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.port_cb = ttk.Combobox(top_frame, width=18, state="readonly")
        self.port_cb.grid(row=0, column=1, sticky="w", padx=(6, 8))
        ttk.Button(top_frame, text="Refresh", command=self.refresh_ports).grid(row=0, column=2, sticky="w")

        ttk.Label(top_frame, text="Baud:", style="Title.TLabel").grid(row=0, column=3, sticky="w", padx=(12, 0))
        self.baud_cb = ttk.Combobox(top_frame, values=COMMON_BAUDRATES, width=12, state="readonly")
        self.baud_cb.set("115200")
        self.baud_cb.grid(row=0, column=4, sticky="w", padx=(6, 8))

        ttk.Label(top_frame, text="Data bits:").grid(row=0, column=5, sticky="w")
        self.data_bits_cb = ttk.Combobox(top_frame, values=DATA_BITS, width=6, state="readonly")
        self.data_bits_cb.set("8")
        self.data_bits_cb.grid(row=0, column=6, sticky="w", padx=(6, 8))

        ttk.Label(top_frame, text="Parity:").grid(row=0, column=7, sticky="w")
        self.parity_cb = ttk.Combobox(top_frame, values=PARITIES, width=6, state="readonly")
        self.parity_cb.set("N")
        self.parity_cb.grid(row=0, column=8, sticky="w", padx=(6, 8))

        ttk.Label(top_frame, text="Stop bits:").grid(row=0, column=9, sticky="w")
        self.stop_bits_cb = ttk.Combobox(top_frame, values=STOP_BITS, width=6, state="readonly")
        self.stop_bits_cb.set("1")
        self.stop_bits_cb.grid(row=0, column=10, sticky="w", padx=(6, 8))

        ttk.Label(top_frame, text="Flow:").grid(row=0, column=11, sticky="w")
        self.flow_cb = ttk.Combobox(top_frame, values=FLOW_CONTROLS, width=12, state="readonly")
        self.flow_cb.set("None")
        self.flow_cb.grid(row=0, column=12, sticky="w", padx=(6, 8))

        self.open_btn = ttk.Button(top_frame, text="Open", command=self.toggle_port, width=10)
        self.open_btn.grid(row=0, column=13, padx=(8, 0))

        # Main area
        main_frame = ttk.Frame(self, padding=(8, 6))
        main_frame.pack(fill="both", expand=True)

        logs_container = ttk.Labelframe(main_frame, text="Logs", padding=(3, 3))
        logs_container.pack(side="left", fill="both", expand=True, padx=(0, 4), pady=(0, 3))

        paned = ttk.Panedwindow(logs_container, orient="vertical")
        paned.pack(fill="both", expand=True)

        # Sent pane
        sent_frame = ttk.Labelframe(paned, text="Sent", padding=(0, 0))
        self.tx_text = ScrolledText(sent_frame, wrap="none", state="normal", height=5)
        self.tx_text.pack(fill="both", expand=True)
        self.tx_text.configure(font=("Consolas", 12), background="#ffffff", foreground="#000000", insertbackground="black")
        self.tx_text.tag_configure("sent", foreground="#0033aa")
        self.tx_text.tag_configure("sent_ts", foreground="#666666", font=("Segoe UI", 8))
        paned.add(sent_frame, weight=2)

        # Received pane
        recv_frame = ttk.Labelframe(paned, text="Received", padding=(0, 0))
        self.rx_text = ScrolledText(recv_frame, wrap="none", state="normal", height=5)
        self.rx_text.pack(fill="both", expand=True)
        self.rx_text.configure(font=("Consolas", 12), background="#ffffff", foreground="#000000", insertbackground="black")
        paned.add(recv_frame, weight=2)



        # Right controls
        right_frame = ttk.Frame(main_frame, width=240)
        right_frame.pack(side="right", fill="both")

        actions_frame = ttk.Frame(right_frame)
        actions_frame.pack(fill="x", pady=(0, 6))
        ttk.Label(actions_frame, text="Actions:", style="Title.TLabel").grid(row=0, column=0, sticky="w")

        top_buttons = ttk.Frame(actions_frame)
        top_buttons.grid(row=0, column=1, sticky="e")
        # Restore full set of action buttons
        # ttk.Button(top_buttons, text="Refresh", command=self.refresh_ports).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(top_buttons, text="Clear Received", command=self.clear_received).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(top_buttons, text="Clear Sent", command=self.clear_sent).grid(row=0, column=1, padx=(0, 6))
        # ttk.Button(top_buttons, text="Clear All", command=self._clear_all).grid(row=0, column=3, padx=(0, 6))
        ttk.Button(top_buttons, text="Save Received", command=self.save_received).grid(row=1, column=0, padx=(0, 6))
        ttk.Button(top_buttons, text="Save Sent", command=self.save_sent).grid(row=1, column=1, padx=(0, 6))
        # ttk.Button(top_buttons, text="Save Log", command=self.save_log_all).grid(row=1, column=2, padx=(0, 6))
        ttk.Button(top_buttons, text="Stop All", command=self._stop_all).grid(row=1, column=3, padx=(6, 0))

        # action buttons (Full_Self_Test / Fire / Self_Test)
        btn_frame = ttk.Frame(actions_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="we", pady=(6, 0))
        btn_frame.columnconfigure((0, 1, 2), weight=1)

        # Self_Test
        right_col = ttk.Frame(btn_frame)
        right_col.grid(row=1, column=0, sticky="we")
        self.self_btn = tk.Button(right_col, text="Self_Test", bg="#007bff", fg="white", activebackground="#0069d9",
                                  command=self._toggle_repeat_self)
        self.self_btn.pack(fill="x")
        self.self_ind = tk.Label(right_col, text="OFF", bg="#cccccc", width=4)
        self.self_ind.pack(pady=(4, 0))

        # Full_Self_Test
        left_col = ttk.Frame(btn_frame)
        left_col.grid(row=1, column=1, sticky="we", padx=(0, 6))
        self.full_btn = tk.Button(left_col, text="Full_Self_Test", bg="#28a745", fg="white", activebackground="#1e7e34",
                                  command=self._toggle_repeat_full)
        self.full_btn.pack(fill="x")
        self.full_ind = tk.Label(left_col, text="OFF", bg="#cccccc", width=4)
        self.full_ind.pack(pady=(4, 0))

        # Fire
        mid_col = ttk.Frame(btn_frame)
        mid_col.grid(row=1, column=2, sticky="we", padx=(0, 6))
        self.fi_btn = tk.Button(mid_col, text="Fire", bg="#d9534f", fg="white", activebackground="#c43d3d",
                                command=self._toggle_repeat_fi)
        self.fi_btn.pack(fill="x")
        self.fi_ind = tk.Label(mid_col, text="OFF", bg="#cccccc", width=4)
        self.fi_ind.pack(pady=(4, 0))



        # Fire options
        fi_frame = ttk.Labelframe(right_frame, text="Fire packet options", padding=(8, 8))
        fi_frame.pack(fill="x", pady=(6, 6))

        vcmd = (self.register(self._validate_uint16), "%P", "%W")
        ttk.Label(fi_frame, text="Vc (0..65535):").grid(row=0, column=0, sticky="w")
        self.vc_entry = ttk.Entry(fi_frame, textvariable=self.vc_var, validate="key", validatecommand=vcmd, width=14)
        self.vc_entry.grid(row=0, column=1, sticky="e", padx=(8, 0))

        ttk.Label(fi_frame, text="H (0..65535):").grid(row=1, column=0, sticky="w")
        self.h_entry = ttk.Entry(fi_frame, textvariable=self.h_var, validate="key", validatecommand=vcmd, width=14)
        self.h_entry.grid(row=1, column=1, sticky="e", padx=(8, 0))

        tcmd = (self.register(self._validate_nonneg_int), "%P", "%W")
        ttk.Label(fi_frame, text="Time Interval (ms):").grid(row=2, column=0, sticky="w")
        self.time_interval_entry = ttk.Entry(fi_frame, textvariable=self.time_interval_var, validate="key",
                                             validatecommand=tcmd, width=14)
        self.time_interval_entry.grid(row=2, column=1, sticky="e", padx=(8, 0))
        ttk.Label(fi_frame, text="0 -> send once").grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

        cb_frame = ttk.Frame(fi_frame)
        cb_frame.grid(row=4, column=0, columnspan=2, pady=(6, 0))
        ttk.Checkbutton(cb_frame, text="Ready", variable=self.ready_var).grid(row=0, column=0, sticky="w", padx=2)
        ttk.Checkbutton(cb_frame, text="Tar_Det", variable=self.tar_det_var).grid(row=0, column=1, sticky="w", padx=2)
        ttk.Checkbutton(cb_frame, text="Exp", variable=self.exp_var).grid(row=0, column=2, sticky="w", padx=2)

        # Options
        opts_frame = ttk.Frame(right_frame)
        opts_frame.pack(fill="x", pady=(6, 6))
        ttk.Checkbutton(opts_frame, text="Show HEX", variable=self.show_hex).grid(row=0, column=0, sticky="w", padx=2)
        ttk.Checkbutton(opts_frame, text="Timestamps", variable=self.show_timestamp).grid(row=0, column=1, sticky="w",
                                                                                          padx=2)

        # Bottom send box
        bottom_frame = ttk.Frame(self, padding=(8, 8))
        bottom_frame.pack(fill="x", side="bottom")

        ttk.Label(bottom_frame, text="Send:", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.send_entry = ttk.Entry(bottom_frame)
        self.send_entry.grid(row=0, column=1, sticky="we", padx=(8, 8))
        bottom_frame.columnconfigure(1, weight=1)

        self.append_newline_cb = ttk.Checkbutton(bottom_frame, text="Append \\n", variable=self.append_newline)
        self.append_newline_cb.grid(row=0, column=2, padx=(0, 8))

        self.send_hex_cb = ttk.Checkbutton(bottom_frame, text="Send as HEX", variable=self.send_as_hex)
        self.send_hex_cb.grid(row=0, column=3, padx=(0, 8))

        send_btn = ttk.Button(bottom_frame, text="Send", command=self.send_data, width=14)
        send_btn.grid(row=0, column=4)

        # Status bar
        self.status_var = tk.StringVar(value="Closed")
        status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        status.pack(fill="x", side="bottom", ipady=2)

    # Validation helpers
    def _validate_uint16(self, new_value: str, widget_name: str) -> bool:
        if new_value == "":
            return True
        try:
            v = int(new_value)
            return 0 <= v <= 0xFFFF
        except Exception:
            self.bell()
            return False

    def _validate_nonneg_int(self, new_value: str, widget_name: str) -> bool:
        if new_value == "":
            return True
        try:
            v = int(new_value)
            return v >= 0
        except Exception:
            self.bell()
            return False

    # Shortcuts
    def _bind_shortcuts(self):
        self.bind_all("<Control-Shift-R>", lambda e: self.refresh_ports())
        self.bind_all("<Control-Return>", lambda e: self.send_data())
        try:
            self.protocol("WM_DELETE_WINDOW", self.on_close)
        except Exception:
            pass

    # Serial handling
    def refresh_ports(self):
        ports = []
        if serial:
            ports_info = serial.tools.list_ports.comports()
            ports = [p.device for p in ports_info]
        if not ports:
            ports = ["(no ports)"]
        self.port_cb['values'] = ports
        if ports and ports[0] != "(no ports)":
            self.port_cb.set(ports[0])
        else:
            self.port_cb.set("")

    def toggle_port(self):
        if self.serial_port and getattr(self.serial_port, "is_open", False):
            self.close_port()
        else:
            self.open_port()

    def open_port(self):
        if not serial:
            messagebox.showerror("Dependency missing", "pyserial is not installed. Install with:\n\npip install pyserial")
            return

        port = self.port_cb.get()
        if not port or port == "(no ports)":
            messagebox.showwarning("Port", "No serial port selected.")
            return
        try:
            baud = int(self.baud_cb.get())
            bytesize = int(self.data_bits_cb.get())
            parity = self.parity_cb.get()
            stopbits_val = float(self.stop_bits_cb.get())
        except Exception as e:
            messagebox.showerror("Settings", f"Invalid serial settings: {e}")
            return

        parity_map = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD,
                      "M": serial.PARITY_MARK, "S": serial.PARITY_SPACE}
        parity_val = parity_map.get(parity, serial.PARITY_NONE)

        stop_map = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE, "2": serial.STOPBITS_TWO}
        stopbits = stop_map.get(self.stop_bits_cb.get(), serial.STOPBITS_ONE)

        rtscts = False
        xonxoff = False
        flow = self.flow_cb.get()
        if flow == "RTS/CTS":
            rtscts = True
        elif flow == "XON/XOFF":
            xonxoff = True

        try:
            self.serial_port = serial.Serial(
                port=port,
                baudrate=baud,
                bytesize=bytesize,
                parity=parity_val,
                stopbits=stopbits,
                timeout=READ_TIMEOUT,
                rtscts=rtscts,
                xonxoff=xonxoff,
            )
        except Exception as e:
            messagebox.showerror("Open Port", f"Failed to open port {port}:\n{e}")
            self.serial_port = None
            return

        if self.serial_port and getattr(self.serial_port, "is_open", False):
            self.open_btn.config(text="Close")
            self.status_var.set(f"Open: {port} @ {baud}")
            self.alive.set()
            self.reader_thread = threading.Thread(target=self._reader_worker, daemon=True)
            self.reader_thread.start()

    def close_port(self):
        self._stop_all()
        self.alive.clear()
        if self.reader_thread:
            self.reader_thread.join(timeout=0.5)
            self.reader_thread = None
        try:
            if self.serial_port:
                self.serial_port.close()
        except Exception:
            pass
        finally:
            self.serial_port = None
            self.open_btn.config(text="Open")
            self.status_var.set("Closed")

    # Reader
    def _reader_worker(self):
        try:
            while self.alive.is_set() and self.serial_port and getattr(self.serial_port, "is_open", False):
                try:
                    data = self.serial_port.read(1024)
                except Exception:
                    break
                if data:
                    ts = time.time()
                    self.rx_queue.put((ts, data))
                else:
                    continue
        except Exception:
            pass

    def _process_rx_queue(self):
        try:
            while True:
                ts, data = self.rx_queue.get_nowait()
                self.log_received(ts, data)
        except queue.Empty:
            pass
        self.after(100, self._process_rx_queue)

    # Packet building / sending
    def _build_fi_packet(self) -> bytes:
        p = bytearray()
        p += bytes.fromhex("FA70")
        p += bytes.fromhex("4F460B")

        try:
            vc_val = int(self.vc_var.get())
        except Exception:
            raise ValueError("Vc must be integer 0..65535")
        if vc_val < 0 or vc_val > 0xFFFF:
            raise ValueError("Vc must be 0..65535")
        p += vc_val.to_bytes(2, "big")

        try:
            h_val = int(self.h_var.get())
        except Exception:
            raise ValueError("H must be integer 0..65535")
        if h_val < 0 or h_val > 0xFFFF:
            raise ValueError("H must be 0..65535")
        p += h_val.to_bytes(2, "big")

        p += bytes([0x00])  # byte 10
        p += b"C"           # 11
        p += b"N"           # 12
        p += bytes([0x00])  # 13
        p += (b"R" if self.ready_var.get() else bytes([0x00]))   # 14
        p += (b"D" if self.tar_det_var.get() else bytes([0x00])) # 15
        p += (b"X" if self.exp_var.get() else bytes([0x00]))     # 16

        data_for_crc = bytes(p[5:16])
        crc = crc16_ccitt_false(data_for_crc)
        p += crc.to_bytes(2, "big")
        p += bytes.fromhex("AA55")
        return bytes(p)

    def send_fi_key(self):
        if not self.serial_port or not getattr(self.serial_port, "is_open", False):
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        try:
            pkt = self._build_fi_packet()
        except ValueError as e:
            messagebox.showerror("Fire packet", f"Invalid Fire parameters:\n{e}")
            return
        try:
            self.serial_port.write(pkt)
            ts = time.time()
            self.log_sent(ts, pkt)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send Fire packet:\n{e}")

    def send_full_key(self):
        if not self.serial_port or not getattr(self.serial_port, "is_open", False):
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        try:
            data = bytes.fromhex("FA70464300E1F0AA55")
            self.serial_port.write(data)
            ts = time.time()
            self.log_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send Full_Self_Test key:\n{e}")

    def send_self_key(self):
        if not self.serial_port or not getattr(self.serial_port, "is_open", False):
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        try:
            data = bytes.fromhex("FA70544300E1F0AA55")
            self.serial_port.write(data)
            ts = time.time()
            self.log_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send Self_Test key:\n{e}")

    def send_data(self):
        if not self.serial_port or not getattr(self.serial_port, "is_open", False):
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        payload = self.send_entry.get() or ""
        try:
            if self.send_as_hex.get():
                data = bytes.fromhex(payload.replace(" ", ""))
            else:
                if self.append_newline.get():
                    payload += "\n"
                data = payload.encode(self.encoding)
            self.serial_port.write(data)
            ts = time.time()
            self.log_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send data:\n{e}")

    # Logging helpers
    def _format_ts(self, ts: float) -> str:
        return time.strftime("%H:%M:%S", time.localtime(ts))

    def log_received(self, ts: float, data: bytes):
        if self.show_hex.get():
            text = data.hex(" ").upper()
        else:
            try:
                text = data.decode(self.encoding, errors="replace")
            except Exception:
                text = str(data)
        line = f"[{self._format_ts(ts)}] {text}" if self.show_timestamp.get() else text
        self.rx_text.configure(state="normal")
        self.rx_text.insert("end", line + ("\n" if not line.endswith("\n") else ""))
        self.rx_text.see("end")
        self.rx_text.configure(state="disabled")

    def log_sent(self, ts: float, data: bytes):
        hex_text = data.hex(" ").upper()
        self.tx_text.configure(state="normal")
        if self.show_timestamp.get():
            ts_text = f"[{self._format_ts(ts)}] "
            self.tx_text.insert("end", ts_text, "sent_ts")
        self.tx_text.insert("end", hex_text + ("\n" if not hex_text.endswith("\n") else ""), "sent")
        self.tx_text.see("end")
        self.tx_text.configure(state="disabled")

    # Clear / Save helpers
    def clear_received(self):
        self.rx_text.configure(state="normal")
        self.rx_text.delete("1.0", "end")
        self.rx_text.configure(state="disabled")

    def clear_sent(self):
        self.tx_text.configure(state="normal")
        self.tx_text.delete("1.0", "end")
        self.tx_text.configure(state="disabled")

    def _clear_all(self):
        self.clear_received()
        self.clear_sent()

    def save_received(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not fname:
            return
        try:
            with open(fname, "w", encoding=self.encoding) as f:
                f.write(self.rx_text.get("1.0", "end"))
            messagebox.showinfo("Save", f"Saved received log to {fname}")
        except Exception as e:
            messagebox.showerror("Save", f"Failed to save received log:\n{e}")

    def save_sent(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not fname:
            return
        try:
            with open(fname, "w", encoding=self.encoding) as f:
                f.write(self.tx_text.get("1.0", "end"))
            messagebox.showinfo("Save", f"Saved sent log to {fname}")
        except Exception as e:
            messagebox.showerror("Save", f"Failed to save sent log:\n{e}")

    def save_log_all(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not fname:
            return
        try:
            with open(fname, "w", encoding=self.encoding) as f:
                f.write("=== Received ===\n")
                f.write(self.rx_text.get("1.0", "end"))
                f.write("\n\n=== Sent ===\n")
                f.write(self.tx_text.get("1.0", "end"))
            messagebox.showinfo("Save", f"Saved combined log to {fname}")
        except Exception as e:
            messagebox.showerror("Save", f"Failed to save combined log:\n{e}")

    # Repeat machinery (ms)
    def _parse_time_interval_ms(self) -> int:
        try:
            return max(0, int(float(self.time_interval_var.get())))
        except Exception:
            return 0

    def _start_repeat(self, name: str, send_callable, button_widget: tk.Button, indicator_label: tk.Label):
        if self._repeat_running.get(name):
            return
        interval_ms = self._parse_time_interval_ms()
        if interval_ms <= 0:
            try:
                send_callable()
            except Exception as e:
                messagebox.showerror("Send", f"Failed to send {name} packet:\n{e}")
            return
        self._repeat_running[name] = True
        button_widget.config(relief="sunken")
        indicator_label.config(text="ON", bg="#66ff66")

        def _repeat_step():
            if not self._repeat_running.get(name):
                return
            try:
                send_callable()
            except Exception as e:
                messagebox.showerror("Send", f"Failed to send {name} packet:\n{e}")
            next_ms = self._parse_time_interval_ms()
            if next_ms <= 0:
                self._stop_repeat(name, button_widget, indicator_label)
                return
            after_id = self.after(next_ms, _repeat_step)
            self._repeat_after_ids[name] = after_id

        try:
            send_callable()
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send {name} packet:\n{e}")
        after_id = self.after(interval_ms, _repeat_step)
        self._repeat_after_ids[name] = after_id

    def _stop_repeat(self, name: str, button_widget: tk.Button, indicator_label: tk.Label):
        if not self._repeat_running.get(name):
            return
        after_id = self._repeat_after_ids.get(name)
        if after_id:
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
        self._repeat_after_ids[name] = None
        self._repeat_running[name] = False
        if name == "Full_Self_Test":
            button_widget.config(relief="raised", bg="#28a745")
            indicator_label.config(text="OFF", bg="#cccccc")
        elif name == "Fire":
            button_widget.config(relief="raised", bg="#d9534f")
            indicator_label.config(text="OFF", bg="#cccccc")
        elif name == "Self_Test":
            button_widget.config(relief="raised", bg="#007bff")
            indicator_label.config(text="OFF", bg="#cccccc")

    def _stop_all(self):
        self._stop_repeat("Full_Self_Test", self.full_btn, self.full_ind)
        self._stop_repeat("Fire", self.fi_btn, self.fi_ind)
        self._stop_repeat("Self_Test", self.self_btn, self.self_ind)

    def _toggle_repeat_full(self):
        if self._repeat_running.get("Full_Self_Test"):
            self._stop_repeat("Full_Self_Test", self.full_btn, self.full_ind)
        else:
            self._start_repeat("Full_Self_Test", self.send_full_key, self.full_btn, self.full_ind)

    def _toggle_repeat_fi(self):
        if self._repeat_running.get("Fire"):
            self._stop_repeat("Fire", self.fi_btn, self.fi_ind)
        else:
            self._start_repeat("Fire", self.send_fi_key, self.fi_btn, self.fi_ind)

    def _toggle_repeat_self(self):
        if self._repeat_running.get("Self_Test"):
            self._stop_repeat("Self_Test", self.self_btn, self.self_ind)
        else:
            self._start_repeat("Self_Test", self.send_self_key, self.self_btn, self.self_ind)

    # Cleanup
    def on_close(self):
        self._stop_all()
        self.close_port()
        self.destroy()


def main():
    root = SerialTerminal()
    root.mainloop()


if __name__ == "__main__":
    main()