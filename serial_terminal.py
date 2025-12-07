#!/usr/bin/env python3
"""
serial_terminal.py

Serial port terminal GUI (Tkinter + pyserial)

Fixed repeating/send logic so buttons کار می‌کنند وقتی Time Interval > 0.
Added "Stop All" button and better validation / error messages.
Time Interval is in milliseconds.
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

APP_TITLE = "Serial Terminal"
DEFAULT_ENCODING = "utf-8"

COMMON_BAUDRATES = [
    "300", "1200", "2400", "4800", "9600", "14400", "19200", "38400", "57600", "115200", "230400", "460800",
    "921600"
]
DATA_BITS = ["5", "6", "7", "8"]
PARITIES = ["N", "E", "O", "M", "S"]  # None, Even, Odd, Mark, Space
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
        self.geometry("1280x820")

        # serial
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

        # Fi-specific controls state
        self.ready_var = tk.BooleanVar(value=False)
        self.tar_det_var = tk.BooleanVar(value=False)
        self.exp_var = tk.BooleanVar(value=False)
        self.vc_var = tk.StringVar(value="0")   # decimal 0..65535
        self.h_var = tk.StringVar(value="0")    # decimal 0..65535

        # Time interval (milliseconds) for repeating packets
        self.time_interval_var = tk.StringVar(value="0")  # ms as integer

        # Repeat control state
        self._repeat_after_ids = {"full": None, "fi": None, "self": None}
        self._repeat_running = {"full": False, "fi": False, "self": False}

        # Build UI
        self._setup_style()
        self._build_widgets()
        self._bind_shortcuts()

        # Initialize port list
        self.refresh_ports()

        # Start periodic queue check
        self.after(100, self._process_rx_queue)

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        default_font = ("Segoe UI", 10)
        style.configure(".", font=default_font)
        style.configure("Title.TLabel", font=("Segoe UI", 11, "bold"))

    def _build_widgets(self):
        top_frame = ttk.Frame(self, padding=(8, 8))
        top_frame.pack(fill="x", side="top")

        ttk.Label(top_frame, text="Port:", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.port_cb = ttk.Combobox(top_frame, width=18, state="readonly")
        self.port_cb.grid(row=0, column=1, sticky="w", padx=(6, 8))
        ttk.Button(top_frame, text="Refresh", command=self.refresh_ports).grid(row=0, column=2, sticky="w", padx=(0, 8))

        ttk.Label(top_frame, text="Baud:", style="Title.TLabel").grid(row=0, column=3, sticky="w")
        self.baud_cb = ttk.Combobox(top_frame, values=COMMON_BAUDRATES, width=12, state="readonly")
        self.baud_cb.set("9600")
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

        self.open_btn = ttk.Button(top_frame, text="Open", command=self.toggle_port, width=12)
        self.open_btn.grid(row=0, column=13, padx=(8, 0))

        main_frame = ttk.Frame(self, padding=(8, 6))
        main_frame.pack(fill="both", expand=True)

        rx_frame = ttk.Labelframe(main_frame, text="Received / Log", padding=(6, 6))
        rx_frame.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=(0, 6))

        self.rx_text = ScrolledText(rx_frame, wrap="none", state="normal", height=25)
        self.rx_text.pack(fill="both", expand=True)
        self.rx_text.configure(font=("Consolas", 11), background="#1e1e1e", foreground="#e6e6e6", insertbackground="white")

        right_frame = ttk.Frame(main_frame, width=360)
        right_frame.pack(side="right", fill="y")

        actions_frame = ttk.Frame(right_frame)
        actions_frame.pack(fill="x", pady=(0, 6))
        ttk.Label(actions_frame, text="Actions:", style="Title.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))

        top_buttons = ttk.Frame(actions_frame)
        top_buttons.grid(row=0, column=1, sticky="e")
        ttk.Button(top_buttons, text="Clear", command=self.clear_display).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(top_buttons, text="Save Log", command=self.save_log).grid(row=0, column=1, padx=(0,6))
        ttk.Button(top_buttons, text="Stop All", command=self._stop_all).grid(row=0, column=2)

        btn_frame = ttk.Frame(actions_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="we", pady=(6, 0))
        btn_frame.columnconfigure((0, 1, 2), weight=1)

        self.full_btn = tk.Button(btn_frame, text="Full", bg="#28a745", fg="white", activebackground="#1e7e34",
                                  command=self._toggle_repeat_full)
        self.full_btn.grid(row=0, column=0, sticky="we", padx=(0, 6))

        self.fi_btn = tk.Button(btn_frame, text="Fi", bg="#d9534f", fg="white", activebackground="#c43d3d",
                                command=self._toggle_repeat_fi)
        self.fi_btn.grid(row=0, column=1, sticky="we", padx=(0, 6))

        self.self_btn = tk.Button(btn_frame, text="self", bg="#007bff", fg="white", activebackground="#0069d9",
                                  command=self._toggle_repeat_self)
        self.self_btn.grid(row=0, column=2, sticky="we")

        fi_frame = ttk.Labelframe(right_frame, text="Fi packet options", padding=(8, 8))
        fi_frame.pack(fill="x", pady=(6, 6))

        vc_frame = ttk.Frame(fi_frame)
        vc_frame.pack(fill="x", pady=(4, 4))
        ttk.Label(vc_frame, text="Vc (0..65535):").grid(row=0, column=0, sticky="w")
        self.vc_entry = ttk.Entry(vc_frame, textvariable=self.vc_var, width=14)
        self.vc_entry.grid(row=0, column=1, sticky="e", padx=(8, 0))

        h_frame = ttk.Frame(fi_frame)
        h_frame.pack(fill="x", pady=(2, 4))
        ttk.Label(h_frame, text="H  (0..65535):").grid(row=0, column=0, sticky="w")
        self.h_entry = ttk.Entry(h_frame, textvariable=self.h_var, width=14)
        self.h_entry.grid(row=0, column=1, sticky="e", padx=(8, 0))

        ti_frame = ttk.Frame(fi_frame)
        ti_frame.pack(fill="x", pady=(2, 4))
        ttk.Label(ti_frame, text="Time Interval (ms):").grid(row=0, column=0, sticky="w")
        self.time_interval_entry = ttk.Entry(ti_frame, textvariable=self.time_interval_var, width=14)
        self.time_interval_entry.grid(row=0, column=1, sticky="e", padx=(8, 0))
        ttk.Label(ti_frame, text="0 => send once").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        cb_frame = ttk.Frame(fi_frame)
        cb_frame.pack(fill="x", pady=(6, 4))
        ttk.Checkbutton(cb_frame, text="Ready", variable=self.ready_var).grid(row=0, column=0, sticky="w", padx=2)
        ttk.Checkbutton(cb_frame, text="Tar_Det", variable=self.tar_det_var).grid(row=0, column=1, sticky="w", padx=2)
        ttk.Checkbutton(cb_frame, text="Exp", variable=self.exp_var).grid(row=0, column=2, sticky="w", padx=2)

        opts_frame = ttk.Frame(right_frame)
        opts_frame.pack(fill="x", pady=(6, 6))
        ttk.Checkbutton(opts_frame, text="Show HEX", variable=self.show_hex).grid(row=0, column=0, sticky="w", padx=2)
        ttk.Checkbutton(opts_frame, text="Timestamps", variable=self.show_timestamp).grid(row=0, column=1, sticky="w", padx=2)

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

        self.status_var = tk.StringVar(value="Closed")
        status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        status.pack(fill="x", side="bottom", ipady=2)

    def _bind_shortcuts(self):
        self.bind_all("<Control-Shift-R>", lambda e: self.refresh_ports())
        self.bind_all("<Control-Return>", lambda e: self.send_data())
        self.protocol("WM_DELETE_WINDOW", self.on_close)

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
        if self.serial_port and self.serial_port.is_open:
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

        if self.serial_port and self.serial_port.is_open:
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

    def _reader_worker(self):
        try:
            while self.alive.is_set() and self.serial_port and self.serial_port.is_open:
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
        return

    def _process_rx_queue(self):
        try:
            while True:
                ts, data = self.rx_queue.get_nowait()
                self._display_received(ts, data)
        except queue.Empty:
            pass
        self.after(100, self._process_rx_queue)

    def _display_received(self, ts, data: bytes):
        if self.show_hex.get():
            text = data.hex(" ").upper()
        else:
            try:
                text = data.decode(self.encoding, errors="replace")
            except Exception:
                text = str(data)
        if self.show_timestamp.get():
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            line = f"[{tstr}] {text}"
        else:
            line = text
        self.rx_text.configure(state="normal")
        self.rx_text.insert("end", line)
        if not line.endswith("\n"):
            self.rx_text.insert("end", "\n")
        self.rx_text.see("end")
        self.rx_text.configure(state="disabled")

    def send_data(self):
        if not self.serial_port or not self.serial_port.is_open:
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        payload = self.send_entry.get()
        if payload is None:
            return
        try:
            if self.send_as_hex.get():
                hexstr = payload.replace(" ", "")
                data = bytes.fromhex(hexstr)
            else:
                if self.append_newline.get():
                    payload = payload + "\n"
                data = payload.encode(self.encoding)
            self.serial_port.write(data)
            ts = time.time()
            self._display_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send data:\n{e}")

    def send_self_key(self):
        if not self.serial_port or not self.serial_port.is_open:
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        try:
            data = bytes.fromhex("FA70544300E1F0AA55")
            self.serial_port.write(data)
            ts = time.time()
            self._display_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send SELF key:\n{e}")

    def send_full_key(self):
        if not self.serial_port or not self.serial_port.is_open:
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        try:
            data = bytes.fromhex("FA70464300E1F0AA55")
            self.serial_port.write(data)
            ts = time.time()
            self._display_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send FULL key:\n{e}")

    def _build_fi_packet(self) -> bytes:
        packet = bytearray()
        packet += bytes.fromhex("FA70")
        packet += bytes.fromhex("4F460B")

        try:
            vc_val = int(self.vc_var.get())
        except Exception:
            raise ValueError("Vc must be an integer 0..65535")
        if vc_val < 0 or vc_val > 0xFFFF:
            raise ValueError("Vc must be 0..65535")
        packet += vc_val.to_bytes(2, "big")

        try:
            h_val = int(self.h_var.get())
        except Exception:
            raise ValueError("H must be an integer 0..65535")
        if h_val < 0 or h_val > 0xFFFF:
            raise ValueError("H must be 0..65535")
        packet += h_val.to_bytes(2, "big")

        packet += bytes([0x00])  # Byte 10
        packet += b"C"           # Byte 11
        packet += b"N"           # Byte 12
        packet += bytes([0x00])  # Byte 13
        packet += (b"R" if self.ready_var.get() else bytes([0x00]))   # 14
        packet += (b"D" if self.tar_det_var.get() else bytes([0x00])) # 15
        packet += (b"X" if self.exp_var.get() else bytes([0x00]))     # 16

        data_for_crc = bytes(packet[5:16])
        crc = crc16_ccitt_false(data_for_crc)
        packet += crc.to_bytes(2, "big")
        packet += bytes.fromhex("AA55")
        return bytes(packet)

    def send_fi_key(self):
        if not self.serial_port or not self.serial_port.is_open:
            messagebox.showwarning("Send", "Serial port is not open.")
            return
        try:
            pkt = self._build_fi_packet()
        except ValueError as e:
            messagebox.showerror("Fi packet", f"Invalid Fi parameters:\n{e}")
            return
        try:
            self.serial_port.write(pkt)
            ts = time.time()
            self._display_sent(ts, pkt)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send Fi packet:\n{e}")

    # ---------- Repeating send machinery (milliseconds) ----------
    def _parse_time_interval_ms(self) -> int:
        try:
            v = float(self.time_interval_var.get())
            ms = int(max(0.0, v))
            return ms
        except Exception:
            return 0

    def _start_repeat(self, name: str, send_callable, button_widget: tk.Button):
        """Start repeating send_callable at interval milliseconds (read live).
        If interval == 0 then call once and do not start repeating.
        """
        if self._repeat_running.get(name):
            return

        interval_ms = self._parse_time_interval_ms()
        if interval_ms <= 0:
            # send once
            try:
                send_callable()
            except Exception as e:
                messagebox.showerror("Send", f"Failed to send {name} packet:\n{e}")
            return

        # begin repeating
        self._repeat_running[name] = True
        # visual
        button_widget.config(relief="sunken", bg=self._active_button_color(button_widget))

        def _repeat_step():
            if not self._repeat_running.get(name):
                return
            try:
                send_callable()
            except Exception as e:
                # show error but continue attempts
                messagebox.showerror("Send", f"Failed to send {name} packet:\n{e}")
            # read current interval (live update)
            next_ms = self._parse_time_interval_ms()
            if next_ms <= 0:
                self._stop_repeat(name)
                return
            after_id = self.after(next_ms, _repeat_step)
            self._repeat_after_ids[name] = after_id

        # initial send then schedule next
        try:
            send_callable()
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send {name} packet:\n{e}")
        after_id = self.after(interval_ms, _repeat_step)
        self._repeat_after_ids[name] = after_id

    def _stop_repeat(self, name: str):
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
        if name == "full":
            self.full_btn.config(relief="raised", bg="#28a745")
        elif name == "fi":
            self.fi_btn.config(relief="raised", bg="#d9534f")
        elif name == "self":
            self.self_btn.config(relief="raised", bg="#007bff")

    def _stop_all(self):
        for name in list(self._repeat_running.keys()):
            if self._repeat_running.get(name):
                self._stop_repeat(name)

    def _active_button_color(self, btn: tk.Button) -> str:
        try:
            orig = btn.cget("bg")
            if orig.lower().startswith("#28"):
                return "#1e7e34"
            if orig.lower().startswith("#d9"):
                return "#c43d3d"
            if orig.lower().startswith("#00") or orig.lower().startswith("#4d"):
                return "#0069d9"
        except Exception:
            pass
        return btn.cget("bg")

    def _toggle_repeat_full(self):
        if self._repeat_running.get("full"):
            self._stop_repeat("full")
        else:
            self._start_repeat("full", self.send_full_key, self.full_btn)

    def _toggle_repeat_fi(self):
        if self._repeat_running.get("fi"):
            self._stop_repeat("fi")
        else:
            self._start_repeat("fi", self.send_fi_key, self.fi_btn)

    def _toggle_repeat_self(self):
        if self._repeat_running.get("self"):
            self._stop_repeat("self")
        else:
            self._start_repeat("self", self.send_self_key, self.self_btn)

    # ---------- end repeating machinery ----------

    def _display_sent(self, ts, data: bytes):
        if self.show_hex.get():
            text = data.hex(" ").upper()
        else:
            try:
                text = data.decode(self.encoding, errors="replace")
            except Exception:
                text = str(data)
        if self.show_timestamp.get():
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            line = f"[{tstr}] -> {text}"
        else:
            line = f"-> {text}"
        self.rx_text.configure(state="normal")
        self.rx_text.insert("end", line)
        if not line.endswith("\n"):
            self.rx_text.insert("end", "\n")
        self.rx_text.see("end")
        self.rx_text.configure(state="disabled")

    def clear_display(self):
        self.rx_text.configure(state="normal")
        self.rx_text.delete("1.0", "end")
        self.rx_text.configure(state="disabled")

    def save_log(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", ".txt"), ("All files", "*.*")])
        if not fname:
            return
        try:
            content = self.rx_text.get("1.0", "end")
            with open(fname, "w", encoding=self.encoding) as f:
                f.write(content)
            messagebox.showinfo("Save", f"Saved log to {fname}")
        except Exception as e:
            messagebox.showerror("Save", f"Failed to save log:\n{e}")

    def on_close(self):
        self._stop_all()
        self.close_port()
        self.destroy()


def main():
    root = SerialTerminal()
    root.mainloop()


if __name__ == "__main__":
    main()