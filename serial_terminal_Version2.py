#!/usr/bin/env python3
"""
serial_terminal.py

A simple serial port terminal GUI using Tkinter and pyserial.

Features:
- Port selection (enumerates serial ports)
- Baudrate, Data bits, Parity, Stop bits, Flow control selection
- Open / Close port
- Received data display (ASCII or HEX) with optional timestamps
- Input box for sending data, options to append newline or send as hex
- Background reader thread with queue to safely update the GUI
- Save log / Clear display
Requires: pyserial (pip install pyserial)
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
except Exception as e:
    serial = None  # handle later

APP_TITLE = "Serial Terminal"
DEFAULT_ENCODING = "utf-8"

COMMON_BAUDRATES = [
    "300","1200","2400","4800","9600","14400","19200","38400","57600","115200","230400","460800","921600"
]
DATA_BITS = ["5","6","7","8"]
PARITIES = ["N","E","O","M","S"]  # None, Even, Odd, Mark, Space
STOP_BITS = ["1","1.5","2"]
FLOW_CONTROLS = ["None","RTS/CTS","XON/XOFF"]

READ_TIMEOUT = 0.1  # seconds


class SerialTerminal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x600")

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

        # Build UI
        self._build_widgets()
        self._bind_shortcuts()

        # Initialize port list
        self.refresh_ports()

        # Start periodic queue check
        self.after(100, self._process_rx_queue)

    def _build_widgets(self):
        # Top frame: settings
        top_frame = ttk.Frame(self, padding=(6,6))
        top_frame.pack(fill="x", side="top")

        # Port list and refresh
        ttk.Label(top_frame, text="Port:").grid(row=0, column=0, sticky="w")
        self.port_cb = ttk.Combobox(top_frame, width=16, state="readonly")
        self.port_cb.grid(row=0, column=1, sticky="w", padx=(2,8))
        ttk.Button(top_frame, text="Refresh", command=self.refresh_ports).grid(row=0, column=2, sticky="w", padx=(0,8))

        # Baudrate
        ttk.Label(top_frame, text="Baud:").grid(row=0, column=3, sticky="w")
        self.baud_cb = ttk.Combobox(top_frame, values=COMMON_BAUDRATES, width=10, state="readonly")
        self.baud_cb.set("9600")
        self.baud_cb.grid(row=0, column=4, sticky="w", padx=(2,8))

        # Data bits
        ttk.Label(top_frame, text="Data bits:").grid(row=0, column=5, sticky="w")
        self.data_bits_cb = ttk.Combobox(top_frame, values=DATA_BITS, width=4, state="readonly")
        self.data_bits_cb.set("8")
        self.data_bits_cb.grid(row=0, column=6, sticky="w", padx=(2,8))

        # Parity
        ttk.Label(top_frame, text="Parity:").grid(row=0, column=7, sticky="w")
        self.parity_cb = ttk.Combobox(top_frame, values=PARITIES, width=4, state="readonly")
        self.parity_cb.set("N")
        self.parity_cb.grid(row=0, column=8, sticky="w", padx=(2,8))

        # Stop bits
        ttk.Label(top_frame, text="Stop bits:").grid(row=0, column=9, sticky="w")
        self.stop_bits_cb = ttk.Combobox(top_frame, values=STOP_BITS, width=4, state="readonly")
        self.stop_bits_cb.set("1")
        self.stop_bits_cb.grid(row=0, column=10, sticky="w", padx=(2,8))

        # Flow control
        ttk.Label(top_frame, text="Flow:").grid(row=0, column=11, sticky="w")
        self.flow_cb = ttk.Combobox(top_frame, values=FLOW_CONTROLS, width=10, state="readonly")
        self.flow_cb.set("None")
        self.flow_cb.grid(row=0, column=12, sticky="w", padx=(2,8))

        # Open / Close button
        self.open_btn = ttk.Button(top_frame, text="Open", command=self.toggle_port, width=10)
        self.open_btn.grid(row=0, column=13, padx=(8,0))

        # Middle frame: received text
        mid_frame = ttk.Frame(self)
        mid_frame.pack(fill="both", expand=True, padx=6, pady=(4,0))

        self.rx_text = ScrolledText(mid_frame, wrap="none", state="normal", height=20)
        self.rx_text.pack(fill="both", expand=True, side="left")
        self.rx_text.configure(font=("Consolas", 11))

        # Right side controls
        right_frame = ttk.Frame(mid_frame, width=200)
        right_frame.pack(fill="y", side="right", padx=(6,0))

        ttk.Button(right_frame, text="Clear", command=self.clear_display).pack(fill="x", pady=(0,4))
        ttk.Button(right_frame, text="Save Log", command=self.save_log).pack(fill="x", pady=(0,8))

        # NEW BUTTON: send predefined "self" key as hex when pressed
        ttk.Button(right_frame, text="self", command=self.send_self_key).pack(fill="x", pady=(0,8))

        ttk.Checkbutton(right_frame, text="Show HEX", variable=self.show_hex).pack(anchor="w")
        ttk.Checkbutton(right_frame, text="Timestamps", variable=self.show_timestamp).pack(anchor="w")

        # Bottom frame: send box
        bottom_frame = ttk.Frame(self, padding=(6,6))
        bottom_frame.pack(fill="x", side="bottom")

        ttk.Label(bottom_frame, text="Send:").grid(row=0, column=0, sticky="w")
        self.send_entry = ttk.Entry(bottom_frame)
        self.send_entry.grid(row=0, column=1, sticky="we", padx=(4,8))
        bottom_frame.columnconfigure(1, weight=1)

        self.append_newline_cb = ttk.Checkbutton(bottom_frame, text="Append \\n", variable=self.append_newline)
        self.append_newline_cb.grid(row=0, column=2, padx=(0,8))

        self.send_hex_cb = ttk.Checkbutton(bottom_frame, text="Send as HEX", variable=self.send_as_hex)
        self.send_hex_cb.grid(row=0, column=3, padx=(0,8))

        send_btn = ttk.Button(bottom_frame, text="Send", command=self.send_data, width=12)
        send_btn.grid(row=0, column=4)

        # Status bar
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
        else:
            # If pyserial not installed, show placeholder
            ports = []
        if not ports:
            ports = ["(no ports)"]
        self.port_cb['values'] = ports
        # set first real port if available
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

        # Map parity
        parity_map = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD,
                      "M": serial.PARITY_MARK, "S": serial.PARITY_SPACE}
        parity_val = parity_map.get(parity, serial.PARITY_NONE)

        # Map stop bits
        stop_map = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE, "2": serial.STOPBITS_TWO}
        stopbits = stop_map.get(self.stop_bits_cb.get(), serial.STOPBITS_ONE)

        # Flow control mapping
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
            # start reader thread
            self.alive.set()
            self.reader_thread = threading.Thread(target=self._reader_worker, daemon=True)
            self.reader_thread.start()

    def close_port(self):
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
        # Read from serial and put bytes into queue
        try:
            while self.alive.is_set() and self.serial_port and self.serial_port.is_open:
                try:
                    data = self.serial_port.read(1024)
                except Exception:
                    break
                if data:
                    # put a timestamped tuple
                    ts = time.time()
                    self.rx_queue.put((ts, data))
                else:
                    # no data, continue
                    continue
        except Exception:
            pass
        # thread exiting
        return

    def _process_rx_queue(self):
        # Called periodically in main thread to drain queue and update text widget
        try:
            while True:
                ts, data = self.rx_queue.get_nowait()
                self._display_received(ts, data)
        except queue.Empty:
            pass
        # reschedule
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
        # insert and autoscroll
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
                # Interpret payload as hex bytes separated by spaces or continuous hex
                hexstr = payload.replace(" ", "")
                data = bytes.fromhex(hexstr)
            else:
                if self.append_newline.get():
                    payload = payload + "\n"
                data = payload.encode(self.encoding)
            self.serial_port.write(data)
            # optionally also show what we sent
            ts = time.time()
            self._display_sent(ts, data)
        except Exception as e:
            messagebox.showerror("Send", f"Failed to send data:\n{e}")

    def send_self_key(self):
        """Send the fixed hex sequence FA70544300E1F0AA55 over serial."""
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
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
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
        # cleanup
        self.close_port()
        self.destroy()


def main():
    root = SerialTerminal()
    root.mainloop()


if __name__ == "__main__":
    main()