import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import serial
import serial.tools.list_ports
import threading
import time
from datetime import datetime
from typing import Optional

# ==========================================
#  CORE LOGIC (STRICTLY PRESERVED)
#  ※ロジック部分は一切変更なし
# ==========================================
class KissProtocol:
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD

    def __init__(self):
        self._tx_lfsr: Optional[int] = None
        self._rx_lfsr: Optional[int] = None

    def _update_lfsr(self, lfsr):
        if lfsr is None or lfsr == 0:
            lfsr = 0x1FF
        feedback = ((lfsr >> 0) ^ (lfsr >> 4)) & 0x01
        lfsr >>= 1
        lfsr |= (feedback << 8)
        return lfsr

    def generate_pn9(self, length: int, lfsr_state: int) -> tuple[bytes, int]:
        if length <= 0: return b"", lfsr_state
        if lfsr_state is None or lfsr_state == 0: lfsr_state = 0x1FF
        
        out = bytearray()
        current_byte = 0
        bit_pos = 0
        local_lfsr = lfsr_state
        
        while len(out) < length:
            out_bit = local_lfsr & 0x01
            current_byte |= (out_bit << bit_pos)
            bit_pos += 1
            if bit_pos == 8:
                out.append(current_byte)
                current_byte = 0
                bit_pos = 0
            
            feedback = ((local_lfsr >> 0) ^ (local_lfsr >> 4)) & 0x01
            local_lfsr >>= 1
            local_lfsr |= (feedback << 8)
            
        return bytes(out), local_lfsr

    def build_payload(self, counter: int, size: int, reset_each: bool) -> bytes:
        if size < 3: raise ValueError("Size must be >= 3")
        payload = bytearray(size)
        payload[0] = 0x42
        payload[1] = (counter >> 8) & 0xFF
        payload[2] = counter & 0xFF
        
        rem = size - 3
        if rem > 0:
            if reset_each:
                start_lfsr = 0x1FF
            else:
                if self._tx_lfsr is None: self._tx_lfsr = 0x1FF
                start_lfsr = self._tx_lfsr
            
            pn9_data, next_lfsr = self.generate_pn9(rem, start_lfsr)
            payload[3:] = pn9_data
            
            if not reset_each:
                self._tx_lfsr = next_lfsr
        return bytes(payload)

    def kiss_encode(self, data: bytes) -> bytes:
        out = bytearray()
        out.append(self.FEND)
        out.append(0x00) 
        for b in data:
            if b == self.FEND: out.extend([self.FESC, self.TFEND])
            elif b == self.FESC: out.extend([self.FESC, self.TFESC])
            else: out.append(b)
        out.append(self.FEND)
        return bytes(out)

    def kiss_decode_stream(self, data_chunk: bytes, buffer: bytearray, in_frame: bool, escape: bool):
        frames = []
        for b in data_chunk:
            if b == self.FEND:
                if in_frame and len(buffer) > 0:
                    frames.append(bytes(buffer))
                    buffer.clear()
                    in_frame = False
                    escape = False
                else:
                    buffer.clear()
                    in_frame = True
                    escape = False
            elif in_frame:
                if b == self.FESC:
                    escape = True
                else:
                    if escape:
                        if b == self.TFEND: buffer.append(self.FEND)
                        elif b == self.TFESC: buffer.append(self.FESC)
                        else: buffer.append(b)
                        escape = False
                    else:
                        buffer.append(b)
        return frames, buffer, in_frame, escape

# ==========================================
#  FALLOUT STYLE TERMINAL GUI
# ==========================================
class FalloutApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ROBCO INDUSTRIES TERMINAL LINK")
        self.root.geometry("950x750")
        
        # --- THEME DEFINITION (NO RED ALLOWED) ---
        self.col_bg = "#000500"       # CRT Black
        self.col_fg = "#33ff33"       # Phosphor Green
        self.col_dim = "#002200"      # Dimmed Green
        self.col_act = "#66ff66"      # Bright Green (Active)
        
        self.root.configure(bg=self.col_bg)
        
        self.protocol = KissProtocol()
        self.running = False
        self.stop_event = threading.Event()
        self.stats = {"tx_count": 0, "rx_count": 0, "loss": 0, "ok": 0}

        self.setup_ui()
        
        # Start Boot Sequence immediately
        self.root.after(500, self.boot_sequence)

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('default')
        # Dropdown style customization to match terminal
        style.configure("TCombobox", 
                        fieldbackground=self.col_bg, 
                        background=self.col_dim, 
                        foreground=self.col_fg, 
                        arrowcolor=self.col_fg,
                        borderwidth=1)
        style.map('TCombobox', fieldbackground=[('readonly', self.col_bg)], selectbackground=[('readonly', self.col_bg)], selectforeground=[('readonly', self.col_fg)])

        # Main Container
        main_frame = tk.Frame(self.root, bg=self.col_bg, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. CONFIG MODULE
        lbl_conf = tk.Label(main_frame, text="[ CONFIGURATION MODULE ]", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 12, "bold"))
        lbl_conf.pack(anchor=tk.W, pady=(0, 5))
        
        conf_frame = tk.Frame(main_frame, bg=self.col_bg, highlightbackground=self.col_fg, highlightthickness=1)
        conf_frame.pack(fill=tk.X, pady=(0, 20), ipadx=10, ipady=10)

        # Row 1: Ports
        r1 = tk.Frame(conf_frame, bg=self.col_bg)
        r1.pack(fill=tk.X, pady=5)
        
        def mk_lbl(p, t): tk.Label(p, text=t, bg=self.col_bg, fg=self.col_fg, font=("Consolas", 10)).pack(side=tk.LEFT, padx=(0, 5))

        mk_lbl(r1, "TX LINK >")
        self.cb_tx = ttk.Combobox(r1, width=15, font=("Consolas", 10))
        self.cb_tx.pack(side=tk.LEFT, padx=(0, 20))
        
        mk_lbl(r1, "RX LINK >")
        self.cb_rx = ttk.Combobox(r1, width=15, font=("Consolas", 10))
        self.cb_rx.pack(side=tk.LEFT, padx=(0, 20))
        
        self.btn_refresh = tk.Button(r1, text="[ SCAN PORTS ]", command=self.refresh_ports, 
                                     bg=self.col_dim, fg=self.col_fg, relief="flat", font=("Consolas", 9), activebackground=self.col_fg, activeforeground=self.col_bg)
        self.btn_refresh.pack(side=tk.LEFT)

        # Row 2: Params
        r2 = tk.Frame(conf_frame, bg=self.col_bg)
        r2.pack(fill=tk.X, pady=5)
        
        def mk_entry(p, def_val):
            e = tk.Entry(p, width=10, bg="#001100", fg=self.col_fg, insertbackground=self.col_fg, font=("Consolas", 10), relief="flat")
            e.insert(0, def_val)
            e.pack(side=tk.LEFT, padx=(0, 20))
            return e

        mk_lbl(r2, "BAUD RATE >")
        self.e_baud = mk_entry(r2, "9600")
        
        mk_lbl(r2, "PACKET SIZE >")
        self.e_size = mk_entry(r2, "16")
        
        mk_lbl(r2, "INTERVAL(s) >")
        self.e_int = mk_entry(r2, "0.5")

        # 2. STATUS MODULE
        lbl_stat = tk.Label(main_frame, text="[ SYSTEM DIAGNOSTICS ]", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 12, "bold"))
        lbl_stat.pack(anchor=tk.W, pady=(0, 5))
        
        stat_frame = tk.Frame(main_frame, bg=self.col_bg, highlightbackground=self.col_fg, highlightthickness=1)
        stat_frame.pack(fill=tk.X, pady=(0, 20), ipadx=10, ipady=10)

        # Metrics Display (Grid like)
        self.lbl_tx = tk.Label(stat_frame, text="TX PKTS: 00000", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 14))
        self.lbl_tx.pack(side=tk.LEFT, expand=True)
        
        self.lbl_rx = tk.Label(stat_frame, text="RX OK: 00000", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 14))
        self.lbl_rx.pack(side=tk.LEFT, expand=True)
        
        self.lbl_loss = tk.Label(stat_frame, text="LOSS: 00000", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 14)) # Green! No Red.
        self.lbl_loss.pack(side=tk.LEFT, expand=True)

        self.lbl_rate = tk.Label(stat_frame, text="INTEGRITY: 000.0%", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 14, "bold"))
        self.lbl_rate.pack(side=tk.LEFT, expand=True)

        # 3. CONTROL
        self.btn_run = tk.Button(main_frame, text=">>> INITIALIZE DATA LINK <<<", command=self.toggle_test,
                                 bg=self.col_dim, fg=self.col_fg, font=("Consolas", 14, "bold"), relief="flat",
                                 activebackground=self.col_fg, activeforeground=self.col_bg, height=2, state="disabled")
        self.btn_run.pack(fill=tk.X, pady=(0, 20))

        # 4. TERMINAL LOG
        lbl_log = tk.Label(main_frame, text="[ KERNEL LOG ]", bg=self.col_bg, fg=self.col_fg, font=("Consolas", 10))
        lbl_log.pack(anchor=tk.W)
        
        self.log_area = scrolledtext.ScrolledText(main_frame, height=12, bg="#001100", fg=self.col_fg, font=("Consolas", 10), relief="flat", insertbackground=self.col_fg)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        # Monochromatic tags (Using brightness or symbols for distinction)
        self.log_area.tag_config("SYS", foreground=self.col_fg)
        self.log_area.tag_config("TX", foreground=self.col_fg) 
        self.log_area.tag_config("ERR", foreground=self.col_fg, background="#003300") # Highlight errs with bg, keep fg green

    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.cb_tx['values'] = ports
        self.cb_rx['values'] = ports
        if ports:
            self.cb_tx.current(0)
            if len(ports) > 1: self.cb_rx.current(1)
            else: self.cb_rx.current(0)
            self.log_sys(f"DETECTED {len(ports)} INTERFACES.")
        else:
            self.log_sys("WARNING: NO SERIAL INTERFACES FOUND.")

    def log_sys(self, msg, tag="SYS"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.log_area.see(tk.END)

    # --- BOOT SEQUENCE (RESTORED & REFINED) ---
    def boot_sequence(self):
        art = r"""
MM    MM MM    MM JJJJJJJJJ    AAA      NN    NN TTTTTTTTT
MMM  MMM MMM  MMM     JJ      AAAAA     NNN   NN    TTT  
MM MM MM MM MM MM     JJ     AA   AA    NNNN  NN    TTT  
MM    MM MM    MM JJ  JJ    AAAAAAAAA   NN NN NN    TTT  
MM    MM MM    MM  JJJJ    AA       AA  NN  NNNN    TTT  
"""
        messages = [
            art,
            " KERNEL: LOADING SERIAL DRIVERS... [OK]",
            " MODULE: KISS PROTOCOL ENCODER... [OK]",
            " MODULE: PN9 GENERATOR (x^9 + x^5 + 1)... [OK]",
            " SECURITY: BYPASSED.",
            " ??KISAMA KOKOWO MITEIRUNA???",
            " ------------------------------------------",
            " MMJ ANT - TRANSMISSION CONTROL v5.0",
            " ",
            " ========================================== "
            " [ OPERATION GUIDE ]",
            "  1. [TX LINK] 送信用ポートを選択",
            "  2. [RX LINK] 受信用ポートを選択",
            "  3. [PARAMS]  通信設定を同期せよ",
            "  4. [INITIATE] ボタンでリンク確立",
            " ",
            "  <NOTE>",
            "  - 赤色は使用禁止。全ては緑色である。",
            "  - 送信(TX)と受信(RX)をリアルタイムで監視する。",
            "  - PN9は乱数を生成する。",
            " ",
            " > SYSTEM READY. WAITING FOR COMMAND...",
        ]
        
        threading.Thread(target=self.typewriter_effect, args=(messages,)).start()

    def typewriter_effect(self, lines):
        self.log_area.delete(1.0, tk.END)
        for line in lines:
            if "MMJ" in line or "KERNEL" in line:
                self.log_area.insert(tk.END, line + "\n")
                self.log_area.see(tk.END)
                time.sleep(0.1)
                continue
                
            for char in line:
                self.log_area.insert(tk.END, char)
                self.log_area.see(tk.END)
                time.sleep(0.005) 
            self.log_area.insert(tk.END, "\n")
            time.sleep(0.05)
        
        self.root.after(0, lambda: self.btn_run.config(state="normal"))
        self.root.after(0, self.refresh_ports)

    # --- MAIN LOGIC ---
    def toggle_test(self):
        if self.running:
            # STOP
            self.running = False
            self.stop_event.set()
            self.btn_run.config(text=">>> INITIALIZE DATA LINK <<<", bg=self.col_dim, fg=self.col_fg)
            self.log_sys("HALT COMMAND RECEIVED. TERMINATING LINK.")
        else:
            # START
            tx_port = self.cb_tx.get()
            rx_port = self.cb_rx.get()
            
            if not tx_port or not rx_port:
                self.log_sys("ERROR: UNDEFINED PORTS", "ERR")
                return
            if tx_port == rx_port:
                self.log_sys("WARNING: TX AND RX ARE SAME INTERFACE", "ERR")

            try:
                self.cfg = {
                    "baud": int(self.e_baud.get()),
                    "size": int(self.e_size.get()),
                    "interval": float(self.e_int.get())
                }
            except ValueError:
                self.log_sys("ERROR: INVALID PARAMETERS", "ERR")
                return

            self.running = True
            self.stop_event.clear()
            self.stats = {"tx_count": 0, "rx_count": 0, "loss": 0, "ok": 0}
            self.update_dashboard()
            
            # Inverted colors for active state
            self.btn_run.config(text=">>> TERMINATE DATA LINK <<<", bg=self.col_fg, fg=self.col_bg)
            
            threading.Thread(target=self.thread_tx, args=(tx_port,), daemon=True).start()
            threading.Thread(target=self.thread_rx, args=(rx_port,), daemon=True).start()

    def update_dashboard(self):
        if not self.running: return
        s = self.stats
        total_rx = s["ok"] + s["loss"]
        # Simple integrity calc
        rate = (s["ok"] / (total_rx + 1e-9) * 100) if total_rx > 0 else 100.0
        
        self.lbl_tx.config(text=f"TX PKTS: {s['tx_count']:05d}")
        self.lbl_rx.config(text=f"RX OK: {s['ok']:05d}")
        self.lbl_loss.config(text=f"LOSS: {s['loss']:05d}")
        self.lbl_rate.config(text=f"INTEGRITY: {rate:05.1f}%")
        
        self.root.after(200, self.update_dashboard)

    # --- TX THREAD ---
    def thread_tx(self, port):
        self.log_sys(f"TX UPLINK ESTABLISHED: {port}")
        try:
            with serial.Serial(port, self.cfg["baud"]) as ser:
                counter = 0
                while not self.stop_event.is_set():
                    payload = self.protocol.build_payload(counter, self.cfg["size"], reset_each=False)
                    frame = self.protocol.kiss_encode(payload)
                    ser.write(frame)
                    
                    self.stats["tx_count"] += 1
                    counter = (counter + 1) & 0xFFFF
                    time.sleep(self.cfg["interval"])
        except Exception as e:
            self.log_sys(f"TX FAILURE: {e}", "ERR")
            self.running = False

    # --- RX THREAD ---
    def thread_rx(self, port):
        self.log_sys(f"RX DOWNLINK LISTENING: {port}")
        try:
            with serial.Serial(port, self.cfg["baud"], timeout=0.1) as ser:
                buffer = bytearray()
                in_frame = False
                escape = False
                expected_cnt = -1
                
                while not self.stop_event.is_set():
                    if ser.in_waiting > 0:
                        chunk = ser.read(ser.in_waiting)
                        frames, buffer, in_frame, escape = self.protocol.kiss_decode_stream(chunk, buffer, in_frame, escape)
                        
                        for frame in frames:
                            if len(frame) >= 4 and frame[0] == 0x00 and frame[1] == 0x42:
                                recv_cnt = (frame[2] << 8) | frame[3]
                                
                                if expected_cnt != -1:
                                    diff = (recv_cnt - expected_cnt) & 0xFFFF
                                    if diff > 0 and diff < 1000:
                                        self.stats["loss"] += diff
                                        self.log_sys(f"!! PACKET LOSS DETECTED: {diff} FRAMES !!", "ERR")
                                
                                self.stats["ok"] += 1
                                expected_cnt = (recv_cnt + 1) & 0xFFFF
                    else:
                        time.sleep(0.01)
        except Exception as e:
            self.log_sys(f"RX FAILURE: {e}", "ERR")

if __name__ == "__main__":
    root = tk.Tk()
    app = FalloutApp(root)
    root.mainloop()