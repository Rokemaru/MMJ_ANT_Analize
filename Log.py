import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import csv
import re
import os
import threading
from datetime import datetime

# ==========================================
#  CORE LOGIC
# ==========================================
class KissProtocol:
    def __init__(self):
        self.state = 0x1FF

    def generate_pn9(self, length, lfsr_state=None):
        if length <= 0: return b"", lfsr_state
        if lfsr_state is None: lfsr_state = 0x1FF
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

class LogDecoderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MMJ LOG DECODER (全体統計機能付き)")
        self.root.geometry("950x700") 
        
        self.col_bg = "#000500"
        self.col_fg = "#33ff33"
        self.col_dim = "#002200"
        
        self.root.configure(bg=self.col_bg)
        self.results = [] 
        self.global_stats = {} # 全体統計保存用

        self.setup_ui()
        self.log_sys("システム準備完了。TeraTermログを読み込んでください。")

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('default')

        main_frame = tk.Frame(self.root, bg=self.col_bg, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. FILE
        lbl_file = tk.Label(main_frame, text="[ 対象ログファイル選択 ]", bg=self.col_bg, fg=self.col_fg, font=("Meiryo", 12, "bold"))
        lbl_file.pack(anchor=tk.W, pady=(0, 5))
        
        file_frame = tk.Frame(main_frame, bg=self.col_bg, highlightbackground=self.col_fg, highlightthickness=1)
        file_frame.pack(fill=tk.X, pady=(0, 20), ipadx=10, ipady=10)
        
        self.entry_path = tk.Entry(file_frame, bg="#001100", fg=self.col_fg, insertbackground=self.col_fg, font=("Consolas", 10), relief="flat")
        self.entry_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        btn_browse = tk.Button(file_frame, text="[ 参照... ]", command=self.browse_file, bg=self.col_dim, fg=self.col_fg, relief="flat", font=("Meiryo", 9))
        btn_browse.pack(side=tk.LEFT)

        # 2. SETTINGS
        lbl_set = tk.Label(main_frame, text="[ 解析設定 ]", bg=self.col_bg, fg=self.col_fg, font=("Meiryo", 12, "bold"))
        lbl_set.pack(anchor=tk.W, pady=(0, 5))
        
        set_frame = tk.Frame(main_frame, bg=self.col_bg)
        set_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(set_frame, text="パケットサイズ(Byte) >", bg=self.col_bg, fg=self.col_fg, font=("Meiryo", 10)).pack(side=tk.LEFT)
        self.entry_size = tk.Entry(set_frame, width=5, bg="#001100", fg=self.col_fg, insertbackground=self.col_fg, font=("Consolas", 10), relief="flat")
        self.entry_size.insert(0, "16")
        self.entry_size.pack(side=tk.LEFT, padx=(5, 20))

        # 3. ACTIONS
        btn_frame = tk.Frame(main_frame, bg=self.col_bg)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        self.btn_analyze = tk.Button(btn_frame, text=">>> 解析実行 (ANALYZE) <<<", command=self.start_analysis,
                                     bg=self.col_dim, fg=self.col_fg, font=("Meiryo", 12, "bold"), relief="flat", height=2)
        self.btn_analyze.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.btn_save = tk.Button(btn_frame, text="[ CSV保存 ]", command=self.save_csv,
                                  bg=self.col_dim, fg=self.col_fg, font=("Meiryo", 12, "bold"), relief="flat", height=2, state="disabled")
        self.btn_save.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 4. LOG
        self.log_area = scrolledtext.ScrolledText(main_frame, bg="#001100", fg=self.col_fg, font=("Meiryo", 10), relief="flat", insertbackground=self.col_fg)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.tag_config("ERR", foreground="#ff5555")
        self.log_area.tag_config("OK", foreground=self.col_fg)
        self.log_area.tag_config("WARN", foreground="#ffff55")
        self.log_area.tag_config("STAT", foreground="#00ffff", font=("Meiryo", 11, "bold")) # 統計用

    def log_sys(self, msg, tag="OK"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.log_area.see(tk.END)

    def browse_file(self):
        f = filedialog.askopenfilename(filetypes=[("Log Files", "*.txt;*.log"), ("All Files", "*.*")])
        if f:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, f)
            self.log_sys(f"ファイル選択: {os.path.basename(f)}")

    def start_analysis(self):
        path = self.entry_path.get()
        if not path or not os.path.exists(path):
            self.log_sys("エラー: ファイルが見つかりません。", "ERR")
            return
        
        try:
            size = int(self.entry_size.get())
        except:
            self.log_sys("エラー: パケットサイズは数字で入力してください。", "ERR")
            return

        self.btn_analyze.config(state="disabled")
        threading.Thread(target=self.process_log, args=(path, size), daemon=True).start()

    def process_log(self, path, packet_size):
        self.log_sys("--- 解析プロセス開始 ---")
        self.results = []
        self.global_stats = {}
        proto = KissProtocol()
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            self.log_sys("データクリーニング中... (HEX抽出)")
            clean_hex = re.sub(r'[^0-9A-Fa-f]', '', content)
            data_bytes = bytes.fromhex(clean_hex)
            self.log_sys(f"抽出データ総量: {len(data_bytes)} バイト")

            found_packets = []
            i = 0
            while i < len(data_bytes):
                if data_bytes[i] == 0x42:
                    if i + packet_size <= len(data_bytes):
                        packet = data_bytes[i : i + packet_size]
                        found_packets.append(packet)
                        i += packet_size
                        continue
                i += 1
            
            self.log_sys(f"パケット候補発見数: {len(found_packets)} 個")
            
            pn9_payload_len = packet_size - 3
            # PN9部分のビット数 = バイト数 * 8
            total_bits_per_packet = pn9_payload_len * 8 
            
            ok_count = 0
            err_count = 0
            
            # === 全体統計用アキュムレータ ===
            accum_total_bits = 0
            accum_total_errors = 0

            for idx, frame in enumerate(found_packets):
                if len(frame) < 3: continue
                
                recv_cnt = (frame[1] << 8) | frame[2]
                actual_pn9 = frame[3:]
                
                dummy_len = recv_cnt * pn9_payload_len
                _, state_at_start = proto.generate_pn9(dummy_len, 0x1FF)
                exp_pn9, _ = proto.generate_pn9(pn9_payload_len, state_at_start)
                
                tx_payload = bytes([0x42, (recv_cnt >> 8) & 0xFF, recv_cnt & 0xFF]) + exp_pn9
                tx_hex = tx_payload.hex()
                rx_hex = frame.hex()
                
                bit_errors = 0
                error_rate_percent = 0.0 
                status = "OK"
                
                if len(actual_pn9) == len(exp_pn9):
                    for b_rx, b_tx in zip(actual_pn9, exp_pn9):
                        diff = b_rx ^ b_tx
                        bit_errors += bin(diff).count('1')
                    
                    if total_bits_per_packet > 0:
                        error_rate_percent = (bit_errors / total_bits_per_packet) * 100.0
                        
                else:
                    status = "SIZE_ERR"
                    error_rate_percent = 100.0 
                    bit_errors = total_bits_per_packet # サイズエラー時は全ビットエラー扱い
                
                if bit_errors > 0:
                    status = "DATA_CORRUPT"
                    err_count += 1
                else:
                    ok_count += 1
                
                # 全体統計に加算
                accum_total_bits += total_bits_per_packet
                accum_total_errors += bit_errors

                self.results.append({
                    "Index": idx,
                    "Status": status,
                    "RecvCounter": recv_cnt,
                    "RxHex": rx_hex,
                    "TxHex": tx_hex,
                    "BitErrors": bit_errors,
                    "ErrorRate(%)": f"{error_rate_percent:.2f}"
                })

            # === 全体統計の計算 ===
            global_ber = 0.0
            if accum_total_bits > 0:
                global_ber = (accum_total_errors / accum_total_bits) * 100.0
            
            # 結果を保存
            self.global_stats = {
                "TotalPackets": len(found_packets),
                "TotalBits": accum_total_bits,
                "TotalErrors": accum_total_errors,
                "GlobalBER": global_ber
            }

            self.log_sys("------------------------------")
            self.log_sys("【 全体統計レポート (GLOBAL STATS) 】", "STAT")
            self.log_sys(f" 総受信パケット数 : {len(found_packets)} 個", "STAT")
            self.log_sys(f" 総受信ビット数   : {accum_total_bits} bits", "STAT")
            self.log_sys(f" 総エラービット数 : {accum_total_errors} bits", "STAT")
            self.log_sys(f" ★全体ビット破損率 : {global_ber:.4f} %", "STAT")
            self.log_sys("------------------------------")
            
            if len(found_packets) > 0:
                self.log_sys("完了しました。[CSV保存] を押すと、この統計も末尾に追加されます。", "OK")
                self.root.after(0, lambda: self.btn_save.config(state="normal", bg=self.col_fg, fg=self.col_bg))
            else:
                self.log_sys("警告: パケットが見つかりませんでした。", "WARN")

            self.root.after(0, lambda: self.btn_analyze.config(state="normal"))

        except Exception as e:
            self.log_sys(f"致命的なエラー: {e}", "ERR")
            self.root.after(0, lambda: self.btn_analyze.config(state="normal"))

    def save_csv(self):
        if not self.results: return
        
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if f:
            try:
                with open(f, "w", newline="") as csvfile:
                    writer = csv.writer(csvfile)
                    # ヘッダー
                    writer.writerow(["Index", "Status", "RecvCounter", "RxHex", "TxHex", "BitErrors", "ErrorRate(%)"])
                    
                    # データ行
                    for row in self.results:
                        writer.writerow([
                            row["Index"], row["Status"], row["RecvCounter"],
                            row["RxHex"], row["TxHex"], row["BitErrors"], row["ErrorRate(%)"]
                        ])
                    
                    # 末尾に全体統計を追加（Excelで見やすいように空白行を挟む）
                    writer.writerow([])
                    writer.writerow(["=== GLOBAL STATISTICS ==="])
                    writer.writerow(["Total Received Bits", self.global_stats["TotalBits"]])
                    writer.writerow(["Total Bit Errors", self.global_stats["TotalErrors"]])
                    writer.writerow(["Global Bit Error Rate (%)", f"{self.global_stats['GlobalBER']:.4f}"])

                self.log_sys(f"保存完了: {os.path.basename(f)}", "OK")
                messagebox.showinfo("成功", "解析結果と全体統計を保存しました！")
            except Exception as e:
                self.log_sys(f"保存エラー: {e}", "ERR")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogDecoderApp(root)
    root.mainloop()
