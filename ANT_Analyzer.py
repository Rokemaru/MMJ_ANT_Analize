import time
import argparse
import csv
from datetime import datetime
from typing import Optional, Tuple
import serial.tools.list_ports

"""
KISS受信＆解析ツール
機能:
1. KISSフレームのデコード
2. パケットカウンタによるロス検出
3. PN9データによるビット誤り検出
4. ログ保存 (CSV)
"""

# === 設定 (デフォルト) ===
RX_PORT = "COM11"  # 受信側のポートに変えてください
BAUDRATE = 9600
PACKET_SIZE = 16   # 送信側と合わせる必要があります

# === KISS定数 ===
FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD

# === PN9 生成ロジック (送信側と完全一致させる) ===
_pn9_lfsr: Optional[int] = None

def _pn9_init(seed: int):
    global _pn9_lfsr
    s = seed & 0x1FF
    if s == 0: s = 0x1FF
    _pn9_lfsr = s

def generate_pn9_bytes_continuous(length: int) -> bytes:
    global _pn9_lfsr
    if length <= 0: return b""
    if _pn9_lfsr is None: _pn9_init(0x1FF)
    
    lfsr = _pn9_lfsr
    out = bytearray()
    current_byte = 0
    bit_pos = 0
    while len(out) < length:
        out_bit = lfsr & 0x01
        current_byte |= (out_bit << bit_pos)
        bit_pos += 1
        if bit_pos == 8:
            out.append(current_byte)
            current_byte = 0
            bit_pos = 0
        feedback = ((lfsr >> 0) ^ (lfsr >> 4)) & 0x01
        lfsr >>= 1
        lfsr |= (feedback << 8)
        _pn9_lfsr = lfsr
    return bytes(out)

def generate_pn9_bytes_reset_each(length: int, seed: int) -> bytes:
    if length <= 0: return b""
    lfsr = seed & 0x1FF
    if lfsr == 0: lfsr = 0x1FF
    out = bytearray()
    current_byte = 0
    bit_pos = 0
    while len(out) < length:
        out_bit = lfsr & 0x01
        current_byte |= (out_bit << bit_pos)
        bit_pos += 1
        if bit_pos == 8:
            out.append(current_byte)
            current_byte = 0
            bit_pos = 0
        feedback = ((lfsr >> 0) ^ (lfsr >> 4)) & 0x01
        lfsr >>= 1
        lfsr |= (feedback << 8)
    return bytes(out)

# === 受信処理 ===
class KissReader:
    def __init__(self, ser):
        self.ser = ser
        self.buffer = bytearray()
        self.in_frame = False
        self.escape_mode = False

    def read_frame(self) -> Optional[bytes]:
        """1バイトずつ読み込み、フレームが完成したらbytesを返す。なければNone"""
        while self.ser.in_waiting > 0:
            b = ord(self.ser.read(1))
            
            if b == FEND:
                if self.in_frame and len(self.buffer) > 0:
                    # フレーム完了
                    frame = bytes(self.buffer)
                    self.buffer = bytearray()
                    self.in_frame = False # 次のFENDまで待機状態へ（連続FEND対策）
                    self.escape_mode = False
                    return frame
                else:
                    # フレーム開始または連続FEND
                    self.buffer = bytearray()
                    self.in_frame = True
                    self.escape_mode = False
            elif self.in_frame:
                if b == FESC:
                    self.escape_mode = True
                else:
                    if self.escape_mode:
                        if b == TFEND:
                            self.buffer.append(FEND)
                        elif b == TFESC:
                            self.buffer.append(FESC)
                        else:
                            # 不正なエスケープだがそのまま記録
                            self.buffer.append(b)
                        self.escape_mode = False
                    else:
                        self.buffer.append(b)
        return None

def analyze_packet(payload: bytes, expected_counter: int, packet_size: int, pn9_reset: bool, pn9_seed: int) -> Tuple[str, int, int]:
    """
    パケットを解析する
    戻り値: (ステータス文字列, 抽出したカウンタ, ビット誤り数)
    """
    # 1. サイズチェック (コマンド0x00を除去済みの前提)
    # 受信側では「コマンドバイト(0x00)」がフレームに含まれているか確認が必要
    # 通常 KISSフレーム = [FEND] [CMD] [DATA...] [FEND]
    # このスクリプトのKissReaderはFENDを除去した中身を返す。
    # 先頭が0x00(Data Frame)であるはず。
    
    data_start_idx = 0
    if len(payload) > 0 and payload[0] == 0x00:
        data_start_idx = 1 # 標準的なKISSは0バイト目がコマンド
    
    actual_data = payload[data_start_idx:]
    
    if len(actual_data) != packet_size:
        return ("SIZE_MISMATCH", -1, 0)

    # 2. ヘッダチェック (ID=0x42)
    if actual_data[0] != 0x42:
        return ("INVALID_ID", -1, 0)

    # 3. カウンタ取得
    recv_counter = (actual_data[1] << 8) | actual_data[2]

    # 4. PN9チェック
    pn9_len = packet_size - 3
    if pn9_len > 0:
        recv_pn9 = actual_data[3:]
        
        # 正解データの生成
        if pn9_reset:
            expected_pn9 = generate_pn9_bytes_reset_each(pn9_len, pn9_seed)
        else:
            # 連続モードの場合、ここに来る前に「前のパケットとの差分」を埋めておく必要がある
            # この関数内では「今のLFSR状態」から生成するだけにする
            expected_pn9 = generate_pn9_bytes_continuous(pn9_len)
            
        # 比較
        bit_errors = 0
        if len(recv_pn9) == len(expected_pn9):
            for i in range(len(recv_pn9)):
                diff = recv_pn9[i] ^ expected_pn9[i]
                bit_errors += bin(diff).count('1')
        else:
            return ("PN9_LEN_ERR", recv_counter, 0)
        
        if bit_errors > 0:
            return ("DATA_CORRUPT", recv_counter, bit_errors)

    return ("OK", recv_counter, 0)

def main():
    # --- 引数解析の準備 ---
    parser = argparse.ArgumentParser(description="KISS受信・解析ツール (CUI高信頼モード)")
    parser.add_argument("--port", default=None, help="指定しない場合は対話モードで選択")
    parser.add_argument("--baud", type=int, default=BAUDRATE, help="ボーレート")
    parser.add_argument("--size", type=int, default=PACKET_SIZE, help="パケットサイズ")
    parser.add_argument("--pn9-seed", type=lambda x: int(x, 0), default=0x1FF, help="PN9初期シード")
    parser.add_argument("--pn9-reset-each", action="store_true", help="パケット毎リセット")
    parser.add_argument("--log", default="rx_log.csv", help="ログファイル名")
    
    args = parser.parse_args()

    # ==========================================
    # ★ ポート選択ロジック (ここを追加・変更) ★
    # ==========================================
    selected_port = args.port

    # ポートがコマンド引数で指定されていなければ、リストから選ばせる
    if selected_port is None:
        print("\n=== SERIAL PORT SELECTION ===")
        ports = list(serial.tools.list_ports.comports())
        
        if not ports:
            print(" [ERROR] No serial ports found!")
            return

        for i, p in enumerate(ports):
            print(f"  [{i}] {p.device} ({p.description})")
        
        print("=============================")
        while True:
            try:
                val = input(f"Select Port Number (0-{len(ports)-1}) > ")
                idx = int(val)
                if 0 <= idx < len(ports):
                    selected_port = ports[idx].device
                    break
                else:
                    print("Invalid number.")
            except ValueError:
                print("Please enter a number.")
    
    # ==========================================

    # 初期化
    if not args.pn9_reset_each:
        _pn9_init(args.pn9_seed)
    
    next_expected_counter = 0
    total_packets = 0
    ok_packets = 0
    packet_loss_count = 0
    bit_error_packets = 0
    
    # ログファイル準備
    # ファイル名にタイムスタンプをつけて上書き防止するとさらに安全かも
    log_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{args.log}"

    print(f"\n[TARGET LOCKED] Port: {selected_port}, Baud: {args.baud}")
    print(f"Logging to: {log_filename}")
    print("-" * 60)

    try:
        with open(log_filename, mode='w', newline='') as logfile:
            writer = csv.writer(logfile)
            writer.writerow(["Timestamp", "Status", "RecvCounter", "ExpectedCounter", "BitErrors", "RawHex"])
            
            with serial.Serial(selected_port, args.baud, timeout=0.1) as ser:
                reader = KissReader(ser)
                
                while True:
                    frame = reader.read_frame()
                    if frame is None:
                        continue 
                    
                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    
                    # --- 以下、元の解析ロジックと同じ ---
                    start_idx = 0
                    if len(frame) > 0 and frame[0] == 0x00: start_idx = 1
                    
                    recv_cnt = -1
                    bit_err = 0
                    
                    # 簡易解析・同期
                    if len(frame) >= (start_idx + 3) and frame[start_idx] == 0x42:
                        recv_cnt = (frame[start_idx+1] << 8) | frame[start_idx+2]
                        
                        if not args.pn9_reset_each:
                            diff = (recv_cnt - next_expected_counter) & 0xFFFF
                            if diff > 0 and diff < 1000:
                                print(f"!! LOSS DETECTED: Skipped {diff} packets")
                                packet_loss_count += diff
                                pn9_bytes_per_pkt = args.size - 3
                                if pn9_bytes_per_pkt > 0:
                                    generate_pn9_bytes_continuous(pn9_bytes_per_pkt * diff)
                                next_expected_counter = recv_cnt
                            elif diff > 60000:
                                next_expected_counter = recv_cnt

                    # 詳細解析
                    status, valid_cnt, bit_err = analyze_packet(
                        frame, next_expected_counter, args.size, args.pn9_reset_each, args.pn9_seed
                    )

                    # 統計更新
                    total_packets += 1
                    if status == "OK":
                        ok_packets += 1
                        print(f"[{timestamp}] OK  Seq={valid_cnt:05d}")
                    else:
                        if status == "DATA_CORRUPT":
                            bit_error_packets += 1
                            print(f"[{timestamp}] NG  Seq={valid_cnt:05d} ErrBits={bit_err} <DATA CORRUPT>")
                        else:
                            print(f"[{timestamp}] BAD Seq={valid_cnt} {status}")

                    if valid_cnt != -1:
                        next_expected_counter = (valid_cnt + 1) & 0xFFFF
                    
                    writer.writerow([timestamp, status, valid_cnt, next_expected_counter, bit_err, frame.hex()])
                    logfile.flush()

    except KeyboardInterrupt:
        print("\n" + "="*30)
        print(" STATISTICS (FINAL)")
        print("="*30)
        print(f"Total Received: {total_packets}")
        print(f"OK Packets:     {ok_packets}")
        print(f"Packet Loss:    {packet_loss_count}")
        print(f"Bit Errors:     {bit_error_packets}")
        if total_packets > 0:
            rate = (ok_packets / total_packets) * 100
            print(f"Success Rate:   {rate:.2f}%")
        print(f"Log saved to:   {log_filename}")

    except serial.SerialException as e:
        print(f"[CRITICAL] Serial Error: {e}")

# ... (if __name__ == "__main__": main() はそのまま)

if __name__ == "__main__":
    main()