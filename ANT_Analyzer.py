import serial
import time
import argparse
import csv
from datetime import datetime
from typing import Optional, Tuple

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

# === メイン処理 ===
def main():
    parser = argparse.ArgumentParser(description="KISS受信・解析ツール")
    parser.add_argument("--port", default=RX_PORT, help="受信シリアルポート")
    parser.add_argument("--baud", type=int, default=BAUDRATE, help="ボーレート")
    parser.add_argument("--size", type=int, default=PACKET_SIZE, help="送信側と同じパケットサイズを指定")
    parser.add_argument("--pn9-seed", type=lambda x: int(x, 0), default=0x1FF, help="送信側と同じシード")
    parser.add_argument("--pn9-reset-each", action="store_true", help="送信側がreset-eachなら指定")
    parser.add_argument("--log", default="rx_log.csv", help="ログ保存ファイル名")
    
    args = parser.parse_args()

    # 初期化
    if not args.pn9_reset_each:
        _pn9_init(args.pn9_seed)
    
    next_expected_counter = 0
    total_packets = 0
    ok_packets = 0
    packet_loss_count = 0
    bit_error_packets = 0
    
    # ログファイル準備
    with open(args.log, mode='w', newline='') as logfile:
        writer = csv.writer(logfile)
        writer.writerow(["Timestamp", "Status", "RecvCounter", "ExpectedCounter", "BitErrors", "RawHex"])
        
        print(f"Waiting for data on {args.port}...")
        print(f"Config: Size={args.size}, ResetPN9={args.pn9_reset_each}")
        print("-" * 60)

        try:
            with serial.Serial(args.port, args.baud, timeout=0.1) as ser:
                reader = KissReader(ser)
                
                while True:
                    frame = reader.read_frame()
                    if frame is None:
                        continue # データ待ち
                    
                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    
                    # 連続モードの場合の同期ズレ補正準備
                    # 解析前に現在のLFSR状態をバックアップ（失敗時のロールバック用等、今回は簡易実装）
                    
                    # まずパケットからカウンタだけ読んで、ロスがあったらLFSRを空回しする
                    # フレーム構造: [CMD(1)] [ID(1)] [CNT(2)] ...
                    # 最低でも4バイト必要
                    temp_status = "UNKNOWN"
                    recv_cnt = -1
                    bit_err = 0
                    
                    # 簡易解析でカウンタを取得して同期合わせ
                    packet_len_ok = False
                    start_idx = 0
                    if len(frame) > 0 and frame[0] == 0x00: start_idx = 1
                    
                    if len(frame) >= (start_idx + 3) and frame[start_idx] == 0x42:
                        recv_cnt = (frame[start_idx+1] << 8) | frame[start_idx+2]
                        
                        # パケットロス判定とLFSR同期
                        if not args.pn9_reset_each:
                            diff = (recv_cnt - next_expected_counter) & 0xFFFF
                            if diff > 0 and diff < 1000: # 1000パケット以内の抜けならロスとみなす
                                print(f"!! LOSS DETECTED: Skipped {diff} packets (Exp: {next_expected_counter}, Got: {recv_cnt})")
                                packet_loss_count += diff
                                # 抜けた分のPN9を空回しして捨てる
                                pn9_bytes_per_pkt = args.size - 3
                                if pn9_bytes_per_pkt > 0:
                                    generate_pn9_bytes_continuous(pn9_bytes_per_pkt * diff)
                                next_expected_counter = recv_cnt
                            elif diff > 60000: # カウンタが一周した場合などの逆転現象（リセット扱い）
                                # ここでは単純に同期させる
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

                    # 次の期待値
                    if valid_cnt != -1:
                        next_expected_counter = (valid_cnt + 1) & 0xFFFF
                    
                    # ログ書き込み
                    writer.writerow([timestamp, status, valid_cnt, next_expected_counter, bit_err, frame.hex()])
                    logfile.flush() # リアルタイムで書き込む

        except KeyboardInterrupt:
            print("\n" + "="*30)
            print(" STATISTICS")
            print("="*30)
            print(f"Total Received Packets: {total_packets}")
            print(f"OK Packets:             {ok_packets}")
            print(f"Packet Loss Detected:   {packet_loss_count}")
            print(f"Corrupted Packets:      {bit_error_packets}")
            if total_packets > 0:
                print(f"Success Rate:           {(ok_packets/total_packets)*100:.2f}%")
            print(f"Log saved to: {args.log}")

        except serial.SerialException as e:
            print(f"Serial Error: {e}")

if __name__ == "__main__":
    main()