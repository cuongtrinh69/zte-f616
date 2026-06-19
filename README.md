# ZTE F616 Codec

Công cụ dòng lệnh viết bằng Ruby để **giải mã**, **mã hóa** và **kiểm tra** file cấu hình nhị phân `.bin` của thiết bị ZTE F616 (modem/ONT).

File cấu hình `.bin` của ZTE F616 được mã hóa bằng AES-256-CBC và nén bằng zlib. Công cụ này cho phép chuyển đổi qua lại giữa định dạng nhị phân (`.bin`) và định dạng XML có thể đọc được.

---

## Tính năng

- **`inspect`** — Đọc và hiển thị thông tin header của file `.bin` mà không cần khóa. Nếu cung cấp khóa, sẽ giải mã và hiển thị thêm thông tin nội dung.
- **`decode`** — Giải mã file `.bin` thành file XML có thể đọc và chỉnh sửa.
- **`encode`** — Mã hóa file XML trở lại thành file `.bin` dựa trên một file template.
- **`roundtrip`** — Kiểm tra tính toàn vẹn: giải mã rồi mã hóa lại, so sánh SHA-256 với file gốc.

---

## Yêu cầu

- **Ruby** phiên bản **2.7 trở lên** (đã kiểm tra trên Ruby 4.0.5).
- **Không cần cài thêm gem nào.** Chương trình chỉ sử dụng thư viện có sẵn của Ruby:
  - `digest` — tính SHA-256
  - `openssl` — mã hóa/giải mã AES-256-CBC
  - `optparse` — phân tích tham số dòng lệnh
  - `zlib` — nén/giải nén dữ liệu
- Không giới hạn hệ điều hành (Windows, Linux, macOS đều dùng được).

---

## Cài đặt

```bash
git clone https://github.com/kaiblue/zte-f616-codec.git
cd zte-f616-codec
```

Không cần bước cài đặt thêm.

---

## Cách sử dụng

### Cú pháp chung

```bash
ruby zte_f616_codec.rb <lệnh> [tham-số]
```

---

### 1. `inspect` — Xem thông tin file `.bin`

Kiểm tra header mà không cần khóa:

```bash
ruby zte_f616_codec.rb inspect config.bin
```

Kiểm tra đầy đủ (bao gồm giải mã nội dung) khi có khóa:

```bash
ruby zte_f616_codec.rb inspect config.bin --key-string KEY --iv-string IV
```

**Ví dụ đầu ra (không có khóa):**

```
File size:         8968
SHA-256:           bdb1fabac6827bceb6fb7445a31093e275f29b3add71853b461118f194643ed0
Signature:         F616
Payload type:      5
Outer header size: 88
Inner length:      8865
Cipher length:     8880
```

**Ví dụ đầu ra (có khóa):**

```
File size:         8968
SHA-256:           bdb1fabac6827bceb6fb7445a31093e275f29b3add71853b461118f194643ed0
Signature:         F616
Payload type:      5
Outer header size: 88
Inner length:      8865
Cipher length:     8880
AES:               AES-256-CBC
Padding:           zero padding
Zlib chunks:       1
Decoded XML size:  24576
XML SHA-256:       ...
```

---

### 2. `decode` — Giải mã `.bin` thành XML

```bash
ruby zte_f616_codec.rb decode config.bin config.xml --key-string KEY --iv-string IV
```

**Ví dụ đầu ra:**

```
[+] Decoded: config.bin -> config.xml
[+] XML bytes: 24576
[+] Zlib chunks: 1
[+] XML SHA-256: ...
```

---

### 3. `encode` — Mã hóa XML thành `.bin`

Cần một file `.bin` gốc làm **template** để sao chép header:

```bash
ruby zte_f616_codec.rb encode \
  --template config.bin \
  --xml config.xml \
  --out new.bin \
  --key-string KEY \
  --iv-string IV
```

**Ví dụ đầu ra:**

```
[+] Encoded: config.xml -> new.bin
[+] Output bytes: 8968
[+] SHA-256: ...
[+] Internal round-trip: OK
[+] Byte-identical to template: YES
```

---

### 4. `roundtrip` — Kiểm tra tính toàn vẹn

Giải mã rồi mã hóa lại, kiểm tra xem file đầu ra có byte-identical với file gốc không:

```bash
ruby zte_f616_codec.rb roundtrip config.bin --key-string KEY --iv-string IV
```

Lưu file kết quả (tùy chọn):

```bash
ruby zte_f616_codec.rb roundtrip config.bin --out rebuilt.bin --key-string KEY --iv-string IV
```

**Ví dụ đầu ra (thành công):**

```
Ruby:             4.0.5
Zlib:             1.3.1
Original SHA-256: bdb1fabac6827bceb6fb7445a31093e275f29b3add71853b461118f194643ed0
Rebuilt SHA-256:  bdb1fabac6827bceb6fb7445a31093e275f29b3add71853b461118f194643ed0
Byte-identical:   YES
```

Nếu không byte-identical, chương trình thoát với mã lỗi `2` và hiển thị vị trí byte đầu tiên khác nhau.

---

## Định dạng file

### File `.bin` (cấu hình nhị phân ZTE F616)

| Thành phần | Kích thước | Mô tả |
|---|---|---|
| Outer header | 88 byte (0x58) | Magic `04 03 02 01`, chữ ký `F616`, payload type, kích thước |
| Ciphertext | `cipher_len` byte | Nội dung mã hóa AES-256-CBC, bội số của 16 |

### Inner payload (sau khi giải mã)

| Thành phần | Mô tả |
|---|---|
| Inner header | 60 byte, magic `01 02 03 04`, CRC, thông tin chunk |
| Chunk(s) | Mỗi chunk: header 12 byte + dữ liệu zlib |

### File XML

Định dạng XML cấu hình thiết bị ZTE, ví dụ:

```xml
<DB>
  <Tbl name="DBBase" RowCount="1">
    <Row No="0">
      <DM name="IFInfo" val="..."/>
    </Row>
  </Tbl>
</DB>
```

---

## Cấu trúc dự án

```
zte-f616-codec/
├── zte_f616_codec.rb   # Toàn bộ mã nguồn công cụ
├── README.md           # Tài liệu hướng dẫn (file này)
├── LICENSE             # Giấy phép MIT
└── .gitignore          # Danh sách file không đưa lên Git
```

---

## Lưu ý an toàn

> ⚠️ **Quan trọng — đọc trước khi sử dụng**

- **Sao lưu file gốc** trước khi thực hiện bất kỳ thao tác nào.
- **Không tải file `.bin` hoặc `.xml` cấu hình thật lên nơi công khai** — chúng có thể chứa mật khẩu WiFi, thông tin đăng nhập quản trị và cấu hình mạng nội bộ.
- **Không ghi đè file gốc** nếu chưa có bản sao lưu.
- **Chỉ sử dụng trên thiết bị hoặc dữ liệu mà bạn có quyền quản lý.** Sử dụng trên thiết bị của người khác mà không được phép là vi phạm pháp luật.
- Khóa (`--key-string`) và vector khởi tạo (`--iv-string`) là thông tin nhạy cảm — không chia sẻ công khai.

---

## Các lỗi thường gặp

### `ruby: command not found` hoặc `'ruby' is not recognized`
Ruby chưa được cài đặt hoặc chưa có trong PATH.
→ Tải Ruby tại [https://www.ruby-lang.org](https://www.ruby-lang.org) hoặc dùng [RubyInstaller](https://rubyinstaller.org) trên Windows.

### `File ngắn hơn header F616 0x58 byte`
File đầu vào không phải file cấu hình ZTE F616 hợp lệ, hoặc file bị hỏng/cắt ngắn.

### `Sai outer magic: ...`
File không có chữ ký `04 03 02 01` ở đầu — không phải định dạng F616.

### `Chữ ký không phải F616: ...`
File có outer magic đúng nhưng chữ ký bên trong không phải `F616`.

### `Sai kích thước file: file=X, expected=Y`
File bị cắt ngắn hoặc bị thêm dữ liệu thừa.

### `Sai header CRC` hoặc `Sai payload CRC`
Dữ liệu bị hỏng, hoặc khóa/IV sai dẫn đến giải mã ra dữ liệu không hợp lệ.

### `Padding sau inner payload không phải toàn byte 0`
Khóa hoặc IV không đúng — dữ liệu giải mã ra không hợp lệ.

### `No such file or directory`
Đường dẫn file đầu vào không tồn tại. Kiểm tra lại tên file và thư mục hiện tại.

### `Permission denied`
Không có quyền đọc file đầu vào hoặc ghi file đầu ra. Kiểm tra quyền truy cập file.

### `Internal round-trip thất bại`
Lỗi nội bộ: file vừa mã hóa không giải mã lại được đúng. Không nên xảy ra trong điều kiện bình thường.

---

## Giấy phép

Dự án này được phát hành theo giấy phép [MIT](LICENSE).
