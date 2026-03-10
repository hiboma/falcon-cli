# ADR-0002 実装計画: macOS コード署名によるピアプロセス検証

## フェーズ概要

| フェーズ | 内容 | 依存 |
|---------|------|------|
| 1 | ピア PID 取得 | なし |
| 2 | 実行パス取得 | フェーズ 1 |
| 3 | コード署名検証 | フェーズ 2 |
| 4 | server.rs への統合 | フェーズ 3 |
| 5 | テスト | フェーズ 4 |

---

## フェーズ 1: ピア PID の取得

### 対象ファイル

- 新規: `src/daemon/peer_verify.rs`
- 変更: `Cargo.toml`

### タスク

1. macOS 用の `get_peer_pid` 関数を実装します
   - `getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)` を呼び出します
   - `SOL_LOCAL` (`0x0`) と `LOCAL_PEERPID` (`0x002`) は macOS 固有の定数であり、`libc` クレートに定義がない場合は手動で定義します
   - `tokio::net::UnixStream` から `std::os::unix::io::AsRawFd` で fd を取得します

2. Linux 用の `get_peer_pid` 関数を実装します
   - `tokio::net::UnixStream::peer_cred()` から `UCred.pid()` を取得します

3. プラットフォーム分岐を `#[cfg(target_os = "...")]` で実装します

---

## フェーズ 2: 実行パスの取得

### タスク

1. macOS 用の `get_peer_exe_path` 関数を実装します
   - `libproc` クレートの `pidpath(pid)` を使用します

2. Linux 用の `get_peer_exe_path` 関数を実装します
   - `/proc/<PID>/exe` の symlink を `std::fs::read_link` で解決します

3. daemon 自身の実行パスを `std::env::current_exe()` で取得する関数を実装します

### 依存関係の追加

```toml
[target.'cfg(target_os = "macos")'.dependencies]
libproc = "0.14"
```

---

## フェーズ 3: コード署名の検証

### タスク

1. macOS 用の `verify_code_signature` 関数を実装します
   - `SecStaticCodeCreateWithPath` でピアの実行パスから Code オブジェクトを作成します
   - `SecStaticCodeCheckValidity` で署名の有効性を検証します
   - daemon 自身の Code オブジェクトも同様に取得します
   - 両方の signing identifier を `SecCodeCopySigningInformation` で取得し、一致を確認します

2. 署名なしバイナリの処理を実装します
   - daemon と client の両方が未署名の場合は検証をスキップし、`true` を返します
   - 片方のみ署名されている場合は `false` を返します

3. Linux 用のフォールバックを実装します
   - daemon 自身の実行パスとピアの実行パスを比較します
   - 一致すれば `true` を返します

### 依存関係の追加

```toml
[target.'cfg(target_os = "macos")'.dependencies]
security-framework-sys = "3"
core-foundation = "0.10"
core-foundation-sys = "0.8"
```

### 公開 API

```rust
// src/daemon/peer_verify.rs

/// ピアプロセスの検証結果
pub struct PeerVerification {
    pub pid: i32,
    pub exe_path: String,
    pub signature_valid: bool,
}

/// UDS 接続のピアプロセスを検証します。
/// macOS: PID → 実行パス → コード署名検証
/// Linux: PID → 実行パス → パス一致確認
pub fn verify_peer(stream: &tokio::net::UnixStream) -> Result<PeerVerification>;
```

---

## フェーズ 4: server.rs への統合

### 対象ファイル

- 変更: `src/daemon/server.rs`
- 変更: `src/daemon/mod.rs`

### タスク

1. `accept_loop` 内で `verify_peer` を呼び出します
   - UID 検証の後、セッショントークン検証の前に配置します
   - 検証失敗時は接続を拒否し、監査ログに記録します

2. 検証結果を監査ログに含めます
   - ピアの PID、実行パス、署名検証結果を記録します

3. 検証の有効/無効を設定可能にします
   - `daemon.toml` に `[security] verify_code_signature = true` を追加します
   - デフォルトは `true`（macOS）/ `true`（Linux、パス一致確認のみ）

---

## フェーズ 5: テスト

### タスク

1. `get_peer_pid` のユニットテストを追加します
   - UDS ペアを作成し、PID が `std::process::id()` と一致することを確認します

2. `get_peer_exe_path` のユニットテストを追加します
   - 自プロセスの PID に対して実行パスが取得できることを確認します

3. コード署名検証のテストを追加します
   - 自プロセスの実行バイナリに対して署名検証を実行します
   - テストバイナリは ad-hoc 署名されているため、署名の有無に応じた分岐を確認します

4. 統合テストを追加します
   - daemon を起動し、同一バイナリからの接続が許可されることを確認します

---

## ファイル構成（完成後）

```
src/daemon/
├── mod.rs
├── protocol.rs
├── server.rs         # verify_peer の呼び出しを追加
├── handler.rs
├── client.rs
├── security.rs
└── peer_verify.rs    # 新規: プラットフォーム固有のピア検証
    ├── #[cfg(target_os = "macos")]  — LOCAL_PEERPID + proc_pidpath + SecCode
    └── #[cfg(target_os = "linux")]  — SO_PEERCRED + /proc/PID/exe
```

## 依存関係の追加（まとめ）

```toml
[target.'cfg(target_os = "macos")'.dependencies]
libproc = "0.14"
security-framework-sys = "3"
core-foundation = "0.10"
core-foundation-sys = "0.8"
```

Linux では追加の依存関係はありません。
