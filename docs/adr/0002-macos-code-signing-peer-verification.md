# ADR-0002: macOS コード署名によるピアプロセス検証

## ステータス

提案中

## 日付

2026-03-10

## コンテキスト

ADR-0001 で導入した agent モードでは、以下のセキュリティレイヤーで接続を制御しています。

1. UDS パーミッション (`0700`)
2. ピア UID 検証 (`UCred`)
3. セッショントークン (`FALCON_AGENT_TOKEN`)
4. コマンドホワイトリスト
5. レートリミット

しかし、セッショントークンは「知識ベース」の認証です。トークンが環境変数として Claude Code のプロセス空間に存在するため、以下のリスクが残ります。

- 同一ユーザーの他プロセスが `FALCON_AGENT_TOKEN` 環境変数を読み取れる可能性があります
- `/proc/<pid>/environ`（Linux）や `ps eww`（macOS）で環境変数が見える場合があります
- トークンが意図せずログやエラー出力に含まれる可能性があります

トークンの漏洩があっても接続を拒否できる「正体ベース」の認証レイヤーが必要です。

## 調査結果

macOS 固有のセキュリティ API を調査しました。

### 実用性: 高

| API | 用途 | Rust エコシステム |
|-----|------|------------------|
| `LOCAL_PEERPID` | UDS 接続元の PID を取得する macOS 固有の `getsockopt` オプション | `libc` クレートの FFI |
| `proc_pidpath` | PID から実行ファイルの絶対パスを取得 | `libproc` クレート |
| `SecStaticCodeCheckValidity` | 実行ファイルのコード署名を検証 | `security-framework-sys` クレート |

### 実用性: 中

| API | 用途 | 備考 |
|-----|------|------|
| Hardened Runtime | コードインジェクション防止 | `codesign --options runtime` で有効化。コード変更不要 |
| `kqueue` / `EVFILT_PROC` | クライアントプロセスの終了検知 | セッション管理の補助 |

### 実用性: 低（過剰または不適切）

| API | 却下理由 |
|-----|---------|
| XPC Services | macOS 専用、Rust からの利用が困難、クロスプラットフォーム不可 |
| Endpoint Security | root 必須、Apple の entitlement 取得が必要、IPC 認証には過剰 |
| Keychain Services | agent コンテキストからのアクセスに制限あり |
| TCC | IPC セキュリティに関与しない |
| audit_token | UDS 経由では直接取得できない（XPC 専用） |

## 決定

macOS 環境において、`LOCAL_PEERPID` → `proc_pidpath` → `SecStaticCodeCheckValidity` を組み合わせたコード署名検証を導入します。

### 検証フロー

```
クライアント接続を accept
  ↓
LOCAL_PEERPID (getsockopt) で接続元 PID を取得
  ↓
proc_pidpath(PID) で実行ファイルの絶対パスを取得
  ↓
SecStaticCodeCreateWithPath で Code オブジェクトを作成
  ↓
SecStaticCodeCheckValidity でコード署名を検証
  ↓
署名情報から signing identifier を抽出
  ↓
agent 自身の signing identifier と一致するか確認
  ↓
一致 → 接続を許可、不一致 → 接続を拒否
```

### セキュリティレイヤーの全体像

```
レイヤー 1: UDS パーミッション (0700)         → 他ユーザーのアクセスを OS レベルで拒否
レイヤー 2: ピア UID 検証 (UCred)             → UID 不一致の接続を拒否
レイヤー 3: コード署名検証 (macOS)             → 署名が一致しないバイナリからの接続を拒否 [NEW]
レイヤー 4: セッショントークン (SSH Agent 方式) → トークン不一致のリクエストを拒否
レイヤー 5: コマンドホワイトリスト              → 許可外コマンドの実行を拒否
レイヤー 6: レートリミット                      → 異常頻度のリクエストを拒否
レイヤー 7: 監査ログ                            → 全リクエストを記録し事後追跡を可能にする
```

### プラットフォーム分岐

| 検証ステップ | macOS | Linux |
|-------------|-------|-------|
| ピア PID 取得 | `LOCAL_PEERPID` (`getsockopt`) | `SO_PEERCRED` (`UCred.pid`) |
| 実行パス取得 | `proc_pidpath` | `/proc/<PID>/exe` の readlink |
| バイナリ検証 | `SecStaticCodeCheckValidity` (コード署名) | 実行パスの一致確認（署名検証なし） |

Linux ではコード署名の仕組みがないため、実行パスの一致確認（agent 自身のパスと接続元のパスの比較）をフォールバックとします。

### コード署名の運用

開発時は ad-hoc 署名（`codesign -s -`）でも動作します。配布時は Developer ID で署名することで、Team ID ベースの検証が可能になります。

署名なしバイナリ同士の接続（開発中のデバッグ）も許可するため、agent と client の両方が未署名の場合はこのレイヤーをスキップします。

### リリース時のコード署名

配布方法に応じて、コード署名の要否が異なります。

#### 署名レベルと検証動作

| agent | client | 検証結果 | 補足 |
|--------|--------|---------|------|
| 未署名 | 未署名 | 許可（スキップ） | 開発時、ソースビルド |
| 同一バイナリ | 同一バイナリ | 許可（パス一致） | 通常の利用形態 |
| 署名済み | 同一 identifier で署名済み | 許可 | 正式リリース |
| 署名済み | 未署名 | 拒否 | 改ざん検知 |
| 未署名 | 署名済み | 拒否 | 不整合 |
| 署名済み | 異なる identifier で署名済み | 拒否 | 別バイナリ |

#### 配布シナリオ別の対応

**Homebrew tap / ソースビルド**

署名は不要です。`cargo install` やソースからのビルドでは署名が付かないため、agent と client は同一の未署名バイナリとなり、パス一致でコード署名検証はスキップされます。

**GitHub Releases でのバイナリ配布（署名なし）**

署名なしでも動作します。agent と client は同一バイナリなのでパス一致で許可されます。ただし、macOS の Gatekeeper が「開発元を確認できません」の警告を表示します。ユーザーは `xattr -d com.apple.quarantine falcon-cli` または「システム設定 > セキュリティ」での許可が必要です。

**GitHub Releases でのバイナリ配布（ad-hoc 署名）**

`codesign -s -` で ad-hoc 署名を付けることができます。CI（GitHub Actions の macOS runner）で署名可能であり、追加のデータは不要です。同じ ad-hoc 署名のバイナリ同士は signing identifier が一致するため、検証が機能します。ただし Gatekeeper の警告は解消されません。

```bash
# GitHub Actions での ad-hoc 署名
cargo build --release
codesign -s - --identifier "com.hiboma.falcon-cli" target/release/falcon-cli
```

**GitHub Releases でのバイナリ配布（Developer ID 署名）**

Gatekeeper の警告を解消するには Developer ID 署名が必要です。Apple Developer Program への加入（年間 $99）と、署名用証明書の取得が前提となります。GitHub Actions の secrets に証明書と秘密鍵を登録し、CI でビルド後に署名します。

```bash
# Developer ID 署名
codesign -s "Developer ID Application: Your Name (TEAM_ID)" \
  --options runtime \
  --identifier "com.hiboma.falcon-cli" \
  target/release/falcon-cli

# (任意) Apple の公証 (Notarization)
# 初回起動時の Gatekeeper チェックをスムーズにする
xcrun notarytool submit falcon-cli.zip \
  --apple-id "..." --password "..." --team-id "..."
```

#### 推奨

初期リリースでは署名なしまたは ad-hoc 署名で配布し、Homebrew tap での配布を主要チャネルとします。Gatekeeper 対応が必要になった時点で Developer ID 署名の導入を検討します。

### PID 再利用の TOCTOU リスクへの対応

PID を取得してから `proc_pidpath` を呼ぶまでの間にプロセスが入れ替わる理論的リスクがあります。このリスクは以下の理由から許容可能と判断します。

1. PID 再利用には元プロセスの終了と新プロセスの起動が必要であり、`getsockopt` から `proc_pidpath` までの数マイクロ秒の間に発生する確率は極めて低いです
2. セッショントークン検証が追加のレイヤーとして存在するため、PID 偽装だけでは接続が成立しません
3. UDS 接続は接続確立時にソケットバッファが割り当てられるため、元プロセスが終了すると接続自体が切断されます

## 影響

### 変更が必要なモジュール

- 変更: `src/agent/server.rs` — accept 後にコード署名検証を実行
- 新規: `src/agent/peer_verify.rs` — プラットフォーム固有のピア検証ロジック

### 依存関係の追加

- `libproc` — `proc_pidpath` のバインディング（macOS のみ）
- `security-framework-sys` — コード署名 API のバインディング（macOS のみ）
- `core-foundation` — CoreFoundation 型の操作（macOS のみ）

これらは `#[cfg(target_os = "macos")]` で条件付きコンパイルします。

### 後方互換性

- Linux 環境では実行パスの一致確認にフォールバックします
- 署名なしバイナリでは検証をスキップし、既存のトークン認証で保護します
- 既存の動作に変更はありません
