# ADR-0005: Keychain による client_secret の保管

## ステータス

採択 (実装済み)

## 日付

2026-04-21

## コンテキスト

`falcon-cli` の OAuth2 `client_secret` は、これまで以下のいずれかでのみ
保管されていました。

- `FALCON_CLIENT_SECRET` 環境変数
- `./.falcon-credentials.toml` または `~/.config/falcon-cli/credentials.toml`
  に平文記載

### 脅威

平文ファイル保管には以下のリスクがあります。

1. **バックアップ経由の漏洩**: Time Machine、iCloud Drive、`tar -czf`
   など、ホームディレクトリ単位のバックアップに `client_secret` が
   そのまま含まれます。バックアップは複製・配布されやすく、いったん
   流出すると回収不可能です。
2. **同一ユーザー権限のプロセスからの読み取り**: ファイルパーミッション
   `0600` のみが防御層です。同じ uid で動く任意のマルウェア・スクリプト
   が無条件に読めます。macOS Keychain は ACL で「特定の署名済みアプリの
   み」に制限できます。
3. **dotfiles リポジトリへの誤コミット**: `.gitignore` の漏れや
   `git add -A` 経由で公開リポジトリに push される事故が起こりえます。
4. **AI エージェントによるコンテキスト汚染**: Claude Code 等の LLM
   エージェントが「設定確認のため」と称して `cat credentials.toml` を
   実行し、出力が会話履歴・PR 説明・サポートログに残るリスクが
   あります。

### 制約

- macOS 環境を主要ターゲットとします。Linux / Windows サポートは
  trait 設計で将来追加可能とします。
- 既存の toml 利用者がアップグレードしただけで挙動が変わらないこと
  (後方互換)。
- agent モード (ADR-0001) との整合性を保つこと。agent は親プロセスで
  解決した credentials を子プロセスのメモリに渡すため、Keychain への
  追加読み込みが per-request で発生してはなりません。
- CI / sandbox 環境 (default keychain が無い) で resolve が破綻しない
  こと。

## 決定

### CredentialStore trait による抽象化

`src/config/credential_store.rs` に `CredentialStore` trait を定義し、
プラットフォーム固有の保管バックエンドを抽象化します。

```rust
pub trait CredentialStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}
```

実装は 3 種類です。

| 実装 | 用途 | 配置 |
|---|---|---|
| `KeychainStore` | macOS Keychain (本番) | `#[cfg(target_os = "macos")]` |
| `MemoryStore` | テスト用 in-memory | `#[cfg(test)]` |
| なし | 非 macOS ターゲット | `default_store()` が `None` を返す |

`KeychainStore` は `keyring` crate (`apple-native` feature) 経由で
`Security.framework` の `SecItemAdd` / `SecItemCopyMatching` を
呼び出します。

### Keychain エントリの属性

| 属性 | 値 |
|---|---|
| Kind | `application password` (`kSecClassGenericPassword`) |
| Service | `dev.falcon-cli` |
| Account | `client_secret` |
| Keychain | login (デフォルト) |

Service 名は bundle identifier 風の固定文字列です。Account 名は
`KEY_CLIENT_SECRET` 定数として `src/config/credential_store.rs` で
公開しています。

### Resolve の優先順位

`FalconCredentials::resolve()` は client_secret を以下の順で解決します。

```
FALCON_CLIENT_SECRET (env) > Keychain > credentials.toml > None
```

client_id / base_url / member_cid は機密性が低いため Keychain に格納せず、
CLI args > env > toml の従来順を維持します。

### StoreError の分類とフォールバック判断

`StoreError` を 2 variant に分けます。

| Variant | 意味 | resolve の挙動 |
|---|---|---|
| `Unavailable(msg)` | 保管バックエンドそのものが存在しない (非 macOS、CI sandbox の default keychain なし) | 静かに toml にフォールバック |
| `Backend(msg)` | バックエンドへのアクセスに失敗 (ユーザーが prompt を Deny、Keychain daemon ダウン、ACL 不整合) | **toml にフォールバックしない**。stderr に強い警告を出して `None` を返す |

`Backend` 時に toml フォールバックを許可すると、Keychain に移行済みの
ユーザーが Deny した瞬間に古い toml の secret が黙って採用されます。
これは Keychain への移行という決定そのものを台無しにするため、
明示的な失敗を選びます。

### classify_keyring_err の OSStatus 判定

`classify_keyring_err` は `keyring::Error::PlatformFailure` の source を
`security_framework::base::Error` に downcast し、OSStatus で判定します。
具体的には以下を `Unavailable` に分類します。

| 定数 | OSStatus | 意味 |
|---|---|---|
| `errSecNoDefaultKeychain` | -25307 | default keychain が未設定 |
| `errSecInvalidKeychain` | -25295 | keychain が invalid |

文字列マッチ (`"no default keychain"` 等) は locale 翻訳 (日本語 macOS
など) で外れることがあるため、OSStatus 判定を一次手段として採用し、
文字列マッチは downcast が失敗した場合の last-resort fallback として
残します。

`security-framework` major を `3` に明示 pin しているのは、`keyring` v3
の apple-native backend が内部で `security-framework 3.x` を使っている
ため、downcast 対象の型が一致することを保証するためです。

### `falcon-cli credentials` サブコマンド

ユーザーが Keychain エントリを操作するためのサブコマンドを追加します。

| サブコマンド | 機能 |
|---|---|
| `set <field> [--stdin]` | 対話的または stdin 経由で保管 |
| `delete <field>` | 削除 |
| `status` | 各エントリの「stored / not stored」のみを表示 (値は出さない) |
| `migrate [--dry-run]` | credentials.toml の client_secret を Keychain に移し、toml から削除 |

`get` サブコマンドは**意図的に提供しません**。理由は以下です。

- 値を取り出す正当なユースケースが存在しません。動作確認は `status`
  で十分です。バックアップは Falcon 側の UI で client_secret を再発行
  するのが正攻法です。
- AI エージェントが「デバッグのため」と称して `get` を実行し、出力が
  会話履歴・ログ・PR 説明に流出する事故を構造的に防ぎます。
- シェル履歴・端末スクロールバックへの汚染を防ぎます。

### Migrate の安全策

`migrate` は以下の順で実行します。

1. credentials.toml から client_secret を抽出 (quoted basic string のみ
   サポート、literal / multi-line は明示エラー)
2. ユーザーに移行確認 (default No)
3. **Keychain への書き込み** (toml 未変更のため失敗時の rollback 不要)
4. ユーザーに plaintext 処分方法を確認:
   - **default Yes**: tempfile + atomic rename で `client_secret` 行を
     完全削除。disk 上に plaintext は残らない
   - **No**: 0o600 backup を作成 + toml は新形式に書き換え + 多段の
     警告を表示
5. 失敗時は Keychain エントリを rollback し、plaintext がどこに残って
   いるかを明示

backup 作成は default ではなく opt-in です。backup を残す選択は意識的
にしか取れず、取った場合は強い警告を出します。

### Zeroize と tempfile による hardening

- 対話入力・stdin 入力・migrate 時の toml 読取り内容・抽出した secret
  は `zeroize::Zeroizing<String>` でラップし、scope を抜ける際に heap
  上のバイト列をゼロ埋めします。swap out / core dump / panic backtrace
  の窓を狭めます。
- `atomic_replace` は `tempfile::NamedTempFile::new_in` を使い、予測
  可能な tempfile 名を避けます。`persist()` が失敗すると `NamedTempFile`
  は drop 時に自動で unlink されるため、手動 cleanup 経路を忘れるバグ
  クラスが消えます。

### Debug マスク

`FalconCredentials` の `Debug` 実装を手動化し、`client_secret` を `***`
でマスクします。`dbg!` / `{:?}` / panic backtrace 経由の偶発漏洩を
防ぎます。

### ローカル平文の取り扱い

migrate で作成する backup ファイルは `OpenOptions::mode(0o600) +
create_new(true)` で書き出します。`fs::copy` は元ファイルの mode を
継承する (典型的には `0o644`) ため使いません。toml 本体の書き換えは
sibling tempfile への書き込み + `rename(2)` でアトミックに行います。

## 結果

### Positive

- `client_secret` がホームディレクトリのバックアップ・他プロセス・
  dotfiles リポジトリから完全に隔離されます
- macOS 標準の Keychain Access.app から GUI で監査・削除可能です
- trait 抽象化により Linux / Windows backend の追加コストが小さい
  です
- 既存 toml ユーザーは何もせずアップグレードしても挙動が変わらず、
  `migrate` で能動的に移行できます
- OSStatus 判定により locale 非依存で Unavailable / Backend を分類
  できます

### Negative

- 初回アクセスと `cargo install` 再ビルドのたびに Keychain ACL
  ダイアログが出ます。これは macOS の codesign ベース ACL に由来する
  挙動で、Homebrew bottle のような署名安定なバイナリ配布で緩和でき
  ます
- `keyring` crate の追加でサプライチェーン面積が増えます。`cargo deny`
  での監視を継続します
- 環境変数優先のため、CI や開発環境で `FALCON_CLIENT_SECRET` を
  誤って export したままのセッションでは Keychain 値が使われません。
  これは想定仕様で、ユーザー側で `unset FALCON_CLIENT_SECRET` する
  必要があります

## 代替案

### A. `security` コマンドのサブプロセス呼び出し

`/usr/bin/security add-generic-password` を `Command` で叩く方式です。
追加 crate は不要ですが、子プロセス起動コスト・シェルエスケープ・
ACL の細かい制御が課題です。`keyring` crate は `Security.framework` を
直接 FFI で呼ぶため、子プロセス不要・型安全です。

### B. `security-framework` crate を直接利用

最低レベルです。ACL を細かく制御できますが、コード量が増え、Linux /
Windows backend を将来追加する際に再抽象化が必要です。`keyring` crate
は最初から cross-platform 抽象化を持っています (ただし
`classify_keyring_err` では `security-framework` の `Error::code()` を
直接参照します)。

### C. client_id / member_cid も Keychain に格納

これらは機密性が低く (公開可能な識別子)、Keychain に入れると ACL
ダイアログ頻度が増えるだけで便益が小さいため不採用としました。
toml / env / CLI args に残します。

### D. backup を default で作成し続ける

backup ファイル自体が plaintext を持つため移行の意図を裏切ります。
「default は完全削除、backup は opt-in」に変更済みです。

## 先行事例

- **mde-cli ADR-0004**: 同じパターンを Microsoft Defender CLI 向けに
  先行実装
- **ssh-agent / gpg-agent**: 秘密鍵をプロセスメモリに保持する方式
  (falcon-cli ADR-0001 で採用済)
- **`gh` CLI**: Keychain / Secret Service / Credential Manager を抽象化
  して OAuth トークンを保管
- **Docker CLI**: `docker-credential-osxkeychain` 等の credential
  helper を介して registry credentials を Keychain に保管

## 影響範囲

- `Cargo.toml` — `keyring`, `security-framework = "3"`, `zeroize`,
  `tempfile`, `rpassword` を追加
- `src/config/credential_store.rs` — trait と KeychainStore 実装
- `src/config/mod.rs` — `FalconCredentials::resolve()` の優先順位拡張、
  `Debug` の手動マスク化、`ENV_LOCK` による test 逐次化
- `src/cli.rs` — `Command::Credentials` variant + `CredentialsCommand`
  / `CredentialField` 定義
- `src/commands/credentials.rs` — handler 実装 (set / delete / status /
  migrate)
- `src/main.rs` — `credentials` サブコマンドで resolve をスキップ
- `src/dispatch.rs` — `Credentials` の stub arm 追加
- `src/error.rs` — `FalconError::InvalidInput(String)` variant 追加
- `README.md` — Credential storage セクション追加

## セキュリティ考慮事項

- **codesign の安定性**: `cargo install` で再ビルドするたびに ACL が
  再評価され、ダイアログが再出します。本質的な解決には Homebrew bottle
  のような署名済みバイナリ配布が必要です
- **`FALCON_CLIENT_SECRET` 環境変数の優先**: ユーザーが明示的に export
  した場合は Keychain より優先されます。CI ランナーを奪取された場合
  等の env 経由の攻撃は Keychain では防げません
- **Keychain メモリダンプ**: root 権限による Keychain unlock 後の
  メモリスキャンは ADR-0002 (agent の hardening) の延長で緩和し、
  本 ADR のスコープ外とします
- **`keyring::Error` の OSStatus 判定**: `keyring` の major upgrade で
  `PlatformFailure` のラッピング形状が変わる可能性があります。downcast
  が失敗した場合に備え、文字列マッチを last-resort fallback として
  残しています
