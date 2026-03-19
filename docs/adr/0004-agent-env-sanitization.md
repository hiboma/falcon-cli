# ADR-0004: Agent プロセスの環境変数サニタイズ

## ステータス

提案

## 日付

2026-03-19

## コンテキスト

falcon-cli の agent プロセスは `fork()` で生成されるため、親プロセスの環境変数をすべて継承します。`op run --env-file=.env` のようなシークレットマネージャー経由で起動すると、falcon-cli が必要としない他サービスのトークン（Slack, GitHub など）も agent プロセスの環境に載ります。

### 脅威

1. **`/proc/[pid]/environ` 経由の漏洩（Linux）**: `/proc/[pid]/environ` は `execve(2)` 時点のスナップショットです。`std::env::remove_var()` を呼んでも反映されません。同一ユーザーの任意のプロセスが読み取り可能です。
2. **子プロセスへの伝搬**: agent プロセスが将来的に子プロセスを spawn する場合、不要な認証情報が伝搬します。
3. **最小権限の原則の違反**: agent が必要とするのは CrowdStrike API の認証情報のみです。他サービスのトークンを保持する理由がありません。

### 制約

- `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` は `fork()` 前に `Config` 構造体に読み込み済みで、fork 後は環境変数を再参照しません。
- agent プロセスは HTTP 通信（reqwest）と Unix ドメインソケット通信を行うため、プロキシ・TLS 関連の環境変数は保持する必要があります。
- メモリダンプ（root 権限）による漏洩は本 ADR のスコープ外とします。

## 決定

### ホワイトリスト方式による環境変数クリア

agent プロセスの `fork()` 直後（tokio ランタイム生成前）に、ホワイトリストに含まれない環境変数をすべて削除します。

#### ホワイトリスト

| カテゴリ | 変数 | 用途 |
|----------|------|------|
| パス解決 | `HOME`, `PATH`, `USER`, `TMPDIR` | ファイルシステム操作、外部コマンド |
| XDG | `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR` | セッションファイル、設定ファイル、ソケットパス |
| プロキシ | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` | reqwest による HTTP 通信 |
| プロキシ (小文字) | `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` | reqwest は小文字も参照する |
| TLS | `SSL_CERT_FILE`, `SSL_CERT_DIR` | カスタム CA 証明書 |
| ロケール | `LANG`, `LC_*` | 文字エンコーディング |
| デバッグ | `RUST_LOG`, `RUST_BACKTRACE` | ログ出力、パニック時のバックトレース |

#### プロセス hardening（OS 別）

| OS | API | 効果 |
|----|-----|------|
| Linux | `prctl(PR_SET_DUMPABLE, 0)` | `/proc/[pid]/environ` へのアクセスを制限します。同一ユーザーであっても読み取り不可になります。`CAP_SYS_PTRACE` を持つプロセス（root 含む）は引き続き読めます |
| macOS | `ptrace(PT_DENY_ATTACH, 0, 0, 0)` | デバッガのアタッチを防止します。`task_for_pid()` は SIP + Hardened Runtime で制限されます。Apple 自身が `SecurityAgent` 等で使用しています |
| 共通 | `setrlimit(RLIMIT_CORE, 0)` | コアダンプを抑止し、クラッシュ時のメモリ漏洩を防止します |

macOS には `/proc/[pid]/environ` が存在しないため、`remove_var()` だけで環境変数は外部から読めなくなります。`ptrace(PT_DENY_ATTACH)` はデバッガ経由のメモリ読み取りを防ぐ追加の防御層です。

### 適用タイミング

- **fork モード**: `fork()` 後、子プロセスの `setsid()` 直後に実行します。
- **foreground モード**: `Config` 構築後、tokio ランタイム生成前に実行します。

## 代替案

### 1. ブラックリスト方式（`*_SECRET`, `*_TOKEN` 等を削除）

命名規則に従わない変数（例: `API_KEY=xxx`）を見落とす可能性があります。漏れのない削除を保証できないため不採用としました。

### 2. 環境変数全クリア（ホワイトリストなし）

`HOME`, `PATH` 等の基本変数まで消えるため、ファイルパス解決やプロキシ経由の通信が壊れます。

### 3. `remove_var()` のみ（`prctl` なし）

`/proc/[pid]/environ` には `execve` 時点のスナップショットが残るため、Linux 環境では `remove_var()` だけでは不十分です。`prctl(PR_SET_DUMPABLE, 0)` を併用することで、同一ユーザーからのアクセスも制限します。

## 先行事例

- **ssh-agent**: `prctl(PR_SET_DUMPABLE, 0)` で `/proc` アクセスを制限。`setrlimit(RLIMIT_CORE, 0)` でコアダンプを抑止。秘密鍵は環境変数に含めず、ソケットパスと PID のみを export します。
- **gpg-agent**: GnuPG 2.1 以降で `GPG_AGENT_INFO` 環境変数を廃止し、固定パスの Unix ドメインソケットに移行しています。

## 影響範囲

| ファイル | 変更内容 |
|----------|----------|
| `src/agent/server.rs` | `fork()` 後に `sanitize_env()` を呼び出す。foreground モードでも同様に呼び出す |
| `src/agent/mod.rs` | `sanitize_env()` 関数の実装（ホワイトリスト定義、`prctl`、`setrlimit`） |

## セキュリティに関する考慮事項

### 残存リスク

- Linux: root 権限（`CAP_SYS_PTRACE`）を持つプロセスは `prctl` による制限を迂回して `/proc/[pid]/environ` を読めます。
- macOS: `ptrace(PT_DENY_ATTACH)` は `task_for_pid()` によるアクセスを防げません。SIP + Hardened Runtime が有効な環境（一般的な macOS）では `task_for_pid()` 自体が制限されます。
- Config 構造体にコピーされた `client_secret` はプロセスメモリに残ります（本 ADR のスコープ外）。

### 将来の拡張

- ホワイトリストを agent 設定ファイル（`agent.toml`）で上書き可能にすることを検討します。プロキシ以外のカスタム環境変数が必要な環境に対応するためです。
