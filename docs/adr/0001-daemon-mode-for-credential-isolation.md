# ADR-0001: Daemon モードによる認証情報の分離

## ステータス

提案中

## 日付

2026-03-09

## コンテキスト

falcon-cli は CrowdStrike Falcon API と通信するために OAuth2 Client Credentials（`FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`）を必要とします。運用環境では 1Password CLI (`op run`) を通じてこれらのシークレットを注入する運用が一般的です。

しかし、Claude Code のような LLM エージェントツールと `op run` の組み合わせには以下の問題があります。

### 問題 1: 認証承認の非互換性

`op run` は起動時に生体認証（Touch ID 等）による承認を要求します。Claude Code は非対話的にコマンドを実行するため、この承認プロンプトに対応できません。

### 問題 2: 環境変数経由のシークレット漏洩リスク

`op run -- claude` のように Claude Code 自体を `op run` の子プロセスとして起動する回避策も考えられますが、この方法では以下のリスクがあります。

- Claude Code のプロセス空間にシークレットが平文で存在します
- `env`, `printenv` コマンドでシークレットが読み取れます
- Claude Code が起動するすべての子プロセスに環境変数が継承されます
- Prompt injection を通じてシークレットが外部に送信される可能性があります
- LLM のログやエラー出力にシークレットが含まれる可能性があります

## 決定

falcon-cli に daemon モードを導入します。daemon は Unix ドメインソケットで IPC を提供し、認証情報を daemon プロセス内に閉じ込めます。

### アーキテクチャ

```
┌─────────────┐       ┌──────────────────┐      ┌────────────────────┐
│ Claude Code  │──────▶│ falcon-cli       │─────▶│ falcon-cli daemon  │
│              │       │ (client mode)    │ UDS  │ (op run 下で起動)  │
│              │◀──────│                  │◀─────│                    │
└─────────────┘       └──────────────────┘      └────────────────────┘
                        コマンドを送信            認証情報を保持
                        結果を受信                API を実行
```

### 通信方式

- Unix ドメインソケット（UDS）を使用します
- ソケットパスのデフォルト: `$XDG_RUNTIME_DIR/falcon-cli/falcon.sock` または `/tmp/falcon-cli-$UID/falcon.sock`
- ソケットファイルのパーミッション: `0700`（所有者のみアクセス可能）

### プロトコル

- JSON-RPC ライクなリクエスト/レスポンス形式を採用します
- 各リクエストに一意の ID を付与し、レスポンスと対応付けます

### セキュリティ強化

1. **セッショントークン認証（SSH Agent 方式）**: daemon 起動時にワンタイムトークンを生成し、`ssh-agent` と同様に stdout にシェル変数として出力します。クライアントは `FALCON_DAEMON_TOKEN` 環境変数経由でトークンを取得し、全リクエストに含めます。daemon はトークンが一致しないリクエストを拒否します。
2. **コマンドホワイトリスト**: daemon が受け付けるコマンド（サブコマンド + アクション）を設定ファイルで制限します
3. **レートリミット**: 単位時間あたりのリクエスト数を制限します（デフォルト: 60 req/min）
4. **監査ログ**: daemon が受信したすべてのリクエストとレスポンスのステータスを記録します
5. **ソケットパーミッション**: UDS ファイルとディレクトリを所有者のみアクセス可能に制限します
6. **ピア UID 検証**: UCred で接続元の UID を検証し、daemon と同じユーザー以外の接続を拒否します
7. **PID ファイル**: 二重起動を防止します

## 使用フロー

### Daemon の起動（人間が実行）

```bash
# 1Password 経由でシークレットを注入して daemon を起動（SSH Agent 方式）
eval "$(op run -- falcon-cli daemon start)"
# => FALCON_DAEMON_SOCKET と FALCON_DAEMON_TOKEN が環境変数にセットされます

# または環境変数を直接指定
eval "$(FALCON_CLIENT_ID=xxx FALCON_CLIENT_SECRET=yyy falcon-cli daemon start)"
```

### CLI からの利用（Claude Code が実行）

```bash
# daemon に接続してコマンドを実行
# （FALCON_DAEMON_SOCKET と FALCON_DAEMON_TOKEN は環境変数から自動取得）
falcon-cli --daemon alert list --filter "status:'new'"
falcon-cli --daemon host get --id HOST_ID_1

# daemon の状態確認
falcon-cli daemon status

# daemon の停止
falcon-cli daemon stop
```

## 代替案

### 案 1: `op run -- claude` でラップ

Claude Code のプロセス空間にシークレットが平文で存在するため、セキュリティリスクが高いです。却下しました。

### 案 2: トークンファイルの永続化

`op run -- falcon-cli auth` でトークンを取得しファイルに保存する方式です。トークンがディスクに残る点、トークンの有効期限管理が複雑になる点で却下しました。

### 案 3: 外部プロキシサーバー

nginx や envoy のようなプロキシで認証ヘッダーを注入する方式です。falcon-cli の外部に依存関係を追加する必要があり、セットアップの複雑さが増すため却下しました。

## 影響

### 変更が必要なモジュール

- `src/cli.rs`: `--daemon` フラグと `daemon` サブコマンドの追加
- `src/main.rs`: daemon モードと client モードの分岐
- 新規: `src/daemon/mod.rs`: daemon のメインループ
- 新規: `src/daemon/server.rs`: UDS サーバー実装
- 新規: `src/daemon/handler.rs`: リクエストハンドラー
- 新規: `src/daemon/protocol.rs`: IPC プロトコル定義
- 新規: `src/daemon/security.rs`: ホワイトリスト、レートリミット、監査ログ
- 新規: `src/daemon/client.rs`: daemon に接続する client 実装

### 依存関係の追加

- `uuid` (v4): リクエスト ID およびセッショントークンの生成
- `toml`: daemon 設定ファイルの解析
- `chrono`: 監査ログのタイムスタンプ
- `libc`: UID 検証、PID 操作

### 後方互換性

- `--daemon` フラグなしの場合、従来通りの動作を維持します
- daemon モードは完全にオプトインです
