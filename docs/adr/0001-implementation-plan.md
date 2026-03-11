# ADR-0001 実装計画: Agent モード

## フェーズ概要

| フェーズ | 内容 | 依存 |
|---------|------|------|
| 1 | IPC プロトコル定義 | なし |
| 2 | Agent サーバー実装 | フェーズ 1 |
| 3 | Client モード実装 | フェーズ 1 |
| 4 | セキュリティ強化 | フェーズ 2 |
| 5 | CLI インターフェース統合 | フェーズ 2, 3 |
| 6 | テスト・ドキュメント | フェーズ 5 |

---

## フェーズ 1: IPC プロトコル定義

### 対象ファイル

- 新規: `src/agent/mod.rs`
- 新規: `src/agent/protocol.rs`

### プロトコル設計

改行区切りの JSON（JSON Lines）で通信します。

**リクエスト:**

```json
{
  "id": "uuid-v4",
  "command": "alert",
  "action": "list",
  "args": {
    "filter": "status:'new'",
    "limit": 100,
    "offset": null
  }
}
```

**レスポンス（成功）:**

```json
{
  "id": "uuid-v4",
  "status": "ok",
  "data": { ... }
}
```

**レスポンス（エラー）:**

```json
{
  "id": "uuid-v4",
  "status": "error",
  "error": {
    "kind": "api",
    "message": "404 Not Found: ..."
  }
}
```

### 追加依存

```toml
uuid = { version = "1", features = ["v4"] }
```

### タスク

1. `AgentRequest` / `AgentResponse` の struct を定義します
2. シリアライゼーション / デシリアライゼーションを実装します
3. ソケットパスの決定ロジックを実装します（`$XDG_RUNTIME_DIR` → `/tmp` フォールバック）

---

## フェーズ 2: Agent サーバー実装

### 対象ファイル

- 新規: `src/agent/server.rs`
- 新規: `src/agent/handler.rs`
- 変更: `src/error.rs`（agent 関連のエラーバリアント追加）

### タスク

1. `UnixListener` でソケットを bind し、接続を accept するサーバーループを実装します
2. 接続ごとに tokio タスクを spawn します
3. JSON Lines でリクエストを読み取り、コマンドをディスパッチします
4. 既存の `commands/` モジュールの `execute` 関数を handler から呼び出します
5. PID ファイルの作成・削除を実装します
6. シグナルハンドリング（SIGTERM, SIGINT）でグレースフルシャットダウンを実装します
7. ソケットファイルとディレクトリのパーミッション設定（`0700`）を実装します

### 設計ポイント

- `FalconClient` と `Auth` のインスタンスは agent 起動時に1回だけ生成し、全接続で共有します（`Arc`）
- handler は既存の `commands::*::execute()` 関数を直接呼び出し、`serde_json::Value` を受け取って返します
- コマンド名から `execute` 関数へのマッピングは `main.rs` の既存のマッチを関数として切り出して再利用します

---

## フェーズ 3: Client モード実装

### 対象ファイル

- 新規: `src/agent/client.rs`

### タスク

1. `UnixStream` でソケットに接続する client を実装します
2. CLI 引数を `AgentRequest` に変換するロジックを実装します
3. レスポンスを受信し、`serde_json::Value` として返します
4. 接続エラー時のメッセージ（「agent が起動していません」等）を実装します
5. タイムアウト処理を実装します（デフォルト: 30 秒）

---

## フェーズ 4: セキュリティ強化

### 対象ファイル

- 新規: `src/agent/security.rs`

### タスク

#### 4.1 コマンドホワイトリスト

```toml
# ~/.config/falcon-cli/agent.toml
[security]
allowed_commands = [
  "alert:list",
  "alert:get",
  "host:list",
  "host:get",
  "detection:list",
  "detection:get",
]
# "*" で全コマンドを許可（デフォルト）
```

1. 設定ファイルの読み込みと解析を実装します
2. リクエスト処理前にホワイトリストチェックを実装します
3. 未許可コマンドの拒否レスポンスを実装します

#### 4.2 レートリミット

1. トークンバケットアルゴリズムによるレートリミットを実装します
2. デフォルト: 60 req/min
3. 設定ファイルで変更可能にします

#### 4.3 監査ログ

1. リクエスト受信時にログを出力します（コマンド, 引数, タイムスタンプ, ピア情報）
2. レスポンス送信時にログを出力します（ステータス, 所要時間）
3. ログ出力先: stderr（デフォルト）または `--log-file` で指定したファイル

#### 4.4 ピア認証

1. `UCred`（Unix Credentials）でクライアントの UID を検証します
2. agent の UID と一致しない接続を拒否します

### 追加依存

```toml
toml = "0.8"  # 設定ファイル解析
```

---

## フェーズ 5: CLI インターフェース統合

### 対象ファイル

- 変更: `src/cli.rs`
- 変更: `src/main.rs`

### タスク

1. `agent` サブコマンドを追加します

```
falcon-cli agent start [--socket PATH] [--log-file PATH] [--config PATH]
falcon-cli agent stop [--socket PATH]
falcon-cli agent status [--socket PATH]
```

2. `--agent` グローバルフラグを追加します

```
falcon-cli --agent alert list --filter "status:'new'"
```

3. `main.rs` のディスパッチロジックを修正します
   - `--agent` フラグがある場合: agent client 経由でコマンドを実行します
   - `--agent` フラグがない場合: 従来通り直接 API を呼び出します
   - `agent start` コマンドの場合: agent を起動します

4. 既存のコマンドディスパッチを関数として切り出します（agent handler と main の両方から利用するため）

---

## フェーズ 6: テスト・ドキュメント

### タスク

1. プロトコルのシリアライゼーション/デシリアライゼーションのユニットテストを追加します
2. agent の起動・停止の統合テストを追加します
3. client から agent 経由でのコマンド実行の統合テストを追加します
4. セキュリティ機能（ホワイトリスト、レートリミット、UID 検証）のテストを追加します
5. `specs/` に agent モードの仕様書を追加します
6. README に agent モードの使い方を追加します

---

## ファイル構成（完成後）

```
src/
├── main.rs              # agent/client モードの分岐を追加
├── cli.rs               # --agent フラグ, agent サブコマンドを追加
├── agent/
│   ├── mod.rs           # agent モジュール定義
│   ├── protocol.rs      # AgentRequest, AgentResponse
│   ├── server.rs        # UDS サーバー, 接続管理, シグナルハンドリング
│   ├── handler.rs       # リクエスト → コマンド実行 → レスポンス
│   ├── client.rs        # agent への接続, リクエスト送信
│   └── security.rs      # ホワイトリスト, レートリミット, 監査ログ, UID 検証
├── auth.rs
├── client.rs
├── config.rs
├── error.rs
├── output.rs
└── commands/
    └── ...
```

## 依存関係の追加（まとめ）

```toml
[dependencies]
uuid = { version = "1", features = ["v4"] }
toml = "0.8"
```

## 実装の優先順位

最初の MVP として、フェーズ 1 → 2 → 3 → 5 を実装し、基本的な agent/client 通信を動作させます。セキュリティ強化（フェーズ 4）とテスト（フェーズ 6）はその後に追加します。
