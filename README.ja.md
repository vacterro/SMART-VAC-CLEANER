# Smart VAC Cleaner

**v2.6.10**

Windows の一時ファイル、アプリのキャッシュ、設定したポータブルアプリの
フォルダーを整理するツールです。GUI、コマンドライン、タスク スケジューラに
対応しています。CLI は既定で削除内容のプレビューを表示します。
実際に削除するには `--delete` を指定します。

[English](README.md) · [Русский](README.ru.md) · [Eesti](README.et.md) · **日本語**

![Smart VAC Cleaner GUI](assets/screenshot.png)

## 動作環境とインストール

Windows 10/11、ソース版では Python 3.10 以上を使用します。
Python をインストールせずに使う場合は、
[Releases](https://github.com/vacterro/SMART-VAC-CLEANER/releases) から
`SmartVACCleaner.exe` をダウンロードしてください。

ソース版の依存パッケージをインストールする手順です。

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python _SMART_VAC_CLEANER.py
```

パッケージとしてインストールすると `vac-cleaner` コマンドを利用できます。

```bat
python -m pip install .
vac-cleaner --status
```

## 整理する対象

| 種類 | 対象 |
|---|---|
| システム | 一時ファイル、クラッシュ ダンプ、Explorer のサムネイル、アプリのキャッシュとログ |
| ポータブルアプリ | `portable_roots` に設定したフォルダー内の既知の不要ファイル |
| カスタムルール | `custom_rules` に設定したパスと glob パターンに一致するファイル |

ごみ箱、DNS キャッシュ、Windows Update キャッシュは既定で無効です。
GUI の System Targets で設定するか、CLI の `--sys-targets` で明示的に
有効にします。存在しないポータブルアプリのフォルダーはスキップします。

## 安全な確認と削除

```bat
REM すべての対象をプレビュー
python _SMART_VAC_CLEANER.py --cli --all

REM カスタムルールの対象だけをプレビュー
python _SMART_VAC_CLEANER.py --cli --custom --dry-run

REM 内容を確認してから実際に削除
python _SMART_VAC_CLEANER.py --cli --all --delete
```

`--dry-run` と `--delete` を同時に指定した場合はプレビューを優先します。
プレビューではファイル削除、属性変更、サービス停止、ごみ箱の処理を行いません。

保護されたパス、除外パス、シンボリックリンク、junction、reparse point を
検査します。削除直前にも対象の識別情報と境界を確認します。
利用中またはプロセス状態を確認できないアプリの対象はスキップします。
一般的な `.bak` バックアップ ファイルは自動削除しません。

## GUI

Clean は確認ダイアログの後で実際に削除します。Preview は読み取り専用の
プレビュー、Stop は実行中の処理のキャンセルです。
Exclusions で除外パターンとパス、System Targets でシステムの対象を設定します。
Run in bg はバックグラウンドでクリーンを開始します。
実行中のジョブが終了するまで、安全ポリシーの変更を待つ必要があります。

進行状況とログを画面に表示し、各実行のログは `logs\clean_*.log` に保存します。
GUI の言語設定は `en`、`ru`、`et`、`ded` です。

## 主な CLI オプション

| オプション | 動作 |
|---|---|
| `--portable` / `--system` / `--custom` | 対象の種類を選択 |
| `--all` | 安全な既定設定ですべての種類を選択 |
| `--status` | 対象ごとの容量を表示 |
| `--analyze-caches` | AppData の大きなキャッシュを調査 |
| `--exclude "*.db,*.tmp"` | 追加の除外パターン |
| `--install-task --time 09:00` | 毎日のタスクを登録 |
| `--uninstall-task` | このアプリのスケジュール タスクを削除 |

タスクの登録には管理者権限が必要です。削除:

```bat
python _SMART_VAC_CLEANER.py --uninstall-task
```

基本タスク `SmartVACCleaner` と、インストールされていればユーザー別タスク
`SmartVACCleaner_<USERNAME>` の両方を削除します。

## 設定と保存場所

GUI の起動時または実際の削除ジョブの初回実行時に、既定の
`cleaner_config.json` を作成します。ソース版とポータブル EXE 版はアプリの
隣に、インストールした wheel 版は `%LOCALAPPDATA%\SmartVACCleaner` に
設定とログを保存します。`SMARTVAC_DATA_DIR` で保存場所を指定できます。
読み取り専用の CLI プレビューや状態確認は、存在しない設定を作成しません。
実行ログは同じ保存場所の `logs\clean_YYYYMMDD_HHMMSS.log` に書き出され、
新しい 14 件だけを残します。

```json
{
  "portable_roots": [],
  "custom_rules": [{"path": "D:\\Apps\\TestApp", "pattern": "*.log"}],
  "exclude_patterns": ["*.db"],
  "exclude_paths": [],
  "auto_clean_interval_hours": 0,
  "lang": "en",
  "window_geometry": "",
  "system_targets": {}
}
```

設定したパスは読み込み時に正規化し、重複、保護されたルート、入れ子の
ポータブルルートを検査します。無効な既存の設定を上書きして削除を続行する
ことはありません。

## テストと EXE のビルド

```bat
python -m pytest -q
powershell -File build_exe.ps1
```

ビルド後に `dist\SmartVACCleaner.exe` を検証し、プロジェクトのルートにも
コピーします。EXE の必須テストは専用の使い捨てフォルダーでプレビューと
削除を実行します。

詳しい仕様は [English README](README.md) と
[ドキュメント](docs/Home.md) を参照してください。
不具合の報告は [GitHub Issues](https://github.com/vacterro/SMART-VAC-CLEANER/issues)
で受け付けています。
