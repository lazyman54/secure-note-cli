# secure-note-cli

一个可在命令行使用的小工具：  
按关键词加密保存用户名和密码，再按关键词解密读取。

## 功能

- `save`：输入关键词、用户名、密码，手动输入加密密钥后加密保存到本地文件
- `get`：输入关键词，手动输入加密密钥后解密输出用户名和密码
- `list`：输入加密密钥后列出所有关键词和对应用户名
- `delete`：按关键词删除一条记录
- `update`：按关键词只更新用户名或密码（可只传一个字段）
- `init`：设置默认存储文件路径（以后可不传 `--file`）
- 每次执行命令都需要手动输入加密密钥

## 快速开始

在项目目录下执行：

```bash
chmod +x ./vault
```

保存一条记录（推荐：密码交互输入，不出现在命令历史）：

```bash
./vault save github -u myname
```

不推荐但兼容的方式（密码会出现在历史记录）：

```bash
./vault save github -u myname -p mypass
```

读取一条记录：

```bash
./vault get github
```

也可以不带 `--keyword`，改为交互输入关键词：

```bash
./vault get
```

或使用短参数：

```bash
./vault get -k github
```

列出全部关键词和用户名：

```bash
./vault list
```

删除一条记录：

```bash
./vault delete github
```

更新用户名或密码（可二选一）：

```bash
./vault update github -u new_name
./vault update github --prompt-password
./vault update github -pp
```

## 存储文件

默认存储到：

`~/.secure_note_store.json`

你可以通过 `init` 一次性把默认存储文件改到 git 仓库文件（推荐）：

```bash
vault init ~/Projects/secure-note-data/store.json --migrate
```

设置后，`save/get/list/update/delete` 默认会直接使用这个文件。

你也可以指定存储文件路径：

```bash
./vault --file ~/my-secrets.json save --keyword k --username u --password p
./vault --file ~/my-secrets.json get --keyword k
./vault --file ~/my-secrets.json list
./vault --file ~/my-secrets.json delete --keyword k
./vault --file ~/my-secrets.json update --keyword k --username new_u
./vault --file ~/my-secrets.json update --keyword k --prompt-password
```

> 参数兼容：`--keyword/--username/--password` 仍可用，同时支持短参数 `-k/-u/-p`。
> 你仍可用 `--file` 临时覆盖默认存储文件。

## 快捷安装【推荐】

你的朋友拿到项目目录后，执行：

```bash
bash ./install.sh
```

在线安装（不克隆仓库）：

```bash
curl -fsSL "https://raw.githubusercontent.com/<owner>/secure-note-cli/main/install.sh" | VAULT_REPO="<owner>/secure-note-cli" bash
```

默认会安装到：

- 命令：`~/.local/bin/vault`
- 程序：`~/.local/share/secure-note-cli/vault.py`

如果终端提示找不到 `vault`，把下面这行加入 `~/.zshrc` 或 `~/.bashrc`：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

卸载：

```bash
bash ./uninstall.sh
```

## 跨设备同步（私有数据仓库）

你当前的私有数据仓库：

- `https://github.com/lazyman54/secure-note-data`
- 本地默认目录：`~/Projects/secure-note-data`
- 仓库内数据文件：`store.json`

把本地数据推送到私有仓库：

```bash
vault sync-push
```

从私有仓库拉取到本地（覆盖本地 `~/.secure_note_store.json`）：

```bash
vault sync-pull
```

可选参数（仓库路径与提交信息）：

```bash
vault sync-push --repo ~/Projects/secure-note-data -m "sync from macbook"
vault sync-pull --repo ~/Projects/secure-note-data
```

环境自检（建议先跑一次）：

```bash
vault doctor
```

`doctor` 会检查：

- 本地存储文件是否存在且格式可读
- 私有数据仓库目录与 `.git` 是否存在
- 仓库内 `store.json` 是否可读
- `origin/main` 是否可访问
- 数据仓库是否有未提交改动

新电脑使用步骤：

```bash
git clone https://github.com/lazyman54/secure-note-data ~/Projects/secure-note-data
curl -fsSL "https://raw.githubusercontent.com/lazyman54/secure-note-cli/main/install.sh" | VAULT_REPO="lazyman54/secure-note-cli" bash
vault sync-pull
```

建议首次执行：

```bash
vault init ~/Projects/secure-note-data/store.json
```

## 注意事项

- 同一个关键词再次 `save` 会覆盖旧值
- 加密密钥不会被存储在文件里，只用于当次加解密
- 建议不要在命令参数里传 `--password`，改用交互输入避免进入 shell 历史记录
- 交互提示里“加密密钥”和“账号密码”已分开命名，避免混淆
- `save` 交互顺序为先输入账号密码，再输入加密密钥；`update` 为先密钥后修改内容
- 请使用强密钥并妥善保管
