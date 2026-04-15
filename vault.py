#!/usr/bin/env python3
import argparse
import base64
import datetime
import getpass
import hashlib
import hmac
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Tuple, Union


DEFAULT_STORE_PATH = Path.home() / ".secure_note_store.json"
DEFAULT_SYNC_REPO_PATH = Path.home() / "Projects" / "secure-note-data"
DEFAULT_INIT_STORE_PATH = DEFAULT_SYNC_REPO_PATH / "store.json"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "secure-note-cli" / "config.json"
CONFIG_ENV_KEY = "VAULT_CONFIG_FILE"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def derive_keys(passphrase: str, salt: bytes) -> Tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=64,
    )
    return material[:32], material[32:]


def keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hmac.new(
            enc_key,
            nonce + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt_payload(payload: Dict[str, str], passphrase: str) -> Dict[str, Union[str, int]]:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = derive_keys(passphrase, salt)

    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    stream = keystream(enc_key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, stream)
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()

    return {
        "v": 1,
        "kdf": "pbkdf2-sha256",
        "iter": PBKDF2_ITERATIONS,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }


def decrypt_payload(record: Dict[str, Union[str, int]], passphrase: str) -> Dict[str, str]:
    salt = b64d(str(record["salt"]))
    nonce = b64d(str(record["nonce"]))
    ciphertext = b64d(str(record["ciphertext"]))
    tag = b64d(str(record["tag"]))

    enc_key, mac_key = derive_keys(passphrase, salt)
    calc_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, calc_tag):
        raise ValueError("密钥错误或数据已损坏。")

    stream = keystream(enc_key, nonce, len(ciphertext))
    plaintext = xor_bytes(ciphertext, stream)

    try:
        obj = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("解密后数据格式错误。") from exc

    if not isinstance(obj, dict):
        raise ValueError("解密后数据不是对象。")
    return obj


def load_store(path: Path) -> Dict[str, Dict[str, Union[str, int]]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"存储文件格式非法: {path}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"存储文件内容必须是 JSON 对象: {path}")
    return data


def save_store(path: Path, data: Dict[str, Dict[str, Union[str, int]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as tmp:
        json.dump(data, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def get_config_path() -> Path:
    env_path = os.environ.get(CONFIG_ENV_KEY, "").strip()
    if env_path:
        return Path(env_path).expanduser()
    return DEFAULT_CONFIG_PATH


def load_config() -> Dict[str, str]:
    config_path = get_config_path()
    if not config_path.exists():
        return {}
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"配置文件格式非法: {config_path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"配置文件内容必须是 JSON 对象: {config_path}")
    return data


def save_config(config: Dict[str, str]) -> None:
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", delete=False, dir=str(config_path.parent), encoding="utf-8") as tmp:
        json.dump(config, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, config_path)


def resolve_store_path(cli_file: Optional[str]) -> Path:
    if cli_file:
        return Path(cli_file).expanduser()
    config = load_config()
    configured = str(config.get("default_store_file", "")).strip()
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_STORE_PATH


def prompt_key(confirm: bool = False) -> str:
    key = getpass.getpass("请输入加密密钥: ")
    if not key:
        raise ValueError("加密密钥不能为空。")
    if confirm:
        second = getpass.getpass("请再次输入加密密钥: ")
        if key != second:
            raise ValueError("两次输入的加密密钥不一致。")
    return key


def prompt_secret(label: str, confirm: bool = False) -> str:
    secret = getpass.getpass(f"请输入{label}: ")
    if not secret:
        raise ValueError(f"{label}不能为空。")
    if confirm:
        second = getpass.getpass(f"请再次输入{label}: ")
        if secret != second:
            raise ValueError(f"两次输入的{label}不一致。")
    return secret


def resolve_keyword(positional_keyword: str, option_keyword: str) -> str:
    if positional_keyword and option_keyword and positional_keyword != option_keyword:
        raise ValueError("位置关键词与 --keyword/-k 不一致，请只保留一种写法。")
    return positional_keyword or option_keyword or ""


def run_command(command: List[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        raise ValueError(f"命令执行失败: {' '.join(command)}\n{details}")
    return result.stdout.strip()


def ensure_repo_dir(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"同步仓库目录不存在: {path}")
    if not (path / ".git").exists():
        raise ValueError(f"不是 git 仓库目录: {path}")


def _try_decrypt_with_key(record: Dict[str, Union[str, int]], key: str) -> Optional[Dict[str, str]]:
    try:
        return decrypt_payload(record, key)
    except ValueError:
        return None


def command_save(args: argparse.Namespace) -> int:
    store_path = resolve_store_path(args.file)
    store = load_store(store_path)
    keyword = resolve_keyword(args.keyword, args.keyword_opt)
    if not keyword:
        keyword = input("请输入关键词: ").strip()
    if not keyword:
        print("关键词不能为空。", file=sys.stderr)
        return 1

    password = (
        args.password
        if args.password is not None
        else prompt_secret("要保存的账号密码", confirm=True)
    )
    key = prompt_key(confirm=True)
    encrypted = encrypt_payload(
        {
            "username": args.username,
            "password": password,
        },
        key,
    )
    store[keyword] = encrypted
    save_store(store_path, store)
    print(f"已保存关键词 `{keyword}` 到 {store_path}")
    return 0


def command_get(args: argparse.Namespace) -> int:
    store_path = resolve_store_path(args.file)
    store = load_store(store_path)

    keyword = resolve_keyword(args.keyword, args.keyword_opt)
    if not keyword:
        keyword = input("请输入关键词: ").strip()
        if not keyword:
            print("关键词不能为空。", file=sys.stderr)
            return 1

    if keyword not in store:
        print(f"未找到关键词: {keyword}", file=sys.stderr)
        return 1

    key = prompt_key(confirm=False)
    try:
        payload = decrypt_payload(store[keyword], key)
    except ValueError as exc:
        print(f"解密失败: {exc}", file=sys.stderr)
        return 2

    username = payload.get("username", "")
    password = payload.get("password", "")
    print(f"keyword: {keyword}")
    print(f"username: {username}")
    print(f"password: {password}")
    return 0


def command_list(args: argparse.Namespace) -> int:
    store_path = resolve_store_path(args.file)
    store = load_store(store_path)

    if not store:
        print(f"存储为空: {store_path}")
        return 0

    key = prompt_key(confirm=False)
    success_rows = []
    failed_rows = []
    for keyword in sorted(store.keys()):
        record = store[keyword]
        try:
            payload = decrypt_payload(record, key)
            username = payload.get("username", "")
            success_rows.append((keyword, username))
        except ValueError:
            failed_rows.append((keyword, "[解密失败]"))

    rows = success_rows + failed_rows
    total = len(rows)

    index_header = "#"
    keyword_header = "keyword"
    username_header = "username"

    index_width = max(len(index_header), len(str(total)))
    keyword_width = max(len(keyword_header), *(len(k) for k, _ in rows))
    username_width = max(len(username_header), *(len(u) for _, u in rows))

    print(f"共 {total} 条")
    print(
        f"{index_header:>{index_width}}  "
        f"{keyword_header:<{keyword_width}}  "
        f"{username_header:<{username_width}}"
    )
    print(f"{'-' * index_width}  {'-' * keyword_width}  {'-' * username_width}")
    for idx, (keyword, username) in enumerate(rows, start=1):
        print(
            f"{idx:>{index_width}}  "
            f"{keyword:<{keyword_width}}  "
            f"{username:<{username_width}}"
        )
    return 0


def command_delete(args: argparse.Namespace) -> int:
    store_path = resolve_store_path(args.file)
    store = load_store(store_path)
    keyword = resolve_keyword(args.keyword, args.keyword_opt)
    if not keyword:
        keyword = input("请输入关键词: ").strip()
    if not keyword:
        print("关键词不能为空。", file=sys.stderr)
        return 1

    if keyword not in store:
        print(f"未找到关键词: {keyword}", file=sys.stderr)
        return 1

    del store[keyword]
    save_store(store_path, store)
    print(f"已删除关键词 `{keyword}`")
    return 0


def command_update(args: argparse.Namespace) -> int:
    if args.username is None and args.password is None and not args.prompt_password:
        print("至少提供 --username 或 --password 其中之一。", file=sys.stderr)
        return 1

    store_path = resolve_store_path(args.file)
    store = load_store(store_path)
    keyword = resolve_keyword(args.keyword, args.keyword_opt)
    if not keyword:
        keyword = input("请输入关键词: ").strip()
    if not keyword:
        print("关键词不能为空。", file=sys.stderr)
        return 1

    if keyword not in store:
        print(f"未找到关键词: {keyword}", file=sys.stderr)
        return 1

    key = prompt_key(confirm=False)
    try:
        payload = decrypt_payload(store[keyword], key)
    except ValueError as exc:
        print(f"解密失败: {exc}", file=sys.stderr)
        return 2

    if args.username is not None:
        payload["username"] = args.username
    if args.password is not None:
        payload["password"] = args.password
    elif args.prompt_password:
        payload["password"] = prompt_secret("新的账号密码", confirm=True)

    store[keyword] = encrypt_payload(payload, key)
    save_store(store_path, store)

    changed = []
    if args.username is not None:
        changed.append("username")
    if args.password is not None or args.prompt_password:
        changed.append("password")
    print(f"已更新关键词 `{keyword}`: {', '.join(changed)}")
    return 0


def command_sync_pull(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).expanduser()
    ensure_repo_dir(repo_path)

    run_command(["git", "pull", "--rebase", "origin", "main"], repo_path)

    repo_store = repo_path / args.store
    if not repo_store.exists():
        raise ValueError(f"仓库中未找到存储文件: {repo_store}")

    local_store = resolve_store_path(args.file)
    same_store = repo_store.resolve() == local_store.resolve()
    if same_store:
        print("本地存储文件与仓库存储文件是同一路径，已完成远端拉取。")
    else:
        local_store.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_store, local_store)
        print(f"已拉取并更新本地存储文件: {local_store}")
    return 0


def command_sync_push(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).expanduser()
    ensure_repo_dir(repo_path)

    local_store = resolve_store_path(args.file)
    if not local_store.exists():
        raise ValueError(f"本地存储文件不存在: {local_store}")

    run_command(["git", "pull", "--rebase", "origin", "main"], repo_path)

    repo_store = repo_path / args.store
    same_store = repo_store.resolve() == local_store.resolve()
    if not same_store:
        repo_store.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_store, repo_store)
    else:
        print("本地存储文件与仓库存储文件是同一路径，跳过复制。")

    run_command(["git", "add", args.store], repo_path)

    commit_needed = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(repo_path),
        check=False,
    ).returncode != 0

    if commit_needed:
        message = args.message or f"sync secure note store ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
        run_command(["git", "commit", "-m", message], repo_path)
    else:
        print("没有检测到数据变更，跳过提交。")

    run_command(["git", "push", "origin", "main"], repo_path)
    print(f"已推送存储文件到远端私有仓库: {repo_store}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).expanduser()
    local_store = resolve_store_path(args.file)
    repo_store = repo_path / args.store

    ok_count = 0
    warn_count = 0
    fail_count = 0

    def report(status: str, message: str) -> None:
        nonlocal ok_count, warn_count, fail_count
        print(f"[{status}] {message}")
        if status == "OK":
            ok_count += 1
        elif status == "WARN":
            warn_count += 1
        else:
            fail_count += 1

    report("OK", f"本地存储路径: {local_store}")
    if local_store.exists():
        try:
            store_data = load_store(local_store)
            report("OK", f"本地存储文件可读，记录数: {len(store_data)}")
        except ValueError as exc:
            report("FAIL", f"本地存储文件格式异常: {exc}")
    else:
        report("WARN", "本地存储文件不存在（首次使用可忽略）")

    if repo_path.exists():
        report("OK", f"数据仓库目录存在: {repo_path}")
    else:
        report("FAIL", f"数据仓库目录不存在: {repo_path}")

    if repo_path.exists() and (repo_path / ".git").exists():
        report("OK", "数据仓库是有效 git 仓库")
    elif repo_path.exists():
        report("FAIL", "数据仓库目录缺少 .git")

    if repo_store.exists():
        try:
            store_data = load_store(repo_store)
            report("OK", f"仓库存储文件可读，记录数: {len(store_data)}")
        except ValueError as exc:
            report("FAIL", f"仓库存储文件格式异常: {exc}")
    else:
        report("WARN", f"仓库存储文件不存在: {repo_store}")

    if repo_path.exists() and (repo_path / ".git").exists():
        try:
            remote_url = run_command(["git", "remote", "get-url", "origin"], repo_path)
            report("OK", f"远端 origin: {remote_url}")
        except ValueError as exc:
            report("FAIL", f"无法读取远端 origin: {exc}")

        try:
            run_command(["git", "ls-remote", "--heads", "origin", "main"], repo_path)
            report("OK", "远端 main 分支可访问")
        except ValueError as exc:
            report("FAIL", f"无法访问远端 main 分支: {exc}")

        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_path),
            check=False,
            capture_output=True,
            text=True,
        )
        if status_result.returncode == 0:
            if status_result.stdout.strip():
                report("WARN", "数据仓库有未提交变更")
            else:
                report("OK", "数据仓库工作区干净")
        else:
            details = (status_result.stderr or status_result.stdout).strip()
            report("FAIL", f"无法检查仓库状态: {details}")

    print(f"\n检查完成: OK={ok_count}, WARN={warn_count}, FAIL={fail_count}")
    return 1 if fail_count > 0 else 0


def command_init(args: argparse.Namespace) -> int:
    target_file = Path(args.file).expanduser() if args.file else DEFAULT_INIT_STORE_PATH
    target_file.parent.mkdir(parents=True, exist_ok=True)

    current_default = resolve_store_path(None)
    if args.migrate:
        if not current_default.exists():
            raise ValueError(f"当前默认存储文件不存在，无法迁移: {current_default}")
        if target_file.exists() and not args.force:
            raise ValueError(f"目标文件已存在，使用 --force 允许覆盖: {target_file}")
        shutil.copy2(current_default, target_file)
        print(f"已迁移数据: {current_default} -> {target_file}")
    elif not target_file.exists():
        target_file.write_text("{}\n", encoding="utf-8")
        print(f"已创建新存储文件: {target_file}")

    config = load_config()
    config["default_store_file"] = str(target_file)
    save_config(config)

    print(f"已设置默认存储文件: {target_file}")
    print("之后可直接使用 vault save/get/list/update/delete，无需每次传 --file。")
    return 0


def command_shell(args: argparse.Namespace) -> int:
    store_path = resolve_store_path(args.file)
    session_key = prompt_key(confirm=False)
    readline_module = None
    old_completer = None
    old_delims = None

    print(f"进入 vault 会话模式（存储文件: {store_path}）")
    print("会话已绑定当前加密密钥。")
    print("可用命令: list, get <keyword>, save <keyword> -u <username> [-p <password>], update <keyword> [-u <username>] [-p <password>|-pp], delete <keyword>, clear, help, quit")

    def clear_screen() -> None:
        # ANSI clear screen + move cursor home.
        print("\033[2J\033[H", end="")

    commands = ["clear", "delete", "get", "help", "list", "quit", "save", "update"]

    try:
        import readline as _readline  # type: ignore

        readline_module = _readline
        old_completer = readline_module.get_completer()
        old_delims = readline_module.get_completer_delims()
        readline_module.parse_and_bind("tab: complete")
        readline_module.set_completer_delims(" \t\n")

        def _keyword_candidates(prefix: str) -> List[str]:
            try:
                store = load_store(store_path)
            except ValueError:
                return []
            return sorted([k for k in store.keys() if k.startswith(prefix)])

        def _completer(text: str, state: int) -> Optional[str]:
            line = readline_module.get_line_buffer()
            begidx = readline_module.get_begidx()
            left = line[:begidx]
            parts = left.split()
            suggestions: List[str] = []

            if not parts:
                suggestions = [c for c in commands if c.startswith(text)]
            elif begidx == 0:
                suggestions = [c for c in commands if c.startswith(text)]
            else:
                command = parts[0]
                if command in {"get", "delete", "update", "save"} and len(parts) == 1:
                    suggestions = _keyword_candidates(text)
                elif command == "save" and len(parts) >= 2:
                    option_suggestions = ["-u", "--username", "-p", "--password"]
                    suggestions = [opt for opt in option_suggestions if opt.startswith(text)]
                elif command == "update" and len(parts) >= 2:
                    option_suggestions = ["-u", "--username", "-p", "--password", "-pp", "--prompt-password"]
                    suggestions = [opt for opt in option_suggestions if opt.startswith(text)]

            suggestions = sorted(set(suggestions))
            if state < len(suggestions):
                return suggestions[state]
            return None

        readline_module.set_completer(_completer)
    except Exception:
        readline_module = None

    def print_list(store: Dict[str, Dict[str, Union[str, int]]]) -> None:
        rows = []
        for keyword in sorted(store.keys()):
            payload = _try_decrypt_with_key(store[keyword], session_key)
            if payload is None:
                rows.append((keyword, "[不支持解锁]"))
            else:
                rows.append((keyword, payload.get("username", "")))

        if not rows:
            print(f"存储为空: {store_path}")
            return

        keyword_header = "keyword"
        username_header = "username"
        keyword_width = max(len(keyword_header), *(len(k) for k, _ in rows))
        username_width = max(len(username_header), *(len(u) for _, u in rows))
        print(f"{keyword_header:<{keyword_width}}  {username_header:<{username_width}}")
        print(f"{'-' * keyword_width}  {'-' * username_width}")
        for keyword, username in rows:
            print(f"{keyword:<{keyword_width}}  {username:<{username_width}}")

    while True:
        try:
            line = input("vault> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        if not line:
            continue

        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            print(f"命令解析失败: {exc}")
            continue

        cmd = tokens[0]
        if cmd in {"quit", "exit"}:
            clear_screen()
            break
        if cmd == "help":
            print("list")
            print("get <keyword>")
            print("save <keyword> -u <username> [-p <password>]")
            print("update <keyword> [-u <username>] [-p <password>|-pp]")
            print("delete <keyword>")
            print("clear")
            print("quit")
            continue
        if cmd == "clear":
            clear_screen()
            continue

        try:
            store = load_store(store_path)
        except ValueError as exc:
            print(f"存储文件错误: {exc}")
            continue

        if cmd == "list":
            print_list(store)
            continue

        if cmd == "get":
            if len(tokens) < 2:
                print("用法: get <keyword>")
                continue
            keyword = tokens[1]
            if keyword not in store:
                print(f"未找到关键词: {keyword}")
                continue
            payload = _try_decrypt_with_key(store[keyword], session_key)
            if payload is None:
                print("此数据在当前会话中不支持解锁。请退出后使用对应密钥重新进入会话。")
                continue
            print(f"keyword: {keyword}")
            print(f"username: {payload.get('username', '')}")
            print(f"password: {payload.get('password', '')}")
            continue

        if cmd == "save":
            parser = argparse.ArgumentParser(prog="save", add_help=False)
            parser.add_argument("keyword")
            parser.add_argument("-u", "--username", required=True)
            parser.add_argument("-p", "--password")
            try:
                parsed = parser.parse_args(tokens[1:])
            except SystemExit:
                print("用法: save <keyword> -u <username> [-p <password>]")
                continue

            password = parsed.password if parsed.password is not None else prompt_secret("要保存的账号密码", confirm=True)
            store[parsed.keyword] = encrypt_payload(
                {
                    "username": parsed.username,
                    "password": password,
                },
                session_key,
            )
            save_store(store_path, store)
            print(f"已保存关键词 `{parsed.keyword}`")
            continue

        if cmd == "delete":
            if len(tokens) < 2:
                print("用法: delete <keyword>")
                continue
            keyword = tokens[1]
            if keyword not in store:
                print(f"未找到关键词: {keyword}")
                continue
            payload = _try_decrypt_with_key(store[keyword], session_key)
            if payload is None:
                print("此数据在当前会话中不支持解锁。请退出后使用对应密钥重新进入会话。")
                continue
            del store[keyword]
            save_store(store_path, store)
            print(f"已删除关键词 `{keyword}`")
            continue

        if cmd == "update":
            parser = argparse.ArgumentParser(prog="update", add_help=False)
            parser.add_argument("keyword")
            parser.add_argument("-u", "--username")
            parser.add_argument("-p", "--password")
            parser.add_argument("-pp", "--prompt-password", action="store_true")
            try:
                parsed = parser.parse_args(tokens[1:])
            except SystemExit:
                print("用法: update <keyword> [-u <username>] [-p <password>|-pp]")
                continue

            if parsed.username is None and parsed.password is None and not parsed.prompt_password:
                print("至少提供 -u/--username 或 -p/--password 或 -pp/--prompt-password。")
                continue

            keyword = parsed.keyword
            if keyword not in store:
                print(f"未找到关键词: {keyword}")
                continue

            payload = _try_decrypt_with_key(store[keyword], session_key)
            if payload is None:
                print("此数据在当前会话中不支持解锁。请退出后使用对应密钥重新进入会话。")
                continue

            if parsed.username is not None:
                payload["username"] = parsed.username
            if parsed.password is not None:
                payload["password"] = parsed.password
            elif parsed.prompt_password:
                payload["password"] = prompt_secret("新的账号密码", confirm=True)

            store[keyword] = encrypt_payload(payload, session_key)
            save_store(store_path, store)
            print(f"已更新关键词 `{keyword}`")
            continue

        print(f"未知命令: {cmd}（输入 help 查看可用命令）")

    if readline_module is not None:
        readline_module.set_completer(old_completer)
        if old_delims is not None:
            readline_module.set_completer_delims(old_delims)

    print("已退出 vault 会话。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description="按关键词存储和读取加密账号密码。",
    )
    parser.add_argument(
        "--file",
        help=f"存储文件路径（优先于 init 配置；未配置时默认: {DEFAULT_STORE_PATH}）",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    save_parser = subparsers.add_parser("save", help="保存关键词+用户名+密码")
    save_parser.add_argument("keyword", nargs="?", help="关键词（位置参数，可选）")
    save_parser.add_argument("-k", "--keyword", dest="keyword_opt", help="关键词（可选）")
    save_parser.add_argument("-u", "--username", required=True, help="用户名")
    save_parser.add_argument("-p", "--password", help="密码（不建议，可能被 shell 历史记录）")
    save_parser.set_defaults(func=command_save)

    get_parser = subparsers.add_parser("get", help="按关键词读取并解密（可省略 --keyword 走交互输入）")
    get_parser.add_argument("keyword", nargs="?", help="关键词（位置参数，可选）")
    get_parser.add_argument("-k", "--keyword", dest="keyword_opt", help="关键词（可选，不传则交互输入）")
    get_parser.set_defaults(func=command_get)

    list_parser = subparsers.add_parser("list", help="列出关键词和用户名")
    list_parser.set_defaults(func=command_list)

    delete_parser = subparsers.add_parser("delete", help="删除指定关键词记录")
    delete_parser.add_argument("keyword", nargs="?", help="关键词（位置参数，可选）")
    delete_parser.add_argument("-k", "--keyword", dest="keyword_opt", help="关键词（可选）")
    delete_parser.set_defaults(func=command_delete)

    update_parser = subparsers.add_parser("update", help="按关键词更新用户名或密码")
    update_parser.add_argument("keyword", nargs="?", help="关键词（位置参数，可选）")
    update_parser.add_argument("-k", "--keyword", dest="keyword_opt", help="关键词（可选）")
    update_parser.add_argument("-u", "--username", help="新用户名（可选）")
    update_parser.add_argument("-p", "--password", help="新密码（不建议，可能被 shell 历史记录）")
    update_parser.add_argument(
        "-pp",
        "--prompt-password",
        action="store_true",
        help="交互输入新密码（推荐）",
    )
    update_parser.set_defaults(func=command_update)

    pull_parser = subparsers.add_parser("sync-pull", help="从私有仓库拉取并更新本地存储文件")
    pull_parser.add_argument(
        "--repo",
        default=str(DEFAULT_SYNC_REPO_PATH),
        help=f"数据仓库目录（默认: {DEFAULT_SYNC_REPO_PATH}）",
    )
    pull_parser.add_argument("--store", default="store.json", help="仓库内存储文件相对路径（默认: store.json）")
    pull_parser.set_defaults(func=command_sync_pull)

    push_parser = subparsers.add_parser("sync-push", help="将本地存储文件推送到私有仓库")
    push_parser.add_argument(
        "--repo",
        default=str(DEFAULT_SYNC_REPO_PATH),
        help=f"数据仓库目录（默认: {DEFAULT_SYNC_REPO_PATH}）",
    )
    push_parser.add_argument("--store", default="store.json", help="仓库内存储文件相对路径（默认: store.json）")
    push_parser.add_argument("-m", "--message", help="同步提交信息（可选）")
    push_parser.set_defaults(func=command_sync_push)

    doctor_parser = subparsers.add_parser("doctor", help="检查本地与同步环境是否就绪")
    doctor_parser.add_argument(
        "--repo",
        default=str(DEFAULT_SYNC_REPO_PATH),
        help=f"数据仓库目录（默认: {DEFAULT_SYNC_REPO_PATH}）",
    )
    doctor_parser.add_argument("--store", default="store.json", help="仓库内存储文件相对路径（默认: store.json）")
    doctor_parser.set_defaults(func=command_doctor)

    init_parser = subparsers.add_parser("init", help="初始化默认存储文件路径（后续命令可省略 --file）")
    init_parser.add_argument("file", nargs="?", help=f"默认存储文件路径（默认: {DEFAULT_INIT_STORE_PATH}）")
    init_parser.add_argument(
        "--migrate",
        action="store_true",
        help="把当前默认存储文件迁移到目标文件（用于从 home 路径切到 git 仓库）",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="与 --migrate 一起使用，允许覆盖目标文件",
    )
    init_parser.set_defaults(func=command_init)

    shell_parser = subparsers.add_parser("shell", help="进入交互式会话（单会话绑定单密钥）")
    shell_parser.set_defaults(func=command_shell)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
