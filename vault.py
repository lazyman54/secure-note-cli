#!/usr/bin/env python3
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Tuple, Union


DEFAULT_STORE_PATH = Path.home() / ".secure_note_store.json"
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


def command_save(args: argparse.Namespace) -> int:
    store_path = Path(args.file).expanduser()
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
    store_path = Path(args.file).expanduser()
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
    store_path = Path(args.file).expanduser()
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
    store_path = Path(args.file).expanduser()
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

    store_path = Path(args.file).expanduser()
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description="按关键词存储和读取加密账号密码。",
    )
    parser.add_argument(
        "--file",
        default=str(DEFAULT_STORE_PATH),
        help=f"存储文件路径（默认: {DEFAULT_STORE_PATH}）",
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
