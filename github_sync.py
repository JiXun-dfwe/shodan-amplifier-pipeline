# -*- coding: utf-8 -*-
"""github_sync.py -- shodan_kept.json 自动同步 GitHub (三脚本共用)

功能:
- push(reason)  : 拉取远端 -> 提交 shodan_kept.json 变更 -> 推送
                  (无变化时只 pull 不 commit)
- pull()        : 拉取远端最新数据 (send_reflect.py 启动前调用)

设计原则: 所有 git 操作失败只打日志, 不抛异常 —— 爬虫/发包主流程
不因 git 网络问题中断。每次操作独立调 git, 不依赖任何状态。

导入本模块即自动加载同目录 .env (系统环境变量优先级更高)。
"""
import os
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_env_file(filename=".env"):
    """加载本目录 .env (KEY=VALUE 每行一条, # 为注释); 已存在的变量不覆盖"""
    try:
        with open(os.path.join(_HERE, filename), encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip()
                if k and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass


_load_env_file()


def _env(name, default=""):
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip()


def log(msg):
    print("[%s] [git] %s" % (_stamp(), msg), flush=True)


def _stamp():
    import time
    return time.strftime("%H:%M:%S")


# ================【可自定义配置 - 环境变量 GS_*】================
# GS_ENABLED          1/true = 启用自动同步; 0 = 完全禁用 (只打日志)   默认 1
# GS_SYNC_FILE        要同步的数据文件 (相对脚本目录)                  默认 shodan_kept.json
# GS_REMOTE           git 远端名                                       默认 origin
# GS_BRANCH           分支名; 留空 = 自动用当前分支                    默认 空
# GS_TIMEOUT          单条 git 命令超时秒数                            默认 120
# GS_GIT_NAME         commit 作者名 (机器上没配 git config 时兜底)     默认 shodan-bot
# GS_GIT_EMAIL        commit 作者邮箱                                  默认 bot@local
# ================================================================

ENABLED = _env("GS_ENABLED", "1").lower() not in ("0", "false", "no", "off")
SYNC_FILE = _env("GS_SYNC_FILE", "shodan_kept.json")
REMOTE = _env("GS_REMOTE", "origin")
BRANCH = _env("GS_BRANCH", "")
TIMEOUT = int(_env("GS_TIMEOUT", "120") or 120)
GIT_NAME = _env("GS_GIT_NAME", "shodan-bot")
GIT_EMAIL = _env("GS_GIT_EMAIL", "bot@local")


def _git(args):
    """执行一条 git 命令, 返回 (成功?, 合并输出)。-c 选项兜底 commit 身份"""
    cmd = ["git", "-c", "user.name=%s" % GIT_NAME,
           "-c", "user.email=%s" % GIT_EMAIL] + args
    try:
        r = subprocess.run(cmd, cwd=_HERE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True,
                           encoding="utf-8", errors="replace",
                           timeout=TIMEOUT)
        ok = r.returncode == 0
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if not ok:
            log("git %s 失败: %s" % (args[0], out[-300:] if out else "无输出"))
        return ok, out
    except FileNotFoundError:
        log("未找到 git 命令, 跳过同步")
        return False, ""
    except subprocess.TimeoutExpired:
        log("git %s 超时 (>%ds), 跳过同步" % (args[0], TIMEOUT))
        return False, ""


def _branch():
    if BRANCH:
        return BRANCH
    ok, out = _git(["rev-parse", "--abbrev-ref", "HEAD"])
    return out.strip() if ok and out.strip() else "main"


def push(reason="auto"):
    """提交并推送 SYNC_FILE 的变更。返回 True 表示远端已更新。"""
    if not ENABLED:
        return False
    path = os.path.join(_HERE, SYNC_FILE)
    if not os.path.exists(path):
        log("%s 不存在, 跳过推送" % SYNC_FILE)
        return False
    br = _branch()
    # 1. 先同步远端, 减少推送冲突
    pull()
    # 2. 无变化则跳过 commit
    ok, out = _git(["status", "--porcelain", "--", SYNC_FILE])
    if not ok or not out.strip():
        log("%s 无变更, 不推送 (%s)" % (SYNC_FILE, reason))
        return False
    _git(["add", "--", SYNC_FILE])
    ok, _ = _git(["commit", "-m", "auto: %s (%s)" % (reason, _stamp()),
                  "--", SYNC_FILE])
    if not ok:
        return False
    # 3. 推送
    ok, _ = _git(["push", REMOTE, br])
    if ok:
        log("已推送 %s 到 %s/%s (%s)" % (SYNC_FILE, REMOTE, br, reason))
    return ok


def pull():
    """拉取远端最新数据。返回 True 表示 git 拉取成功。
    兼容旧版 git (CentOS 7 自带 1.8.3 无 --autostash):
    fetch + merge --ff-only, 不做自动 stash。"""
    if not ENABLED:
        return False
    br = _branch()
    ok, _ = _git(["fetch", REMOTE, br])
    if not ok:
        return False
    ok, out = _git(["merge", "--ff-only", "FETCH_HEAD"])
    if ok:
        log("已同步远端最新 %s (%s/%s)" % (SYNC_FILE, REMOTE, br))
    elif "up to date" in out.lower() or "already up-to-date" in out.lower():
        ok = True
    else:
        log("远端分叉/有本地改动, 跳过 ff 合并: %s" % out[-200:])
    return ok
