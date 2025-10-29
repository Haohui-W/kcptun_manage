import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os
import psutil
from datetime import datetime


# =========================
# 配置加载
# =========================
CONFIG_FILE = "kcptun_config.json"


def load_config():
    """加载配置文件"""
    if not os.path.exists(CONFIG_FILE):
        messagebox.showerror("错误", f"缺少配置文件 {CONFIG_FILE}")
        raise SystemExit(1)

    with open(CONFIG_FILE, "r", encoding='utf8') as f:
        return json.load(f)


config = load_config()
client_path = config.get("client")
log_dir = config.get("log_dir", "./logs")

# 确保日志目录存在
os.makedirs(log_dir, exist_ok=True)

if not client_path or not os.path.exists(client_path):
    messagebox.showerror("错误", f"kcptun 可执行文件不存在: {client_path}")
    raise SystemExit(1)

ip_list = config.get("ip", [])
port_list = config.get("port", [])
key_list = config.get("key", [])
crypt_list = config.get("crypt", [])

# 生成显示内容（如：10.38.160.169（广州节点））
ip_display_list = [f"{i['value']}（{i['name']}）" for i in ip_list]
port_display_list = [f"{p['value']}（{p['name']}）" for p in port_list]


# =========================
# 进程管理逻辑
# =========================
kcptun_processes = {}


def build_command(ip: str, port: str, key: str, crypt: str, log_file: str):
    """构造 kcptun 启动命令"""
    remote_port = f"2{port}"
    local_port = f"1{port}"
    return [
        client_path,
        "-r", f"{ip}:{remote_port}",
        "-l", f":{local_port}",
        "-key", key,
        "-crypt", crypt,
        "--log", log_file,
    ]


def start_tunnel():
    """启动隧道"""
    ip_display = selected_ip.get()
    port_display = selected_port.get()
    key = selected_key.get()
    crypt = selected_crypt.get()

    if not ip_display or not port_display:
        messagebox.showerror("错误", "请先选择 IP 和端口")
        return

    ip_value = next(i["value"] for i in ip_list if i["value"] in ip_display)
    port_value = next(p["value"] for p in port_list if p["value"] in port_display)

    # 日志文件路径
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"kcptun_{ip_value}_{port_value}_{timestamp}.log")

    name = f"{ip_display}:{port_display}"
    if name in kcptun_processes:
        messagebox.showinfo("提示", f"{name} 已经在运行！")
        return

    cmd = build_command(ip_value, port_value, key, crypt, log_file)
    try:
        proc = subprocess.Popen(cmd)
        kcptun_processes[name] = proc
        add_process_to_listbox(name, proc, cmd, log_file)
        messagebox.showinfo("提示", f"{name} 已启动\n日志: {log_file}")
    except Exception as e:
        messagebox.showerror("错误", f"启动失败: {e}")


def add_process_to_listbox(name, proc, cmd, log_file):
    """展示进程详细信息"""
    pid = proc.pid
    ppid = psutil.Process(pid).ppid()
    command = " ".join(cmd)
    running_listbox.insert(
        tk.END,
        f"{name} | PID: {pid} | PPID: {ppid} | 日志: {log_file} | 命令: {command}",
    )


def stop_tunnel():
    """停止选中隧道"""
    selection = running_listbox.curselection()
    if not selection:
        messagebox.showinfo("提示", "请先选择要停止的隧道")
        return

    index = selection[0]
    process_info = running_listbox.get(index)
    name = process_info.split(" | ")[0]
    proc = kcptun_processes.get(name)

    if proc:
        proc.terminate()
        proc.wait()
        del kcptun_processes[name]
        running_listbox.delete(index)
        messagebox.showinfo("提示", f"{name} 已停止")


def stop_all():
    """停止所有隧道"""
    for name, proc in kcptun_processes.items():
        try:
            proc.terminate()
            proc.wait()
        except Exception:
            pass
    kcptun_processes.clear()
    running_listbox.delete(0, tk.END)
    messagebox.showinfo("提示", "所有隧道已停止")


# =========================
# GUI 构建
# =========================
root = tk.Tk()
root.title("kcptun 多隧道管理器")
root.geometry("700x640")


def make_combobox(frame, label, values, variable):
    row = ttk.Frame(frame)
    row.pack(fill="x", pady=5)
    ttk.Label(row, text=label, width=10).pack(side="left")
    cb = ttk.Combobox(row, values=values, textvariable=variable, state="readonly")
    cb.pack(side="left", fill="x", expand=True)
    cb.current(0 if values else -1)
    return cb


frame_select = ttk.LabelFrame(root, text="隧道配置选择", padding=10)
frame_select.pack(fill="x", padx=10, pady=10)

selected_ip = tk.StringVar()
selected_port = tk.StringVar()
selected_key = tk.StringVar()
selected_crypt = tk.StringVar()

make_combobox(frame_select, "服务器 IP", ip_display_list, selected_ip)
make_combobox(frame_select, "端口", port_display_list, selected_port)
make_combobox(frame_select, "密钥", key_list, selected_key)
make_combobox(frame_select, "加密方式", crypt_list, selected_crypt)

# 操作按钮
frame_buttons = ttk.Frame(root)
frame_buttons.pack(pady=10)

ttk.Button(frame_buttons, text="启动隧道", command=start_tunnel).pack(side="left", padx=5)
ttk.Button(frame_buttons, text="停止选中", command=stop_tunnel).pack(side="left", padx=5)
ttk.Button(frame_buttons, text="停止全部", command=stop_all).pack(side="left", padx=5)

# 运行信息
frame_running = ttk.LabelFrame(root, text="正在运行的隧道", padding=10)
frame_running.pack(fill="both", expand=True, padx=10, pady=10)

running_listbox = tk.Listbox(frame_running, width=95, height=15)
running_listbox.pack(fill="both", expand=True)

# 底部信息
ttk.Label(root, text=f"客户端路径：{client_path}", foreground="#666").pack(pady=2)
ttk.Label(root, text=f"日志目录：{log_dir}", foreground="#666").pack(pady=2)

root.mainloop()
