import os
import json
import ctypes
import subprocess
from pathlib import Path
import tkinter as tk

import customtkinter as ctk
from tkinter import filedialog, messagebox

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

APP_NAME = "WolfGuard Anti-Ransomware"
CONFIG_FILE = "wolfguard_config.json"
DEFAULT_EXE_1 = "WolfGuard1.exe"
DEFAULT_EXE_2 = "WolfGuard2.exe"
BACKGROUND_IMG = "33.png"
WINDOW_ICON = "1.ico"

def script_dir() -> Path:
    if getattr(__import__('sys'), 'frozen', False) and hasattr(__import__('sys'), '_MEIPASS'):
        return Path(__import__('sys').executable).parent
    return Path(__file__).resolve().parent

def resource_path(relative_path: str) -> Path:
    try:
        base_path = Path(__import__('sys')._MEIPASS)
    except Exception:
        base_path = Path(__file__).resolve().parent
    return base_path / relative_path

def load_config(default_path: str) -> str:
    cfg_path = script_dir() / CONFIG_FILE
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            return data.get("exe_path", default_path)
        except Exception:
            return default_path
    return default_path

def save_config(path: str):
    try:
        (script_dir() / CONFIG_FILE).write_text(
            json.dumps({"exe_path": path}, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception as e:
        messagebox.showwarning(APP_NAME, f"Não foi possível salvar a configuração.\n\n{e}")

def run_as_admin_or_normal(path: Path) -> bool:
    if not path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {path}")

    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(path), None, str(path.parent), 1
        )
        if rc > 32:
            return True
    except Exception:
        pass

    try:
        subprocess.Popen([str(path)], cwd=str(path.parent), shell=True)
        return True
    except Exception as e:
        messagebox.showerror(APP_NAME, f"Falha ao executar:\n{path}\n\n{e}")
        return False


class WolfGuardLauncher(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(APP_NAME)
        self.geometry("500x420")
        self.minsize(500, 420)
        self.resizable(False, False)

        try:
            icon_path = resource_path(WINDOW_ICON)
            if icon_path.exists():
                self.iconbitmap(default=str(icon_path))
        except Exception:
            pass

        self.default_path = str(script_dir())
        self.exe_path = load_config(self.default_path)

        self._bg_label = None
        self._bg_image = None
        self._build_background()

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)

        self.btn_safe = self._make_main_button(
            self, "Safe", self.launch_safe
        )
        self.btn_safe.grid(row=0, column=0, padx=8, pady=20)

        self.btn_adv = self._make_main_button(
            self, "Avançado", self.launch_advanced
        )
        self.btn_adv.grid(row=0, column=1, padx=8, pady=20)

        self.btn_full = self._make_main_button(
            self, "Completo", self.launch_complete
        )
        self.btn_full.grid(row=0, column=2, padx=8, pady=20)

        self.config_btn = self._make_main_button(
            self, "Config", self.open_settings
        )
        self.config_btn.grid(row=1, column=2, sticky="se", padx=20, pady=20)

    def _build_background(self):
        if PIL_AVAILABLE:
            bg_path = resource_path(BACKGROUND_IMG)
            if bg_path.exists():
                img = Image.open(bg_path).convert("RGBA")
                self._bg_image = ctk.CTkImage(light_image=img, dark_image=img, size=(500, 420))
                self._bg_label = ctk.CTkLabel(self, text="", image=self._bg_image)
                self._bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                return
        self.configure(fg_color="#0a1020")

    def _make_main_button(self, parent, title, command):
        canvas = tk.Canvas(
            parent,
            height=40,
            width=150,
            highlightthickness=0,
            relief="flat"
        )
        canvas.configure(bg=parent.cget("bg"))
        
        def draw_button(hover=False):
            canvas.delete("all")
            width = 150
            height = 40
            radius = 6
            
            for x in range(width):
                ratio = x / width
                r = int(0 + (255 - 0) * ratio)
                g = int(0 + (255 - 0) * ratio)
                b = int(0 + (255 - 0) * ratio)
                color = f'#{r:02x}{g:02x}{b:02x}'
                canvas.create_line(x, 0, x, height, fill=color, width=1)
            
            border_color = "#606060"
            
            canvas.create_arc(0, 0, radius*2, radius*2, start=90, extent=90, 
                            fill="", outline=border_color, width=2)
            canvas.create_arc(width-radius*2, 0, width, radius*2, start=0, extent=90, 
                            fill="", outline=border_color, width=2)
            canvas.create_arc(0, height-radius*2, radius*2, height, start=180, extent=90, 
                            fill="", outline=border_color, width=2)
            canvas.create_arc(width-radius*2, height-radius*2, width, height, start=270, extent=90, 
                            fill="", outline=border_color, width=2)
            
            canvas.create_line(radius, 1, width-radius, 1, fill=border_color, width=2)
            canvas.create_line(radius, height-1, width-radius, height-1, fill=border_color, width=2)
            canvas.create_line(1, radius, 1, height-radius, fill=border_color, width=2)
            canvas.create_line(width-1, radius, width-1, height-radius, fill=border_color, width=2)
            
            text_color = "#ffffff" if hover else "#e0e0e0"
            canvas.create_text(width//2, height//2, text=title, 
                             fill=text_color, font=("Segoe UI", 13, "bold"))
        
        def on_enter(e):
            draw_button(hover=True)
        
        def on_leave(e):
            draw_button(hover=False)
        
        def on_click(e):
            command()
        
        canvas.bind("<Enter>", on_enter)
        canvas.bind("<Leave>", on_leave)
        canvas.bind("<Button-1>", on_click)
        
        draw_button()
        return canvas

    def resolve_paths(self):
        base = Path(self.exe_path.strip() or self.default_path)
        exe1 = base / DEFAULT_EXE_1
        exe2 = base / DEFAULT_EXE_2
        return exe1, exe2

    def launch_safe(self):
        exe1, _ = self.resolve_paths()
        try:
            run_as_admin_or_normal(exe1)
        except FileNotFoundError as e:
            messagebox.showerror(APP_NAME, str(e))

    def launch_advanced(self):
        _, exe2 = self.resolve_paths()
        try:
            run_as_admin_or_normal(exe2)
        except FileNotFoundError as e:
            messagebox.showerror(APP_NAME, str(e))

    def launch_complete(self):
        exe1, exe2 = self.resolve_paths()
        missing = [p for p in (exe1, exe2) if not p.exists()]
        if missing:
            msg = "Arquivos não encontrados:\n\n" + "\n".join(str(p) for p in missing)
            messagebox.showerror(APP_NAME, msg)
            return
        ok1 = run_as_admin_or_normal(exe1)
        if ok1:
            run_as_admin_or_normal(exe2)

    def open_settings(self):
        win = ctk.CTkToplevel(self)
        win.title("Configurações")
        win.geometry("360x220")
        win.resizable(False, False)
        win.grab_set()

        try:
            icon_path = resource_path(WINDOW_ICON)
            if icon_path.exists():
                win.iconbitmap(default=str(icon_path))
        except Exception:
            pass

        frame = ctk.CTkFrame(win, fg_color="#0b1020")
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        title = ctk.CTkLabel(frame, text="Configurações", font=("Segoe UI", 16, "bold"))
        title.pack(anchor="w", padx=12, pady=(10, 8))

        pasta_label = ctk.CTkLabel(
            frame, text="Pasta atual:", font=("Segoe UI", 11, "bold"), 
            text_color="#ffffff", anchor="w"
        )
        pasta_label.pack(fill="x", padx=12, pady=(4, 2))

        path_lbl = ctk.CTkLabel(
            frame, text=self.exe_path, font=("Segoe UI", 10), text_color="#aaaaaa",
            wraplength=320, anchor="w", justify="left"
        )
        path_lbl.pack(fill="x", padx=12, pady=(0, 8))

        def browse():
            folder = filedialog.askdirectory(
                title="Selecione a pasta dos executáveis",
                initialdir=self.exe_path or self.default_path
            )
            if folder:
                self.exe_path = folder
                save_config(folder)
                path_lbl.configure(text=folder)
                messagebox.showinfo(APP_NAME, "Pasta salva com sucesso.")

        btn_browse = ctk.CTkButton(
            frame, text="Procurar pasta", command=browse,
            height=36, corner_radius=10, fg_color="#113063", hover_color="#1a3f7f",
            text_color="#eaf2ff", font=("Segoe UI", 12, "bold")
        )
        btn_browse.pack(fill="x", padx=12, pady=(6, 8))

        btn_close = ctk.CTkButton(
            frame, text="Fechar", command=win.destroy,
            height=32, corner_radius=8, fg_color="#182238", hover_color="#223052"
        )
        btn_close.pack(fill="x", padx=12, pady=(0, 12))


if __name__ == "__main__":
    app = WolfGuardLauncher()
    app.mainloop()