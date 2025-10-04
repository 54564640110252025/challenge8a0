import sys, os, re, json, time, threading, ctypes, winreg, pythoncom
from ctypes import wintypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import psutil, wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PySide6.QtCore import Qt, QTimer, QSize, Signal, QObject, QThread
from PySide6.QtGui import QIcon, QPainter, QLinearGradient, QBrush, QPixmap
from PySide6.QtWidgets import QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox, QListWidget, QListWidgetItem, QFrame, QGridLayout, QSystemTrayIcon, QMenu, QProgressBar
try:
    import keyboard
except:
    keyboard = None
try:
    import win32con, win32gui, win32api, win32process
except:
    win32con=win32gui=win32api=win32process=None

APP_NAME = "WolfGuard"
ICON_FILE = os.path.join(os.path.dirname(sys.argv[0]), "1.ico")
CFG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "WolfGuard")
CFG_FILE = os.path.join(CFG_DIR, "antiransom_config.json")

# Whitelist expandida e otimizada
WHITELIST_EXE_NAMES = {
    "wolfguard.exe", "wolfguard1.exe", "wolfguard_updater.exe", "wolfguard2.exe",
    "explorer.exe", "taskmgr.exe", "regedit.exe", "mmc.exe", 
    "svchost.exe", "services.exe", "lsass.exe", "conhost.exe",
    "systemsettings.exe", "winlogon.exe", "wininit.exe", 
    "devenv.exe", "msedge.exe", "chrome.exe", "firefox.exe",
    "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
    "msdt.exe", "windbg.exe", "rundll32.exe", "regsvr32.exe",
    "control.exe", "msiexec.exe", "setupapi.exe", "notepad.exe",
    "ntoskrnl.exe", "csrss.exe", "sihost.exe", "dllhost.exe",
    "spoolsv.exe", "searchhost.exe", "fontdrvhost.exe", 
    "system", "smss.exe", "dwm.exe", "audiodg.exe",
    "vscode.exe", "code.exe", "pycharm64.exe", "idea64.exe"
}

WHITELIST_PY_NAMES = {"wolf", "wolfguard", "wolf5", "wolfguard_monitor"}
SYSTEM_ROOT = os.environ.get("WINDIR", "C:\\Windows")
PROGRAM_FILES = os.environ.get("PROGRAMFILES", "C:\\Program Files")
PROGRAM_FILES_X86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")

SYSTEM_DIRS = {
    os.path.normpath(SYSTEM_ROOT),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"System32")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"SysWOW64")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"WinSxS")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"servicing")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"Microsoft.NET")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"Fonts")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"SystemApps")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"System32\\WindowsPowerShell")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"System32\\config")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"System32\\drivers")),
    os.path.normpath(os.path.join(SYSTEM_ROOT,"System32\\wbem")),
    os.path.normpath(os.path.join(PROGRAM_FILES,"Windows Defender")),
    os.path.normpath(os.path.join(PROGRAM_FILES,"Windows Security")),
}

WHITELISTED_PATHS = {
    os.path.normpath(os.path.join(SYSTEM_ROOT, "System32\\WindowsPowerShell\\v1.0\\powershell.exe")),
    os.path.normpath(os.path.join(SYSTEM_ROOT, "System32\\cmd.exe")),
    os.path.normpath(os.path.join(SYSTEM_ROOT, "explorer.exe")),
    os.path.normpath(os.path.join(SYSTEM_ROOT, "System32\\wscript.exe")),
    os.path.normpath(os.path.join(SYSTEM_ROOT, "System32\\cscript.exe")),
    os.path.normpath(os.path.join(SYSTEM_ROOT, "System32\\taskmgr.exe")),
    os.path.normpath(os.path.join(SYSTEM_ROOT, "System32\\notepad.exe"))
}

DEFAULT_CFG = {
    "block_unsigned_exe": True,
    "block_js": True,
    "block_ps1": True,
    "block_cmd": True,
    "block_bat": True,
    "block_vbs": True,
    "block_py": False,
    "kill_running_offenders": True,
    "downloads_block_js": True,
    "downloads_block_ps1": True,
    "downloads_block_cmd": True,
    "downloads_block_bat": True,
    "downloads_block_vbs": True,
    "downloads_block_py": False,
    "downloads_block_unsigned_exe": True,
    "auto_scan_enabled": True,
    "scan_user_focus": True,
    "aggressive_mode": True,
    "scan_interval": 5
}

MUTEX_NAME = "Global\\WolfGuard_AntiRansom_SingleInstance"
WM_TOGGLE = 0x8000 + 1
WM_SHOW = 0x8000 + 2

# Cache global para assinaturas (muito mais rápido)
SIGNATURE_CACHE = {}
CACHE_LOCK = threading.Lock()
MAX_CACHE_SIZE = 10000

def ensure_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            params = " ".join(['"%s"' % a if " " in a and not a.startswith('"') else a for a in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)
    except:
        pass

def create_single_instance_or_signal():
    k=ctypes.windll.kernel32
    k.CreateMutexW.restype = wintypes.HANDLE
    h = k.CreateMutexW(None, wintypes.BOOL(True), MUTEX_NAME)
    if h and k.GetLastError() == 183:
        if win32gui:
            hwnd = win32gui.FindWindow(None, "WolfGuardAntiRansomware_Hidden")
            if hwnd:
                try:
                    win32api.PostMessage(hwnd, WM_SHOW, 0, 0)
                except:
                    pass
        sys.exit(0)
    return h

def load_cfg():
    try:
        os.makedirs(CFG_DIR, exist_ok=True)
        if os.path.exists(CFG_FILE):
            with open(CFG_FILE,"r",encoding="utf-8") as f:
                d=json.load(f)
            for k,v in DEFAULT_CFG.items():
                if k not in d: d[k]=v
            return d
    except:
        pass
    return DEFAULT_CFG.copy()

def save_cfg(cfg):
    try:
        os.makedirs(CFG_DIR, exist_ok=True)
        tmp = CFG_FILE + ".tmp"
        with open(tmp,"w",encoding="utf-8") as f: json.dump(cfg,f,ensure_ascii=False,indent=2)
        if os.path.exists(CFG_FILE): os.replace(tmp, CFG_FILE)
        else: os.rename(tmp, CFG_FILE)
    except:
        pass

def norm(p):
    try:
        return os.path.normpath(os.path.abspath(p)).lower()
    except:
        return ""

def is_whitelisted(path):
    if not path: return True
    path_norm = norm(path)
    if path_norm in WHITELISTED_PATHS: return True
    name = os.path.basename(path).lower()
    if name in WHITELIST_EXE_NAMES: return True
    stem = os.path.splitext(name)[0]
    if stem in WHITELIST_PY_NAMES: return True
    return False

def is_under_system(path):
    p = norm(path)
    if not p: return False
    if is_whitelisted(p): return True
    for s in SYSTEM_DIRS:
        if p == norm(s) or p.startswith(norm(s)+os.sep):
            return True
    return False

def is_signed_exe_cached(filepath):
    """Verificação ultra-rápida com cache"""
    if not filepath or not os.path.exists(filepath): return False
    if is_whitelisted(filepath): return True
    if is_under_system(filepath): return True
    
    # Cache check
    with CACHE_LOCK:
        if filepath in SIGNATURE_CACHE:
            return SIGNATURE_CACHE[filepath]
    
    # Verificação real
    result = is_signed_exe_fast(filepath)
    
    # Armazena no cache
    with CACHE_LOCK:
        if len(SIGNATURE_CACHE) >= MAX_CACHE_SIZE:
            # Remove 20% mais antigos
            to_remove = list(SIGNATURE_CACHE.keys())[:MAX_CACHE_SIZE // 5]
            for k in to_remove:
                del SIGNATURE_CACHE[k]
        SIGNATURE_CACHE[filepath] = result
    
    return result

def is_signed_exe_fast(filepath):
    if not os.path.exists(filepath): return False
    if is_whitelisted(filepath): return True
    if is_under_system(filepath): return True
    
    try:
        wintrust = ctypes.WinDLL("wintrust.dll")
        class GUID(ctypes.Structure):
            _fields_=[('Data1', wintypes.DWORD),('Data2', wintypes.WORD),('Data3', wintypes.WORD),('Data4', wintypes.BYTE*8)]
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_=[('cbStruct', wintypes.DWORD),('pcwszFilePath', wintypes.LPCWSTR),('hFile', wintypes.HANDLE),('pgKnownSubject', ctypes.POINTER(GUID))]
        class WINTRUST_DATA(ctypes.Structure):
            _fields_=[('cbStruct', wintypes.DWORD),('pPolicyCallbackData', wintypes.LPVOID),('pSIPClientData', wintypes.LPVOID),('dwUIChoice', wintypes.DWORD),
                      ('fdwRevocationChecks', wintypes.DWORD),('dwUnionChoice', wintypes.DWORD),('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                      ('dwStateAction', wintypes.DWORD),('hWVTStateData', wintypes.HANDLE),('pwszURLReference', wintypes.LPCWSTR),('dwProvFlags', wintypes.DWORD),('dwUIContext', wintypes.DWORD)]
        WTD_UI_NONE=2
        WTD_REVOKE_NONE=0
        WTD_CHOICE_FILE=1
        WTD_STATEACTION_VERIFY=1
        WTD_STATEACTION_CLOSE=2
        WTD_SAFER_FLAG=0x100
        WINTRUST_ACTION_GENERIC_VERIFY_V2=GUID(0xaac56b,0xcd44,0x11d0,(0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x95,0xee))
        fi=WINTRUST_FILE_INFO()
        fi.cbStruct=ctypes.sizeof(fi); fi.pcwszFilePath=filepath; fi.hFile=None; fi.pgKnownSubject=None
        td=WINTRUST_DATA()
        td.cbStruct=ctypes.sizeof(td); td.pPolicyCallbackData=None; td.pSIPClientData=None; td.dwUIChoice=WTD_UI_NONE
        td.fdwRevocationChecks=WTD_REVOKE_NONE; td.dwUnionChoice=WTD_CHOICE_FILE; td.pFile=ctypes.pointer(fi)
        td.dwStateAction=WTD_STATEACTION_VERIFY; td.hWVTStateData=None; td.pwszURLReference=None
        td.dwProvFlags=WTD_SAFER_FLAG; td.dwUIContext=0
        r = wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(td))
        td.dwStateAction=WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(td))
        return r == 0
    except:
        return False

def kill_process_ultra_fast(pid):
    """Kill instantâneo usando TerminateProcess direto"""
    try:
        PROCESS_TERMINATE = 0x0001
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if handle:
            ctypes.windll.kernel32.TerminateProcess(handle, 1)
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
    except:
        pass
    
    # Fallback para psutil
    try:
        p=psutil.Process(pid)
        p.kill()
        return True
    except:
        pass
    return False

def extract_script_path(cmdline, exts):
    try:
        s = cmdline or ""
        m = re.findall(r'(?:"([^"]+\.(?:%s))"|(\S+\.(?:%s)))' % ("|".join(exts), "|".join(exts)), s, flags=re.IGNORECASE)
        for a,b in m:
            p = a or b
            if p: return p
    except:
        pass
    return ""

def get_download_dirs():
    dirs=set()
    try:
        k=winreg.OpenKey(winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        p=winreg.QueryValueEx(k,"{374DE290-123F-4565-9164-39C4925E467B}")[0]
        if os.path.isdir(p): dirs.add(p)
    except:
        pass
    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        if os.path.isdir(desktop): dirs.add(desktop)
        docs = os.path.join(os.path.expanduser("~"), "Documents")
        if os.path.isdir(docs): dirs.add(docs)
        pics = os.path.join(os.path.expanduser("~"), "Pictures")
        if os.path.isdir(pics): dirs.add(pics)
    except:
        pass
    return list(dirs)

def get_all_drives():
    """Retorna todas as unidades de disco"""
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
    except:
        pass
    return drives

class MonitorEvents(FileSystemEventHandler):
    def __init__(self, core):
        self.core=core
        self.cache = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    def _handle(self,path):
        if not os.path.isfile(path): return
        if is_under_system(path): return
        
        now = time.time()
        if path in self.cache and now - self.cache[path] < 1:
            return
        self.cache[path] = now
        
        if len(self.cache) > 2000:
            old_time = now - 30
            self.cache = {k: v for k, v in self.cache.items() if v > old_time}
        
        ext = os.path.splitext(path)[1].lower()
        if self.core.is_whitelisted_path(path): return
        
        if ext==".exe":
            if not self.core.cfg["downloads_block_unsigned_exe"]: return
            if os.path.basename(path).lower() in WHITELIST_EXE_NAMES: return
            if is_signed_exe_cached(path): return
            self.core.block_and_log("RANSOMWARE BLOQUEADO - EXE NAO ASSINADO", path, delete=True)
            return
            
        m={
            ".js":("downloads_block_js","SCRIPT MALICIOSO BLOQUEADO - .JS"),
            ".ps1":("downloads_block_ps1","SCRIPT MALICIOSO BLOQUEADO - .PS1"),
            ".cmd":("downloads_block_cmd","SCRIPT MALICIOSO BLOQUEADO - .CMD"),
            ".bat":("downloads_block_bat","SCRIPT MALICIOSO BLOQUEADO - .BAT"),
            ".vbs":("downloads_block_vbs","SCRIPT MALICIOSO BLOQUEADO - .VBS"),
            ".py":("downloads_block_py","SCRIPT BLOQUEADO - .PY")
        }
        
        if ext in m:
            flag,tag=m[ext]
            if self.core.cfg.get(flag,False):
                self.core.block_and_log(tag, path, delete=True)
    
    def on_created(self, event):
        if not event.is_directory: 
            self.executor.submit(self._handle, event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory: 
            self.executor.submit(self._handle, event.src_path)

class ScanThread(QThread):
    progress = Signal(int, str)
    finished = Signal(int)
    
    def __init__(self, core, paths_to_scan):
        super().__init__()
        self.core = core
        self.paths_to_scan = paths_to_scan
        self.running = True
        
    def run(self):
        total = 0
        removed = 0
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            
            for base_path in self.paths_to_scan:
                if not self.running: break
                try:
                    for root, dirs, files in os.walk(base_path):
                        if not self.running: break
                        
                        # Pula pastas do sistema
                        if is_under_system(root):
                            dirs.clear()
                            continue
                        
                        for file in files:
                            if not self.running: break
                            if file.lower().endswith('.exe'):
                                total += 1
                                filepath = os.path.join(root, file)
                                future = executor.submit(self.check_and_remove, filepath)
                                futures.append(future)
                                
                                if len(futures) >= 100:
                                    for f in as_completed(futures):
                                        if f.result():
                                            removed += 1
                                    futures.clear()
                                    self.progress.emit(removed, filepath)
                except:
                    continue
            
            # Processa restantes
            for f in as_completed(futures):
                if f.result():
                    removed += 1
        
        self.finished.emit(removed)
    
    def check_and_remove(self, filepath):
        try:
            if is_whitelisted(filepath):
                return False
            if is_under_system(filepath):
                return False
            if is_signed_exe_cached(filepath):
                return False
            
            # Não assinado - REMOVER
            self.core.delete_file(filepath)
            self.core.blocked_signal.emit(f"REMOVIDO: {filepath}")
            return True
        except:
            return False
    
    def stop(self):
        self.running = False

class FocusMonitor(QThread):
    """Monitora onde o usuário está focado e scanneia automaticamente"""
    focus_changed = Signal(str)
    
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.running = True
        self.last_path = None
        self.scan_cache = set()
        
    def run(self):
        while self.running:
            try:
                if not self.core.cfg.get("scan_user_focus", True):
                    time.sleep(1)
                    continue
                
                # Pega janela ativa
                if win32gui:
                    hwnd = win32gui.GetForegroundWindow()
                    if hwnd:
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        try:
                            proc = psutil.Process(pid)
                            exe_path = proc.exe()
                            current_dir = os.path.dirname(exe_path)
                            
                            # Se mudou de pasta e não é sistema
                            if current_dir != self.last_path and not is_under_system(current_dir):
                                if current_dir not in self.scan_cache:
                                    self.last_path = current_dir
                                    self.focus_changed.emit(current_dir)
                                    self.scan_directory_fast(current_dir)
                                    self.scan_cache.add(current_dir)
                                    
                                    # Limita cache
                                    if len(self.scan_cache) > 100:
                                        self.scan_cache.clear()
                        except:
                            pass
            except:
                pass
            
            time.sleep(2)
    
    def scan_directory_fast(self, directory):
        """Scan rápido da pasta em foco"""
        try:
            for file in os.listdir(directory):
                if not self.running: break
                filepath = os.path.join(directory, file)
                if os.path.isfile(filepath) and filepath.lower().endswith('.exe'):
                    if not is_whitelisted(filepath) and not is_signed_exe_cached(filepath):
                        self.core.block_and_log("DETECTADO NO FOCO", filepath, delete=False)
        except:
            pass
    
    def stop(self):
        self.running = False

class Core(QObject):
    blocked_signal = Signal(str)
    
    def __init__(self, cfg):
        super().__init__()
        self.cfg=cfg
        self.download_dirs=get_download_dirs()
        self.observer=Observer()
        self.process_cache = {}
        self.executor = ThreadPoolExecutor(max_workers=16)
        
        for d in self.download_dirs:
            if os.path.isdir(d):
                self.observer.schedule(MonitorEvents(self), d, recursive=True)
        self.observer.start()
        
        self.monitor_thread=threading.Thread(target=self.monitor_processes, daemon=True)
        self.monitor_thread.start()
        
        if self.cfg.get("kill_running_offenders", True):
            self.cleaner_thread=threading.Thread(target=self.periodic_cleanup, daemon=True)
            self.cleaner_thread.start()
        
        # Monitor de foco do usuário
        if self.cfg.get("scan_user_focus", True):
            self.focus_monitor = FocusMonitor(self)
            self.focus_monitor.focus_changed.connect(lambda p: self.blocked_signal.emit(f"Monitorando: {p}"))
            self.focus_monitor.start()
        
    def is_whitelisted_path(self, path):
        return is_whitelisted(path)
        
    def is_legit_system_script(self, cmdline):
        p = extract_script_path(cmdline, ["ps1","bat","cmd","vbs","js","py"])
        if p and is_under_system(p): return True
        return False
        
    def should_block_exec(self, exe_path, cmdline):
        if not exe_path: return False
        if self.is_whitelisted_path(exe_path): return False
        if is_under_system(exe_path): return False
        if self.is_legit_system_script(cmdline): return False
        
        name = os.path.basename(exe_path).lower()
        
        if exe_path.lower().endswith(".exe"):
            if self.cfg.get("block_unsigned_exe",True) and not is_signed_exe_cached(exe_path):
                return True
                
        if name in {"powershell.exe","pwsh.exe"} and self.cfg.get("block_ps1",True):
            if ".ps1" in (cmdline or "").lower(): return True
            
        if name=="cmd.exe" and self.cfg.get("block_cmd",True):
            if any(e in (cmdline or "").lower() for e in [".cmd",".bat"]): return True
            
        if name in {"wscript.exe","cscript.exe"}:
            s=(cmdline or "").lower()
            if (self.cfg.get("block_js",True) and ".js" in s) or (self.cfg.get("block_vbs",True) and ".vbs" in s):
                return True
                
        if name in {"python.exe","pythonw.exe","py.exe"} and self.cfg.get("block_py",False):
            s=(cmdline or "").lower()
            if ".py" in s and not any(w in s for w in WHITELIST_PY_NAMES):
                return True
                
        return False
        
    def terminate_pid(self, pid):
        kill_process_ultra_fast(pid)
            
    def delete_file(self, path):
        try:
            if os.path.isfile(path):
                try: os.chmod(path,0o777)
                except: pass
                for _ in range(3):
                    try:
                        os.remove(path)
                        return
                    except:
                        time.sleep(0.01)
        except:
            pass
            
    def block_and_log(self, reason, path, pid=None, delete=False):
        msg=f"{reason}: {path}"
        self.blocked_signal.emit(msg)
        
        if pid is not None:
            self.executor.submit(self.terminate_pid, pid)
            
        if delete:
            self.executor.submit(self.delete_file, path)
            
    def monitor_processes(self):
        try:
            pythoncom.CoInitialize()
            c=wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            
            while True:
                try:
                    proc = watcher()
                    path = proc.ExecutablePath or ""
                    cmd = proc.CommandLine or ""
                    pid = proc.ProcessId
                    
                    # Cache ultra-rápido
                    now = time.time()
                    cache_key = f"{path}:{pid}"
                    if cache_key in self.process_cache and now - self.process_cache[cache_key] < 2:
                        continue
                    
                    self.process_cache[cache_key] = now
                    
                    if self.should_block_exec(path, cmd):
                        # KILL INSTANTÂNEO - modo agressivo
                        if self.cfg.get("aggressive_mode", True):
                            self.terminate_pid(pid)
                        
                        self.block_and_log("PROCESSO BLOQUEADO", path, pid=pid, 
                                          delete=path.lower().endswith(".exe") and not is_under_system(path))
                except Exception as e:
                    time.sleep(0.001)
                    
        except Exception as e:
            pass
        finally:
            try: pythoncom.CoUninitialize()
            except: pass
            
    def scan_running_and_enforce(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            try:
                for p in psutil.process_iter(attrs=["pid","name","exe","cmdline"]):
                    future = executor.submit(self._check_process, p)
                    futures.append(future)
                
                for future in as_completed(futures):
                    future.result()
            except:
                pass
    
    def _check_process(self, p):
        try:
            exe=p.info.get("exe") or ""
            cmd=" ".join(p.info.get("cmdline") or [])
            if self.should_block_exec(exe, cmd):
                if self.cfg.get("kill_running_offenders",True):
                    self.block_and_log("ENCERRADO", exe or p.info.get("name",""), 
                                     pid=p.info["pid"], 
                                     delete=(exe or "").lower().endswith(".exe") and not is_under_system(exe))
                else:
                    self.blocked_signal.emit(f"DETECTADO: {exe or p.info.get('name','')}")
        except:
            pass
            
    def periodic_cleanup(self):
        interval = self.cfg.get("scan_interval", 5)
        while True:
            try:
                if self.cfg.get("kill_running_offenders",True):
                    self.scan_running_and_enforce()
            except:
                pass
            time.sleep(interval)

class GlassCard(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self.setStyleSheet("#card{background-color: rgba(10,18,38,220); border:1px solid rgba(255,255,255,40); border-radius:16px;}")

class FancyWindow(QWidget):
    toggle_visibility = Signal()
    
    def __init__(self, core):
        super().__init__()
        self.core=core
        self.scan_thread = None
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(load_app_icon())
        self.setWindowFlags(Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.resize(640, 520)
        self.setStyleSheet("QWidget{color:#ffffff;} QCheckBox{color:#ffffff;} QPushButton{color:#ffffff;} QLabel{color:#ffffff;}")
        self.build_ui()
        self.apply_cfg_to_ui()
        self.core.blocked_signal.connect(self.add_monitor_line)
        self.toggle_visibility.connect(self.handle_toggle)
        
    def paintEvent(self, e):
        p=QPainter(self)
        grad=QLinearGradient(0,0,0,self.height())
        grad.setColorAt(0, Qt.darkBlue)
        grad.setColorAt(1, Qt.black)
        p.setBrush(QBrush(grad))
        p.setPen(Qt.NoPen)
        r=self.rect()
        p.drawRoundedRect(r.adjusted(1,1,-1,-1),18,18)
        super().paintEvent(e)
        
    def build_ui(self):
        root=QVBoxLayout(self); root.setContentsMargins(14,14,14,14); root.setSpacing(10)
        
        # Header
        title=QHBoxLayout()
        logo=QLabel(); pix=icon_pixmap(32)
        logo.setPixmap(pix)
        name=QLabel("WolfGuard - Anti-Ransomware"); 
        name.setStyleSheet("font-size:18px; font-weight:700;")
        title.addWidget(logo); title.addWidget(name); title.addStretch()
        btn_close=QPushButton("×"); btn_close.setFixedSize(36,32); 
        btn_close.setStyleSheet("QPushButton{background:rgba(255,0,0,40);border:0;border-radius:8px;font-size:22px;}QPushButton:hover{background:rgba(255,0,0,70);}")
        btn_close.clicked.connect(self.hide)
        title.addWidget(btn_close)
        root.addLayout(title)
        
        # Status
        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame{background:rgba(0,255,136,25);border-radius:8px;padding:8px;}")
        status_layout = QHBoxLayout(status_frame)
        self.status_label = QLabel("PROTECAO ATIVA")
        self.status_label.setStyleSheet("font-size:14px; font-weight:600; color:#00ff88;")
        status_layout.addWidget(self.status_label)
        root.addWidget(status_frame)
        
        card=GlassCard()
        root.addWidget(card)
        inner=QVBoxLayout(card); inner.setContentsMargins(12,12,12,12); inner.setSpacing(8)
        
        tabs=QTabWidget(); 
        tabs.setStyleSheet("QTabWidget::pane{border:0;} QTabBar::tab{background:rgba(255,255,255,18);color:#ffffff;padding:10px 16px;border-radius:10px;margin-right:6px;font-weight:600;} QTabBar::tab:selected{background:rgba(0,255,136,40);} QTabBar::tab:hover{background:rgba(255,255,255,40);}")
        
        self.tab_cfg=QWidget()
        self.tab_mon=QWidget()
        self.tab_down=QWidget()
        self.tab_scan=QWidget()
        
        tabs.addTab(self.tab_cfg,"Configuracoes")
        tabs.addTab(self.tab_mon,"Monitoramento")
        tabs.addTab(self.tab_down,"Downloads")
        tabs.addTab(self.tab_scan,"Varredura")
        inner.addWidget(tabs)
        
        # Tab Configurações
        g=QGridLayout(self.tab_cfg); g.setContentsMargins(8,8,8,8); g.setHorizontalSpacing(14); g.setVerticalSpacing(10)
        
        label_exec = QLabel("PROTECAO DE EXECUCAO:")
        label_exec.setStyleSheet("font-weight:700; font-size:13px; color:#00ff88;")
        g.addWidget(label_exec, 0, 0, 1, 2)
        
        self.ck_unsigned=QCheckBox("Bloquear .exe sem assinatura digital")
        self.ck_js=QCheckBox("Bloquear scripts .js")
        self.ck_ps1=QCheckBox("Bloquear scripts .ps1 (PowerShell)")
        self.ck_cmd=QCheckBox("Bloquear scripts .cmd")
        self.ck_bat=QCheckBox("Bloquear scripts .bat")
        self.ck_vbs=QCheckBox("Bloquear scripts .vbs")
        self.ck_py=QCheckBox("Bloquear scripts .py")
        
        for i,w in enumerate([self.ck_unsigned,self.ck_js,self.ck_ps1,self.ck_cmd,self.ck_bat,self.ck_vbs,self.ck_py]):
            g.addWidget(w, i+1, 0, 1, 2)
        
        label_adv = QLabel("MODO AVANCADO:")
        label_adv.setStyleSheet("font-weight:700; font-size:13px; color:#ff8800; margin-top:10px;")
        g.addWidget(label_adv, 9, 0, 1, 2)
        
        self.ck_kill=QCheckBox("Encerrar processos maliciosos automaticamente")
        self.ck_aggressive=QCheckBox("Modo Agressivo (kill instantaneo)")
        self.ck_auto_scan=QCheckBox("Varredura automatica ativa")
        self.ck_scan_focus=QCheckBox("Monitorar pasta em foco do usuario")
        
        for i,w in enumerate([self.ck_kill,self.ck_aggressive,self.ck_auto_scan,self.ck_scan_focus]):
            g.addWidget(w, 10+i, 0, 1, 2)
        
        btns=QHBoxLayout()
        self.bt_save=QPushButton("Salvar Configuracao")
        self.bt_apply=QPushButton("Aplicar Agora")
        for b in [self.bt_save,self.bt_apply]:
            b.setStyleSheet("QPushButton{background:#1a60ff;border:0;border-radius:10px;padding:12px 16px;font-weight:600;}QPushButton:hover{background:#2a70ff;}")
            btns.addWidget(b)
        btns.addStretch()
        g.addLayout(btns,14,0,1,2)
        
        self.bt_save.clicked.connect(self.on_save)
        self.bt_apply.clicked.connect(self.on_apply)
        
        # Tab Monitoramento
        m=QVBoxLayout(self.tab_mon); m.setContentsMargins(8,8,8,8)
        self.list_mon=QListWidget(); 
        self.list_mon.setStyleSheet("QListWidget{background:rgba(0,0,0,80);color:#00ff88;border:1px solid rgba(0,255,136,30);border-radius:8px;font-family:Consolas,monospace;}")
        m.addWidget(self.list_mon)
        
        h=QHBoxLayout()
        self.bt_clear=QPushButton("Limpar")
        self.bt_refresh=QPushButton("Verificar Agora")
        for b in [self.bt_clear,self.bt_refresh]:
            b.setStyleSheet("QPushButton{background:#0f46c1;border:0;border-radius:10px;padding:10px 14px;font-weight:600;}QPushButton:hover{background:#1556e4;}")
            h.addWidget(b)
        h.addStretch()
        m.addLayout(h)
        
        self.bt_clear.clicked.connect(self.list_mon.clear)
        self.bt_refresh.clicked.connect(self.on_manual_scan)
        
        # Tab Downloads
        d=QGridLayout(self.tab_down); d.setContentsMargins(8,8,8,8); d.setHorizontalSpacing(14); d.setVerticalSpacing=10
        
        label_down = QLabel("PROTECAO DE DOWNLOADS:")
        label_down.setStyleSheet("font-weight:700; font-size:13px; color:#00ff88;")
        d.addWidget(label_down, 0, 0, 1, 2)
        
        self.dk_unsigned=QCheckBox("Bloquear downloads de .exe sem assinatura")
        self.dk_js=QCheckBox("Bloquear downloads de .js")
        self.dk_ps1=QCheckBox("Bloquear downloads de .ps1")
        self.dk_cmd=QCheckBox("Bloquear downloads de .cmd")
        self.dk_bat=QCheckBox("Bloquear downloads de .bat")
        self.dk_vbs=QCheckBox("Bloquear downloads de .vbs")
        self.dk_py=QCheckBox("Bloquear downloads de .py")
        
        for i,w in enumerate([self.dk_unsigned,self.dk_js,self.dk_ps1,self.dk_cmd,self.dk_bat,self.dk_vbs,self.dk_py]):
            d.addWidget(w, i+1, 0, 1, 2)
        
        info=QLabel("Pastas protegidas: " + ("; ".join(self.core.download_dirs) if self.core.download_dirs else "nenhuma"))
        info.setStyleSheet("color:#aaaaaa; margin-top:10px;")
        d.addWidget(info, 9, 0, 1, 2)
        
        # Tab Varredura
        s=QVBoxLayout(self.tab_scan); s.setContentsMargins(8,8,8,8); s.setSpacing(12)
        
        scan_label = QLabel("VARREDURA COMPLETA DO SISTEMA")
        scan_label.setStyleSheet("font-size:16px; font-weight:700; color:#00ff88;")
        s.addWidget(scan_label)
        
        scan_info = QLabel("Remove automaticamente TODOS os executaveis nao assinados\nem todas as unidades de disco (exceto arquivos do sistema).")
        scan_info.setStyleSheet("color:#cccccc; margin-bottom:10px;")
        scan_info.setWordWrap(True)
        s.addWidget(scan_info)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("QProgressBar{background:rgba(0,0,0,60);border:1px solid rgba(0,255,136,40);border-radius:8px;text-align:center;color:#ffffff;height:28px;} QProgressBar::chunk{background:#00ff88;border-radius:6px;}")
        self.progress_bar.setVisible(False)
        s.addWidget(self.progress_bar)
        
        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet("color:#00ff88; font-weight:600;")
        s.addWidget(self.scan_status)
        
        scan_btns = QHBoxLayout()
        
        self.bt_scan_quick = QPushButton("Varredura Rapida\n(Downloads, Desktop, Documentos)")
        self.bt_scan_full = QPushButton("Varredura Completa\n(Todas as unidades)")
        self.bt_scan_stop = QPushButton("Parar")
        self.bt_scan_stop.setEnabled(False)
        
        for b in [self.bt_scan_quick, self.bt_scan_full, self.bt_scan_stop]:
            b.setStyleSheet("QPushButton{background:#1a60ff;border:0;border-radius:10px;padding:16px;font-weight:600;min-height:50px;}QPushButton:hover{background:#2a70ff;}QPushButton:disabled{background:#444444;}")
            scan_btns.addWidget(b)
        
        s.addLayout(scan_btns)
        s.addStretch()
        
        self.bt_scan_quick.clicked.connect(self.start_quick_scan)
        self.bt_scan_full.clicked.connect(self.start_full_scan)
        self.bt_scan_stop.clicked.connect(self.stop_scan)
        
        # Footer
        foot=QHBoxLayout()
        lab=QLabel("F3 para mostrar/ocultar")
        lab.setStyleSheet("color:#888888;")
        foot.addWidget(lab); foot.addStretch()
        inner.addLayout(foot)
        
        self.dragging=False
        self.offset=None
        
    def mousePressEvent(self, event):
        if event.button()==Qt.LeftButton:
            self.dragging=True
            self.offset=event.globalPosition().toPoint()-self.frameGeometry().topLeft()
            
    def mouseMoveEvent(self, event):
        if self.dragging and self.offset is not None:
            self.move(event.globalPosition().toPoint()-self.offset)
            
    def mouseReleaseEvent(self, event):
        self.dragging=False
        self.offset=None
        
    def handle_toggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.activateWindow()
            self.raise_()
            
    def add_monitor_line(self, text):
        self.list_mon.addItem(QListWidgetItem(time.strftime("[%H:%M:%S] ") + text))
        self.list_mon.scrollToBottom()
        
        # Mantém apenas últimas 1000 linhas
        if self.list_mon.count() > 1000:
            self.list_mon.takeItem(0)
        
    def apply_cfg_to_ui(self):
        c=self.core.cfg
        self.ck_unsigned.setChecked(c.get("block_unsigned_exe",True))
        self.ck_js.setChecked(c.get("block_js",True))
        self.ck_ps1.setChecked(c.get("block_ps1",True))
        self.ck_cmd.setChecked(c.get("block_cmd",True))
        self.ck_bat.setChecked(c.get("block_bat",True))
        self.ck_vbs.setChecked(c.get("block_vbs",True))
        self.ck_py.setChecked(c.get("block_py",False))
        self.ck_kill.setChecked(c.get("kill_running_offenders",True))
        self.ck_aggressive.setChecked(c.get("aggressive_mode",True))
        self.ck_auto_scan.setChecked(c.get("auto_scan_enabled",True))
        self.ck_scan_focus.setChecked(c.get("scan_user_focus",True))
        self.dk_unsigned.setChecked(c.get("downloads_block_unsigned_exe",True))
        self.dk_js.setChecked(c.get("downloads_block_js",True))
        self.dk_ps1.setChecked(c.get("downloads_block_ps1",True))
        self.dk_cmd.setChecked(c.get("downloads_block_cmd",True))
        self.dk_bat.setChecked(c.get("downloads_block_bat",True))
        self.dk_vbs.setChecked(c.get("downloads_block_vbs",True))
        self.dk_py.setChecked(c.get("downloads_block_py",False))
        
    def pull_ui_to_cfg(self):
        c=self.core.cfg
        c["block_unsigned_exe"]=self.ck_unsigned.isChecked()
        c["block_js"]=self.ck_js.isChecked()
        c["block_ps1"]=self.ck_ps1.isChecked()
        c["block_cmd"]=self.ck_cmd.isChecked()
        c["block_bat"]=self.ck_bat.isChecked()
        c["block_vbs"]=self.ck_vbs.isChecked()
        c["block_py"]=self.ck_py.isChecked()
        c["kill_running_offenders"]=self.ck_kill.isChecked()
        c["aggressive_mode"]=self.ck_aggressive.isChecked()
        c["auto_scan_enabled"]=self.ck_auto_scan.isChecked()
        c["scan_user_focus"]=self.ck_scan_focus.isChecked()
        c["downloads_block_unsigned_exe"]=self.dk_unsigned.isChecked()
        c["downloads_block_js"]=self.dk_js.isChecked()
        c["downloads_block_ps1"]=self.dk_ps1.isChecked()
        c["downloads_block_cmd"]=self.dk_cmd.isChecked()
        c["downloads_block_bat"]=self.dk_bat.isChecked()
        c["downloads_block_vbs"]=self.dk_vbs.isChecked()
        c["downloads_block_py"]=self.dk_py.isChecked()
        
    def on_save(self):
        self.pull_ui_to_cfg()
        save_cfg(self.core.cfg)
        self.add_monitor_line("Configuracao salva com sucesso!")
        
    def on_apply(self):
        self.pull_ui_to_cfg()
        save_cfg(self.core.cfg)
        self.on_manual_scan()
        self.add_monitor_line("Configuracao aplicada e sistema verificado!")
    
    def on_manual_scan(self):
        self.add_monitor_line("Iniciando verificacao manual...")
        threading.Thread(target=self.core.scan_running_and_enforce, daemon=True).start()
    
    def start_quick_scan(self):
        paths = self.core.download_dirs
        if not paths:
            self.scan_status.setText("Nenhuma pasta para scanear")
            return
        
        self.scan_status.setText("Iniciando varredura rapida...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.bt_scan_quick.setEnabled(False)
        self.bt_scan_full.setEnabled(False)
        self.bt_scan_stop.setEnabled(True)
        
        self.scan_thread = ScanThread(self.core, paths)
        self.scan_thread.progress.connect(self.update_scan_progress)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
    
    def start_full_scan(self):
        drives = get_all_drives()
        if not drives:
            self.scan_status.setText("Nenhuma unidade encontrada")
            return
        
        self.scan_status.setText("Iniciando varredura COMPLETA...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.bt_scan_quick.setEnabled(False)
        self.bt_scan_full.setEnabled(False)
        self.bt_scan_stop.setEnabled(True)
        
        self.scan_thread = ScanThread(self.core, drives)
        self.scan_thread.progress.connect(self.update_scan_progress)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
    
    def update_scan_progress(self, removed, current_file):
        self.progress_bar.setValue(removed)
        self.scan_status.setText(f"Removidos: {removed} | Scaneando: {os.path.basename(current_file)}")
    
    def scan_finished(self, total_removed):
        self.progress_bar.setVisible(False)
        self.scan_status.setText(f"Varredura concluida! Total removido: {total_removed} arquivo(s)")
        self.bt_scan_quick.setEnabled(True)
        self.bt_scan_full.setEnabled(True)
        self.bt_scan_stop.setEnabled(False)
        self.add_monitor_line(f"Varredura finalizada: {total_removed} arquivo(s) malicioso(s) removido(s)")
    
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_status.setText("Varredura interrompida")
            self.bt_scan_stop.setEnabled(False)

class HotkeyListener(QObject):
    def __init__(self, toggle_signal):
        super().__init__()
        self.toggle_signal = toggle_signal
        self.running = True
        
        if keyboard:
            threading.Thread(target=self._keyboard_hotkey, daemon=True).start()
        elif win32gui and win32api and win32con:
            threading.Thread(target=self._win32_hotkey, daemon=True).start()
    
    def _keyboard_hotkey(self):
        try:
            keyboard.add_hotkey('f3', lambda: self.toggle_signal.emit(), suppress=False)
            while self.running:
                time.sleep(0.1)
        except:
            pass
    
    def _win32_hotkey(self):
        try:
            def wndproc(hwnd, message, wparam, lparam):
                if message == win32con.WM_HOTKEY and wparam == 1:
                    self.toggle_signal.emit()
                    return 0
                return win32gui.DefWindowProc(hwnd, message, wparam, lparam)
            
            wc = win32gui.WNDCLASS()
            hinst = win32api.GetModuleHandle(None)
            wc.hInstance = hinst
            wc.lpszClassName = "WolfGuardF3HotkeyClass"
            wc.lpfnWndProc = wndproc
            
            try:
                classAtom = win32gui.RegisterClass(wc)
            except:
                classAtom = win32gui.FindClass("WolfGuardF3HotkeyClass")
            
            hwnd = win32gui.CreateWindow(
                classAtom, "WolfGuardF3Hotkey", 0, 
                0, 0, 0, 0, 0, 0, hinst, None
            )
            
            MOD_NOREPEAT = 0x4000
            if not win32api.RegisterHotKey(hwnd, 1, 0, win32con.VK_F3):
                win32api.RegisterHotKey(hwnd, 1, MOD_NOREPEAT, win32con.VK_F3)
            
            win32gui.PumpMessages()
        except:
            pass
    
    def stop(self):
        self.running = False

class TrayController(QObject):
    def __init__(self, ui):
        super().__init__()
        self.ui=ui
        self.tray=QSystemTrayIcon()
        self.tray.setIcon(load_app_icon())
        self.menu=QMenu()
        self.act_toggle=self.menu.addAction("Mostrar/Ocultar")
        self.act_toggle.triggered.connect(self.ui.handle_toggle)
        self.menu.addSeparator()
        self.act_exit=self.menu.addAction("Sair")
        self.act_exit.triggered.connect(self.exit_app)
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self.on_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()
            try:
                self.tray.showMessage("WolfGuard", "Protecao antiransom ativa. Use F3 para mostrar/ocultar.", QSystemTrayIcon.Information, 3000)
            except:
                pass
            
    def on_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.ui.handle_toggle()
            
    def exit_app(self):
        QApplication.quit()

def icon_pixmap(sz):
    if os.path.exists(ICON_FILE):
        ic=QIcon(ICON_FILE)
        if not ic.isNull():
            return ic.pixmap(sz, sz)
    pm=QPixmap(sz, sz)
    pm.fill(Qt.transparent)
    p=QPainter(pm)
    g=QLinearGradient(0,0,sz,sz)
    g.setColorAt(0, Qt.darkBlue)
    g.setColorAt(1, Qt.black)
    p.setBrush(QBrush(g))
    p.setPen(Qt.NoPen)
    p.drawRoundedRect(0,0,sz,sz,6,6)
    p.end()
    return pm

def load_app_icon():
    if os.path.exists(ICON_FILE):
        ic=QIcon(ICON_FILE)
        if not ic.isNull():
            return ic
    pm=icon_pixmap(32)
    return QIcon(pm)

def main():
    ensure_admin()
    _ = create_single_instance_or_signal()
    cfg=load_cfg()
    app=QApplication(sys.argv)
    app.setWindowIcon(load_app_icon())
    core=Core(cfg)
    ui=FancyWindow(core)
    tray=TrayController(ui)
    hotkey_listener = HotkeyListener(ui.toggle_visibility)
    
    ui.showNormal()
    ui.activateWindow()
    ui.raise_()
    sys.exit(app.exec())

if __name__=="__main__":
    main()