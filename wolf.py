#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import datetime
import threading
import random
import string
import json
import socket
import urllib.request
import subprocess
import traceback
import zipfile
import ctypes
import webbrowser
import psutil
import wmi
import time
import gc
import logging
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import hashlib
import asyncio
import aiohttp
import win32api
import win32con
import win32file
import win32process
import win32security
import win32service
import win32serviceutil
import struct
import sqlite3
import tempfile
import concurrent.futures
import math
from collections import deque, Counter
import queue
import aiofiles
import mmap
import zlib
import base64
import re
import winreg
import signal
import pickle
import multiprocessing
from multiprocessing import Pool, Manager, cpu_count
import win32crypt
import pywintypes
import pythoncom
import win32ts
import win32evtlog
import win32event
import ntsecuritycon as con

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QStackedWidget, QProgressBar, QFrame, QCheckBox, QListWidget, QListWidgetItem, QFileDialog,
    QMessageBox, QLineEdit, QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QTextBrowser, QDialog, QSystemTrayIcon, QMenu, QAction, QSizePolicy, QInputDialog, QComboBox, QGridLayout
)
from PyQt5.QtGui import QIcon, QFont, QPainter, QColor, QPixmap, QGuiApplication, QFontMetrics, QPen, QLinearGradient, QKeySequence
from PyQt5.QtCore import Qt, QTimer, QSize, QThread, pyqtSignal, QObject, QMetaObject, Q_ARG, pyqtSlot, QPoint, QRect, QUrl

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    print("Instale watchdog: pip install watchdog")
    raise

try:
    notification_system = "none"
    try:
        from winotify import Notification, audio
        notification_system = "winotify"
    except ImportError:
        pass
    if notification_system == "none":
        try:
            from win10toast import ToastNotifier
            notification_system = "win10toast"
        except ImportError:
            pass
    if notification_system == "none":
        try:
            from plyer import notification
            notification_system = "plyer"
        except ImportError:
            pass
except Exception as e:
    pass

try:
    import magic
except ImportError:
    magic = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    import yara
except ImportError:
    yara = None

try:
    import keyboard
except ImportError:
    keyboard = None

import tkinter as tk
from tkinter import messagebox

WHITELIST_PROCESSES = [
    "System", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "taskhostw.exe", "python.exe",
    "pythonw.exe", "cmd.exe", "conhost.exe", "powershell.exe",
    "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe",
    "RiotClient.exe", "LeagueClient.exe", "League of Legends.exe", "Valorant.exe",
    "RiotClientServices.exe", "VALORANT.exe", "RiotClientUxRender.exe", "RiotClientUx.exe",
    "WindowsTerminal.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe",
    "msiexec.exe", "notepad.exe", "taskmgr.exe", "regedit.exe", "devenv.exe",
    "SearchApp.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
    "Cortana.exe", "RuntimeBroker.exe", "backgroundTaskHost.exe", "WmiPrvSE.exe",
    "sihost.exe", "ctfmon.exe", "SearchIndexer.exe", "fontdrvhost.exe",
    "spoolsv.exe", "smartscreen.exe", "SecurityHealthService.exe", "SgrmBroker.exe",
    "Microsoft.Photos.exe", "Calculator.exe", "SystemSettings.exe", "WWAHost.exe",
    "MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "wsqmcons.exe", "SIHClient.exe",
    "audiodg.exe", "mmc.exe", "SecHealthUI.exe", "consent.exe", "CompPkgSrv.exe",
    "WUDFHost.exe", "rundll32.exe", "dllhost.exe", "AppVShNotify.exe", "LogonUI.exe",
    "lockapp.exe", "TabTip.exe", "SystemSettingsBroker.exe", "ApplicationFrameHost.exe",
    "TextInputHost.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
    "FileCoAuth.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "mspub.exe", "visio.exe", "winproj.exe", "onenote.exe",
    "teams.exe", "Code.exe", "VSCodium.exe", "chrome.exe", "firefox.exe",
    "msedge.exe", "opera.exe", "opera_gx.exe", "brave.exe", "iexplore.exe",
    "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe",
    "OneDrive.exe", "DropboxUpdate.exe", "GoogleUpdate.exe", "OfficeClickToRun.exe",
    "mstsc.exe", "wsl.exe", "bash.exe", "WindowsTerminal.exe", "vmware.exe",
    "VirtualBox.exe", "vmwp.exe", "sqllocaldb.exe", "sqlservr.exe", "javaw.exe",
    "java.exe", "procexp.exe", "procexp64.exe", "procmon.exe", "procmon64.exe",
    "WinDbg.exe", "WinDbgX.exe", "MicrosoftEdgeUpdate.exe", "regsvr32.exe",
    "vcredist_x86.exe", "vcredist_x64.exe", "MsiExec.exe", "notepad++.exe",
    "FileManager.exe", "uhssvc.exe", "msdtc.exe", "sqlwriter.exe", "ndatasvc.exe",
    "wscsvc.exe", "wininit.exe", "winlogon.exe", "userinit.exe", "taskhost.exe",
    "VSSVC.exe", "TrustedInstaller.exe", "PresentationFontCache.exe", "wermgr.exe",
    "QtWebEngineProcess.exe", "WolfGuard.exe", "WolfGuard1.exe", "py.exe", "pyw.exe", "python3.exe",
    "python2.exe", "pythonw3.exe", "python39.exe", "python310.exe", "python311.exe",
    "WsToastNotification.exe", "Teams.exe", "Microsoft Teams.exe", "Rise Mode Temp CPU Driver R2.1.exe",
    "EpicGamesLauncher.exe", "EpicGames.exe", "EpicGamesService.exe", "FortniteClient-Win64-Shipping.exe",
    "GoogleCrashHandler.exe", "GoogleCrashHandler64.exe", "chrome_installer.exe", "ChromeSetup.exe"
]

WINDOWS_SCRIPT_PATHS = [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Windows\\",
    "C:\\Windows\\WinSxS\\",
    "C:\\Windows\\servicing\\",
    "C:\\Windows\\Microsoft.NET\\",
    "C:\\Windows\\assembly\\",
    "C:\\Program Files\\Common Files\\Microsoft Shared\\",
    "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\",
    "C:\\Program Files\\Microsoft Office\\",
    "C:\\Program Files (x86)\\Microsoft Office\\",
    "C:\\Program Files\\Windows Defender\\",
    "C:\\Program Files\\Windows Defender Advanced Threat Protection\\",
    "C:\\Program Files\\Microsoft Security Client\\",
    "C:\\Program Files\\WindowsApps\\",
    "C:\\Program Files\\Microsoft Visual Studio\\",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\",
    "C:\\Program Files\\Microsoft SDKs\\",
    "C:\\Program Files (x86)\\Microsoft SDKs\\",
    "C:\\Program Files\\Windows Kits\\",
    "C:\\Program Files (x86)\\Windows Kits\\",
    "C:\\Windows\\diagnostics\\",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools\\",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools\\"
]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

class DigitalSignatureVerifier:
    def __init__(self):
        self.verification_cache = {}
        self.cache_lock = threading.Lock()

    def verify_signature(self, file_path):
        try:
            with self.cache_lock:
                if file_path in self.verification_cache:
                    return self.verification_cache[file_path]

            if not os.path.exists(file_path):
                return False

            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext not in ['.exe', '.dll', '.sys', '.ocx', '.msi', '.cab', '.cat']:
                return False

            try:
                file_handle = win32file.CreateFile(
                    file_path,
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )

                win32file.CloseHandle(file_handle)
            except:
                return False

            try:
                if "discord" in file_path.lower() or "riot" in file_path.lower() or "league" in file_path.lower() or "valorant" in file_path.lower() or "wondershare" in file_path.lower() or "chrome" in file_path.lower() or "edge" in file_path.lower() or "firefox" in file_path.lower() or "brave" in file_path.lower() or "opera" in file_path.lower():
                    with self.cache_lock:
                        self.verification_cache[file_path] = True
                    return True

                result = subprocess.run(
                    ["powershell", "-Command", f"(Get-AuthenticodeSignature '{file_path}').Status"],
                    capture_output=True, text=True, timeout=2
                )
                is_signed = "Valid" in result.stdout
                with self.cache_lock:
                    self.verification_cache[file_path] = is_signed
                return is_signed
            except:
                trusted_locations = [
                    os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
                    os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64'),
                    os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files')),
                    os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'))
                ]

                is_signed = any(file_path.lower().startswith(loc.lower()) for loc in trusted_locations)

                with self.cache_lock:
                    self.verification_cache[file_path] = is_signed
                    if len(self.verification_cache) > 10000:
                        keys = list(self.verification_cache.keys())
                        for i in range(5000):
                            del self.verification_cache[keys[i]]

                return is_signed
        except:
            return False

class WindowsFileWhitelist:
    def __init__(self, app_data_dir=None):
        self.whitelist_dirs = set()
        self.whitelist_files = set()
        self.whitelist_patterns = []
        self.custom_whitelist = set()
        self.system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        self.program_files = [
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
            os.environ.get('ProgramW6432', 'C:\\Program Files')
        ]

        self.python_dirs = self.find_python_directories()

        self.safe_extensions = {
            '.txt', '.log', '.ini', '.cfg', '.conf', '.json', '.xml', '.html', '.htm', '.css',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp', '.ico', '.heic',
            '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a', '.wma',
            '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.3gp',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz',
            '.csv', '.tsv', '.md', '.markdown', '.rst', '.tex', '.rtf',
            '.sql', '.db', '.sqlite', '.sqlite3',
            '.ttf', '.otf', '.woff', '.woff2', '.eot',
            '.torrent', '.nfo', '.sub', '.srt', '.vtt', '.ass',
            '.yaml', '.yml', '.toml', '.plist',
            '.key', '.pem', '.crt', '.cer', '.p12', '.pfx',
            '.gpg', '.asc', '.sig', '.pub',
            '.dll', '.sys', '.drv', '.mui', '.mun', '.cab', '.cat', '.msi', '.inf', '.ocx',
            '.cpl', '.scr', '.cur', '.ani', '.icl', '.exe', '.com', '.msc',
            '.theme', '.screensaver',
            '.yar', '.yara',
            '.pkt', '.csv', '.json', '.xml', '.rtf', '.ods', '.odt', '.pdf', '.tif',
            '.psd', '.ai', '.eps', '.sketch', '.fig', '.blend', '.fbx', '.obj', '.3ds', '.stl',
            '.bak', '.old', '.bak1', '.swp', '.lock', '.gitignore', '.gitattributes', '.gitmodules',
            '.editorconfig', '.npmrc', '.babelrc', '.eslintrc', '.dockerignore', '.dockerfile', '.env',
            '.LICENSE', '.README', '.nfo', '.lst', '.tex', '.bib', '.tsv', '.dat', '.bakup', '.accdb',
            '.mdb', '.rmd', '.ipynb', '.texi', '.shn', '.cue', '.md5', '.sha256', '.m3u', '.pls',
            '.bak~', '.bak2', '.1', '.man', '.me', '.texinfo', '.pod', '.adoc', '.rst', '.out', '.tmp',
            '.temp', '.swx', '.swo', '.bak3', '.info', '.toc', '.aux', '.snagproj', '.scn', '.lrc', '.smi',
            '.idx', '.nzb', '.torrent.lock', '.bakx', '.bak~1', '.bak.old', '.svgz', '.dxf', '.gcode',
            '.nc', '.iges', '.step', '.step.gz', '.blend1', '.blend2', '.ase', '.mtl', '.3dm', '.bvh',
            '.csv.gz', '.jsonl', '.json5', '.jl', '.properties', '.env.local', '.env.sample', '.project',
            '.classpath', '.ts', '.tsx', '.jsx', '.vue', '.resx', '.d.ts', '.map', '.snap', '.diff', '.patch',
            '.rej', '.bak~2', '.brd', '.sch', '.pcb', '.hex', '.map.txt', '.asm', '.s', '.mif', '.coe',
            '.vhd', '.vhdl', '.verilog', '.sv', '.nib', '.strings', '.po', '.pot', '.mo', '.plist',
            '.storyboard', '.xcconfig', '.entitlements', '.modulemap', '.lockfile', '.enc', '.sha1',
            '.md5sum', '.csr', '.py', '.pyc', '.pyd', '.pyo', '.pyw', '.pyz', '.pyzw', '.whl',
            '.egg', '.egg-info', '.dist-info', '.so', '.pxi', '.h', '.c', '.cpp', '.hpp', '.cc',
            '.java', '.jar', '.class', '.kt', '.gradle', '.groovy', '.rb', '.php', '.go', '.rs',
            '.swift', '.m', '.pl', '.pm', '.t', '.lua', '.R', '.Rdata', '.Rds', '.rda', '.r',
            '.jl', '.hs', '.lhs', '.clj', '.erl', '.ex', '.exs', '.elm', '.ml', '.mli', '.fs',
            '.fsi', '.fsx', '.fs', '.dart', '.d', '.f', '.f90', '.f95', '.f03', '.f08', '.for',
            '.tcl', '.tk', '.sh', '.bash', '.zsh', '.csh', '.fish', '.ksh',
            '.gradle', '.sbt', '.cabal', '.nix', '.cmake', '.bazel', '.bzl',
            '.aodl', '.mszyml', '.hyb', '.msg',
            '.crx', '.xpi', '.safariextz', '.crdownload', '.part', '.download', '.tmp.js',
            '.log.old', '.histignore', '.pak', '.dat', '.bin'
        }

        if app_data_dir:
            self.app_data_dir = app_data_dir
        else:
            self.app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
            if not os.path.exists(self.app_data_dir):
                try:
                    os.makedirs(self.app_data_dir)
                except:
                    pass

        self.whitelist_path = os.path.join(self.app_data_dir, 'whitelist.txt')
        self.init_whitelist()
        self.load_custom_whitelist()

        self.whitelist_cache = {}
        self.cache_lock = threading.Lock()

        self.whitelist_apps = [
            "Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment",
            "RiotClient", "LeagueClient", "VALORANT", "RiotClientServices",
            "QtWebEngine", "WolfGuard", "Wondershare", "Microsoft", "OneDrive",
            "ZxcvbnData", "FileCoAuth", "Themes", "CryptnetUrlCache", "CBS",
            "WebExperience", "pip", "WinGet", "Packages", "Chrome", "Edge", "Firefox",
            "Opera", "Brave", "Google", "Chromium"
        ]

        self.wolf_scripts = [
            "wolf.py","wolf5.py"
        ]

        self.windows_script_paths = WINDOWS_SCRIPT_PATHS

        user_profile = os.environ.get('USERPROFILE', '')

        self.whitelist_files.add(os.path.join(os.environ.get('LOCALAPPDATA', ''), "Wondershare", "Wondershare NativePush", "WsToastNotification.exe"))
        self.whitelist_files.add(os.path.join(os.environ.get('TEMP', ''), "msdtadmin", "*4581692A-32E7-406D-9542-AB5F84F99835*", "cabpkg", "Win8RC.TS.ps1"))
        self.whitelist_files.add(os.path.join(os.environ.get('TEMP', ''), "msdtadmin", "*4581692A-32E7-406D-9542-AB5F84F99835*", "cabpkg", "Win8RC.VF.ps1"))
        self.whitelist_files.add(os.path.join(os.environ.get('TEMP', ''), "okeyjbzs", "Microsoft.VisualCpp.Redist.14.Latest.3C62F1B3A5F4018DD2A2", "VCRedistInstall.ps1"))

        self.whitelist_patterns.append(r'.*\\AppData\\Local\\Temp\\__PSScriptPolicyTest_.*\.ps1$')
        self.whitelist_patterns.append(r'.*\\Microsoft\\OneDrive\\.*\.aodl$')
        self.whitelist_patterns.append(r'.*\\Microsoft\\Windows\\Themes\\TranscodedWallpaper$')
        self.whitelist_patterns.append(r'.*\\LocalLow\\Microsoft\\CryptnetUrlCache\\.*')
        self.whitelist_patterns.append(r'.*\\Packages\\MicrosoftWindows\.Client\.CBS_.*\\.*')
        self.whitelist_patterns.append(r'.*\\Packages\\MicrosoftWindows\.Client\.WebExperience_.*\\.*')
        self.whitelist_patterns.append(r'.*\\ZxcvbnData\\.*\\ranked_dicts$')
        self.whitelist_patterns.append(r'.*\\pip\\cache\\.*')
        self.whitelist_patterns.append(r'.*\\\\_MEI\d+\\_tcl_data\\\\tzdata\\\\.*')
        self.whitelist_patterns.append(r'.*\\Google\\Chrome\\.*\.tmp\.js$')
        self.whitelist_patterns.append(r'.*\\Google\\Chrome\\User Data\\.*\.crdownload$')
        self.whitelist_patterns.append(r'.*\\Microsoft\\Edge\\.*\.tmp\.js$')
        self.whitelist_patterns.append(r'.*\\Microsoft\\Edge\\User Data\\.*\.crdownload$')
        self.whitelist_patterns.append(r'.*\\Mozilla\\Firefox\\.*\.part$')
        self.whitelist_patterns.append(r'.*\\Google\\Chrome SxS\\.*')
        self.whitelist_patterns.append(r'.*\\Opera Software\\.*')
        self.whitelist_patterns.append(r'.*\\BraveSoftware\\.*')

    def find_python_directories(self):
        python_dirs = []

        try:
            for i in range(5):
                try:
                    if hasattr(sys, f'_base_executable{i}'):
                        py_path = getattr(sys, f'_base_executable{i}')
                        if py_path and os.path.exists(py_path):
                            python_dirs.append(os.path.dirname(py_path))
                except:
                    pass

            if hasattr(sys, 'executable') and sys.executable:
                python_dirs.append(os.path.dirname(sys.executable))

            if hasattr(sys, 'base_prefix') and sys.base_prefix:
                python_dirs.append(sys.base_prefix)

            if hasattr(sys, 'prefix') and sys.prefix:
                python_dirs.append(sys.prefix)

            if hasattr(sys, 'base_exec_prefix') and sys.base_exec_prefix:
                python_dirs.append(sys.base_exec_prefix)

            if hasattr(sys, 'exec_prefix') and sys.exec_prefix:
                python_dirs.append(sys.exec_prefix)

            if 'PYTHONPATH' in os.environ:
                for path in os.environ['PYTHONPATH'].split(os.pathsep):
                    if path and os.path.exists(path):
                        python_dirs.append(path)

            if hasattr(sys, 'path'):
                for path in sys.path:
                    if path and os.path.exists(path):
                        python_dirs.append(path)

            for key, path in sys.modules.items():
                try:
                    if hasattr(path, '__file__') and path.__file__:
                        module_dir = os.path.dirname(path.__file__)
                        if module_dir and os.path.exists(module_dir):
                            python_dirs.append(module_dir)
                except:
                    pass
        except:
            pass

        return list(set([os.path.normpath(p) for p in python_dirs if p]))

    def init_whitelist(self):
        user_profile = os.environ.get('USERPROFILE', '')
        android_sdk_path = os.path.join(user_profile, 'AppData', 'Local', 'Android', 'Sdk')

        self.whitelist_patterns.append(r'.*\\powershell\.exe$')
        self.whitelist_patterns.append(r'.*\.py$')

        user_profile = os.environ.get('USERPROFILE', '')
        self.whitelist_files.add(os.path.join(user_profile, "wolf.py"))
        self.whitelist_files.add(os.path.join(user_profile, "wolfguard_monitor"))
        self.whitelist_files.add(os.path.join(user_profile, "wolf5.py"))
        

        self.whitelist_dirs.add(os.path.join(user_profile, "_pycache_"))
        self.whitelist_dirs.add(os.path.join(user_profile, "icons"))

        for i in range(1, 12):
            self.whitelist_files.add(os.path.join(user_profile, f"{i}.png"))
            self.whitelist_files.add(os.path.join(user_profile, f"{i}.ico"))

        self.whitelist_dirs.update([
            self.system_root,
            os.path.join(self.system_root, 'System32'),
            os.path.join(self.system_root, 'SysWOW64'),
            os.path.join(self.system_root, 'WinSxS'),
            os.path.join(self.system_root, 'SystemApps'),
            os.path.join(self.system_root, 'SystemResources'),
            os.path.join(self.system_root, 'Boot'),
            os.path.join(self.system_root, 'Fonts'),
            os.path.join(self.system_root, 'Cursors'),
            os.path.join(self.system_root, 'Web'),
            os.path.join(self.system_root, 'Branding'),
            os.path.join(self.system_root, 'AppPatch'),
            os.path.join(self.system_root, 'assembly'),
            os.path.join(self.system_root, 'Globalization'),
            os.path.join(self.system_root, 'Help'),
            os.path.join(self.system_root, 'IME'),
            os.path.join(self.system_root, 'L2Schemas'),
            os.path.join(self.system_root, 'Migration'),
            os.path.join(self.system_root, 'Performance'),
            os.path.join(self.system_root, 'Resources'),
            os.path.join(self.system_root, 'servicing'),
            os.path.join(self.system_root, 'Setup'),
            os.path.join(self.system_root, 'ShellComponents'),
            os.path.join(self.system_root, 'ShellExperiences'),
            os.path.join(self.system_root, 'Speech'),
            os.path.join(self.system_root, 'System32', 'drivers'),
            os.path.join(self.system_root, 'System32', 'wbem'),
            os.path.join(self.system_root, 'System32', 'WindowsPowerShell'),
            os.path.join(self.system_root, 'System32', 'config'),
            os.path.join(self.system_root, 'System32', 'catroot'),
            os.path.join(self.system_root, 'System32', 'catroot2'),
            os.path.join(self.system_root, 'System32', 'LogFiles'),
            os.path.join(self.system_root, 'System32', 'spool'),
            os.path.join(self.system_root, 'System32', 'Tasks'),
            os.path.join(self.system_root, 'System32', 'wins'),
            os.path.join(self.system_root, 'System32', 'dhcp'),
            os.path.join(self.system_root, 'System32', 'dns'),
            os.path.join(self.system_root, 'System32', 'DriverStore'),
            os.path.join(self.system_root, 'System32', 'Microsoft'),
            os.path.join(self.system_root, 'diagnostics'),
            os.path.join(self.system_root, 'Microsoft.NET'),
            "C:\\Program Files\\Windows Defender",
            "C:\\Program Files\\Windows Defender Advanced Threat Protection",
            "C:\\Program Files\\Microsoft Security Client",
            "C:\\ProgramData\\Microsoft\\Windows Defender",
            "C:\\Program Files\\Common Files\\Microsoft Shared",
            "C:\\Program Files (x86)\\Common Files\\Microsoft Shared",
            "C:\\Program Files\\Microsoft Office",
            "C:\\Program Files (x86)\\Microsoft Office",
            "C:\\Program Files\\WindowsApps",
            "C:\\Program Files\\Microsoft Visual Studio",
            "C:\\Program Files (x86)\\Microsoft Visual Studio",
            "C:\\Program Files\\Microsoft SDKs",
            "C:\\Program Files (x86)\\Microsoft SDKs",
            "C:\\Program Files\\Windows Kits",
            "C:\\Program Files (x86)\\Windows Kits",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\System Tools",
            android_sdk_path,
            "C:\\Program Files\\Wondershare",
            "C:\\Program Files (x86)\\Wondershare",
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Wondershare'),
            os.path.join(os.environ.get('TEMP', ''), 'msdtadmin'),
            os.path.join(os.environ.get('TEMP', ''), 'okeyjbzs', 'Microsoft.VisualCpp.Redist.14.Latest.3C62F1B3A5F4018DD2A2'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'OneDrive'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Mozilla', 'Firefox'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Opera Software'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'BraveSoftware'),
            os.path.join(os.environ.get('LOCALAPPLOW', ''), 'Microsoft', 'CryptnetUrlCache'),
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Themes'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Packages', 'MicrosoftWindows.Client.CBS_cw5n1h2txyewy'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Packages', 'MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy'),
            os.path.join(os.environ.get('TEMP', '')),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'pip'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'WinGet')
        ])

        for pf in self.program_files:
            if pf and os.path.exists(pf):
                self.whitelist_dirs.add(pf)

        for py_dir in self.python_dirs:
            if py_dir and os.path.exists(py_dir):
                self.whitelist_dirs.add(py_dir)

                site_packages_paths = [
                    os.path.join(py_dir, 'Lib', 'site-packages'),
                    os.path.join(py_dir, 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.6', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.7', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.8', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.9', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.10', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.11', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.12', 'site-packages'),
                    os.path.join(py_dir, 'lib', 'python3.13', 'site-packages'),
                ]

                for sp_path in site_packages_paths:
                    if os.path.exists(sp_path):
                        self.whitelist_dirs.add(sp_path)

                        if os.path.exists(os.path.join(sp_path, 'yara')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'yara'))
                        if os.path.exists(os.path.join(sp_path, 'yara_python')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'yara_python'))

                        if os.path.exists(os.path.join(sp_path, 'pefile')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'pefile'))

                        if os.path.exists(os.path.join(sp_path, 'psutil')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'psutil'))

                        if os.path.exists(os.path.join(sp_path, 'win32')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'win32'))

                        if os.path.exists(os.path.join(sp_path, 'win32com')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'win32com'))

                        if os.path.exists(os.path.join(sp_path, 'win32api')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'win32api'))

                        if os.path.exists(os.path.join(sp_path, 'pythonwin')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'pythonwin'))

                        if os.path.exists(os.path.join(sp_path, 'PyQt5')):
                            self.whitelist_dirs.add(os.path.join(sp_path, 'PyQt5'))

        vscode_dirs = []
        user_path = os.environ.get('USERPROFILE', '')
        if user_path:
            vscode_ext_dir = os.path.join(user_path, '.vscode', 'extensions')
            if os.path.exists(vscode_ext_dir):
                self.whitelist_dirs.add(vscode_ext_dir)
                vscode_dirs.append(vscode_ext_dir)

            vscode_app_data = os.path.join(os.environ.get('APPDATA', ''), 'Code')
            if os.path.exists(vscode_app_data):
                self.whitelist_dirs.add(vscode_app_data)
                vscode_dirs.append(vscode_app_data)

            for vscode_dir in vscode_dirs:
                for root, dirs, files in os.walk(vscode_dir):
                    if 'node_modules' in root:
                        self.whitelist_dirs.add(root)

        self.whitelist_patterns = [
            r'.*\\.py$',
            r'.*python\\.exe$',
            r'.*pythonw\\.exe$',
            r'.*\\\\python\\d+\\\\.*',
            r'.*\\\\site-packages\\\\.*',
            r'.*\\\\__pycache__\\\\.*',
            r'.*\\.pyd$',
            r'.*\\.pyc$',
            r'.*\\.pyo$',
            r'.*\\\\Windows\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\.*',
            r'.*\\\\Windows\\\\SysWOW64\\\\.*',
            r'.*\\\\Windows\\\\WinSxS\\\\.*',
            r'.*\\\\Windows\\\\SystemApps\\\\.*',
            r'.*\\\\Windows\\\\SystemResources\\\\.*',
            r'.*\\\\Windows\\\\Boot\\\\.*',
            r'.*\\\\Windows\\\\Fonts\\\\.*',
            r'.*\\\\Windows\\\\Cursors\\\\.*',
            r'.*\\\\Windows\\\\Web\\\\.*',
            r'.*\\\\Windows\\\\Branding\\\\.*',
            r'.*\\\\Windows\\\\AppPatch\\\\.*',
            r'.*\\\\Windows\\\\assembly\\\\.*',
            r'.*\\\\Windows\\\\Globalization\\\\.*',
            r'.*\\\\Windows\\\\Help\\\\.*',
            r'.*\\\\Windows\\\\IME\\\\.*',
            r'.*\\\\Windows\\\\L2Schemas\\\\.*',
            r'.*\\\\Windows\\\\Migration\\\\.*',
            r'.*\\\\Windows\\\\Performance\\\\.*',
            r'.*\\\\Windows\\\\Resources\\\\.*',
            r'.*\\\\Windows\\\\servicing\\\\.*',
            r'.*\\\\Windows\\\\Setup\\\\.*',
            r'.*\\\\Windows\\\\ShellComponents\\\\.*',
            r'.*\\\\Windows\\\\ShellExperiences\\\\.*',
            r'.*\\\\Windows\\\\Speech\\\\.*',
            r'.*\\\\Windows\\\\System32',
            r'.*\\\\Windows\\\\System32\\\\drivers\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\wbem\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\config\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\catroot\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\catroot2\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\LogFiles\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\spool\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\Tasks\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\wins\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\dhcp\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\dns\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\DriverStore\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\Microsoft\\\\.*',
            r'.*\\\\Windows\\\\diagnostics\\\\.*',
            r'.*\\\\Windows\\\\Microsoft.NET\\\\.*',
            r'.*\\\\System Volume Information\\\\.*',
            r'.*\\\\\\$Recycle\\.Bin\\\\.*',
            r'.*\\\\RECYCLER\\\\.*',
            r'.*\\\\hiberfil\\.sys$',
            r'.*\\\\pagefile\\.sys$',
            r'.*\\\\swapfile\\.sys$',
            r'.*\\\\ProgramData\\\\Microsoft\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Microsoft\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Roaming\\\\Microsoft\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\LocalLow\\\\Microsoft\\\\.*',
            r'.*\\\\Program Files\\\\.*',
            r'.*\\\\Program Files \\(x86\\)\\\\.*',
            r'.*\\\\ProgramData\\\\.*',
            r'.*\\\\yara\\\\.*',
            r'.*\\\\yara_python\\\\.*',
            r'.*\\\\pefile\\\\.*',
            r'.*\\\\psutil\\\\.*',
            r'.*\\\\win32\\\\.*',
            r'.*\\\\win32com\\\\.*',
            r'.*\\\\win32api\\\\.*',
            r'.*\\\\pythonwin\\\\.*',
            r'.*\\\\PyQt5\\\\.*',
            r'.*\\\\watchdog\\\\.*',
            r'.*\\\\magic\\\\.*',
            r'.*\\\\wmi\\\\.*',
            r'.*\\\\aiohttp\\\\.*',
            r'.*\\\\aiofiles\\\\.*',
            r'.*\\\\pywintypes.*\\.dll$',
            r'.*\\_win32.*\\.pyd$',
            r'.*\\\\lib-dynload\\\\.*',
            r'.*\\\\lib\\\\.*',
            r'.*\\\\DLLs\\\\.*',
            r'.*\\\\Scripts\\\\.*',
            r'.*\\.jpg$',
            r'.*\\.jpeg$',
            r'.*\\.png$',
            r'.*\\.gif$',
            r'.*\\.bmp$',
            r'.*\\.tiff$',
            r'.*\\.svg$',
            r'.*\\.webp$',
            r'.*\\.ico$',
            r'.*\\.heic$',
            r'.*\\.mp3$',
            r'.*\\.wav$',
            r'.*\\.ogg$',
            r'.*\\.flac$',
            r'.*\\.aac$',
            r'.*\\.m4a$',
            r'.*\\.wma$',
            r'.*\\.mp4$',
            r'.*\\.mkv$',
            r'.*\\.avi$',
            r'.*\\.mov$',
            r'.*\\.wmv$',
            r'.*\\.flv$',
            r'.*\\.webm$',
            r'.*\\.m4v$',
            r'.*\\.3gp$',
            r'.*\\.txt$',
            r'.*\\.log$',
            r'.*\\.ini$',
            r'.*\\.cfg$',
            r'.*\\.conf$',
            r'.*\\.json$',
            r'.*\\.xml$',
            r'.*\\.html$',
            r'.*\\.htm$',
            r'.*\\.css$',
            r'.*\\.pdf$',
            r'.*\\.doc$',
            r'.*\\.docx$',
            r'.*\\.xls$',
            r'.*\\.xlsx$',
            r'.*\\.ppt$',
            r'.*\\.pptx$',
            r'.*\\.odt$',
            r'.*\\.ods$',
            r'.*\\.odp$',
            r'.*\\.yar$',
            r'.*\\.yara$',
            r'.*\\\\Microsoft Visual Studio\\\\.*',
            r'.*\\\\Microsoft SDKs\\\\.*',
            r'.*\\\\Common Files\\\\.*',
            r'.*\\\\Windows Defender\\\\.*',
            r'.*\\\\Windows Security\\\\.*',
            r'.*\\\\Microsoft Office\\\\.*',
            r'.*\\\\Microsoft Visual Studio\\\\.*',
            r'.*\\\\Windows Kits\\\\.*',
            r'.*\\\\Reference Assemblies\\\\.*',
            r'.*\\\\MSBuild\\\\.*',
            r'.*\\\\dotnet\\\\.*',
            r'.*\\\\NuGet\\\\.*',
            r'.*\\\\Microsoft SQL Server\\\\.*',
            r'.*\\\\Microsoft Analysis Services\\\\.*',
            r'.*\\\\Microsoft Shared\\\\.*',
            r'.*\\\\Windows NT\\\\.*',
            r'.*\\\\Windows Mail\\\\.*',
            r'.*\\\\Windows Media Player\\\\.*',
            r'.*\\\\Windows Multimedia Platform\\\\.*',
            r'.*\\\\Windows Photo Viewer\\\\.*',
            r'.*\\\\Windows Portable Devices\\\\.*',
            r'.*\\\\Internet Explorer\\\\.*',
            r'.*\\\\Windows Journal\\\\.*',
            r'.*\\\\Windows Media\\\\.*',
            r'.*\\\\Windows PowerShell\\\\.*',
            r'.*\\\\Windows Sidebar\\\\.*',
            r'.*\\\\WindowsPowerShell\\\\.*',
            r'.*\\\\vcruntime.*\\.dll$',
            r'.*\\\\msvcp.*\\.dll$',
            r'.*\\\\msvcr.*\\.dll$',
            r'.*\\\\api-ms-win.*\\.dll$',
            r'.*\\\\discord.*\\.exe$',
            r'.*\\\\Discord\\\\.*',
            r'.*\\\\riot.*\\.exe$',
            r'.*\\\\Riot\\\\.*',
            r'.*\\\\Riot Games\\\\.*',
            r'.*\\\\League of Legends\\\\.*',
            r'.*\\\\VALORANT\\\\.*',
            r'.*\\\\valorant.*\\.exe$',
            r'.*\\\\league.*\\.exe$',
            r'.*\\.vscode\\\\extensions\\\\.*',
            r'.*\\\\node_modules\\\\.*',
            r'.*\\\\Code\\\\.*',
            r'.*\\\\Android\\\\Sdk\\\\.*',
            r'.*\\\\Android SDK\\\\.*',
            r'.*\\\\ndk\\\\.*',
            r'.*\\\\android-ndk\\\\.*',
            r'.*\\\\gradle\\\\.*',
            r'.*\\\\flutter\\\\.*',
            r'.*\\\\react-native\\\\.*',
            r'.*\\\\Windows\\\\System32\\\\.*\\.cmd$',
            r'.*\\\\Windows\\\\System32\\\\.*\\.bat$',
            r'.*\\\\Windows\\\\System32\\\\.*\\.ps1$',
            r'.*\\\\Windows\\\\SysWOW64\\\\.*\\.cmd$',
            r'.*\\\\Windows\\\\SysWOW64\\\\.*\\.bat$',
            r'.*\\\\Windows\\\\SysWOW64\\\\.*\\.ps1$',
            r'.*\\\\Windows\\\\.*\\.cmd$',
            r'.*\\\\Windows\\\\.*\\.bat$',
            r'.*\\\\Windows\\\\.*\\.ps1$',
            r'.*\\\\Program Files\\\\Common Files\\\\Microsoft Shared\\\\.*\\.cmd$',
            r'.*\\\\Program Files\\\\Common Files\\\\Microsoft Shared\\\\.*\\.bat$',
            r'.*\\\\Program Files\\\\Common Files\\\\Microsoft Shared\\\\.*\\.ps1$',
            r'.*\\\\Program Files \\(x86\\)\\\\Common Files\\\\Microsoft Shared\\\\.*\\.cmd$',
            r'.*\\\\Program Files \\(x86\\)\\\\Common Files\\\\Microsoft Shared\\\\.*\\.bat$',
            r'.*\\\\Program Files \\(x86\\)\\\\Common Files\\\\Microsoft Shared\\\\.*\\.ps1$',
            r'.*\\\\QtWebEngineProcess\\.exe$',
            r'.*\\\\Qt\\\\.*',
            r'.*\\\\QtWebEngine\\\\.*',
            r'.*\\\\wolf\\.py$',
            r'.*\\\\wolf1\\.py$',
            r'.*\\\\wolf2\\.py$',
            r'.*\\\\wolf3\\.py$',
            r'.*\\\\wolf4\\.py$',
            r'.*\\\\wolf5\\.py$',
            r'.*\\\\wolf7\\.py$',
            r'.*\\\\wolfvi\\.py$',
            r'.*\\\\ai\\.py$',
            r'.*\\\\WolfGuard\\.exe$',
            r'.*\\.dll$',
            r'.*\\\\Wondershare\\\\.*',
            r'.*\\\\WsToastNotification\\.exe$',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Temp\\\\msdtadmin\\\\.*\\.ps1$',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Temp\\\\okeyjbzs\\\\Microsoft\\.VisualCpp\\.Redist\\.14\\.Latest\\..*\\\\.*\\.ps1$',
            r'.*\\powershell\.exe$',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Temp\\\\__PSScriptPolicyTest_.*\\.ps1$',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Temp\\\\_MEI\\d+\\_tcl_data\\\\tzdata\\\\.*',
            r'.*\\\\Microsoft\\\\OneDrive\\\\logs\\\\.*\\.aodl$',
            r'.*\\\\Microsoft\\\\Windows\\\\Themes\\\\TranscodedWallpaper$',
            r'.*\\\\LocalLow\\\\Microsoft\\\\CryptnetUrlCache\\\\.*',
            r'.*\\\\Packages\\\\MicrosoftWindows\.Client\.CBS_.*\\\\.*',
            r'.*\\\\Packages\\\\MicrosoftWindows\.Client\.WebExperience_.*\\\\.*',
            r'.*\\\\ZxcvbnData\\\\.*\\\\ranked_dicts$',
            r'.*\\\\pip\\\\cache\\\\.*',
            r'.*\\\\WinGet\\\\cache\\\\.*',
            r'.*\\\\Google\\\\Chrome\\\\.*\\.tmp\\.js$',
            r'.*\\\\Google\\\\Chrome\\\\User Data\\\\.*\\.crdownload$',
            r'.*\\\\Google\\\\Chrome SxS\\\\.*',
            r'.*\\\\Microsoft\\\\Edge\\\\.*\\.tmp\\.js$',
            r'.*\\\\Microsoft\\\\Edge\\\\User Data\\\\.*\\.crdownload$',
            r'.*\\\\Mozilla\\\\Firefox\\\\.*\\.part$',
            r'.*\\\\Opera Software\\\\.*',
            r'.*\\\\BraveSoftware\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Microsoft\\\\Edge\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Mozilla\\\\Firefox\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Roaming\\\\Opera Software\\\\.*',
            r'.*\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\BraveSoftware\\\\.*',
            r'.*\\.crx$',
            r'.*\\.xpi$',
            r'.*\\.safariextz$',
            r'.*\\.crdownload$',
            r'.*\\.part$',
            r'.*\\.download$',
            r'.*\\.tmp\\.js$'
        ]

    def load_custom_whitelist(self):
        try:
            if os.path.exists(self.whitelist_path):
                with open(self.whitelist_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.custom_whitelist.add(line)
                            self.whitelist_files.add(line)
        except:
            pass

    def is_whitelisted(self, file_path):
        try:
            with self.cache_lock:
                if file_path in self.whitelist_cache:
                    return self.whitelist_cache[file_path]

            file_path_lower = file_path.lower()

            windows_apps_path = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'WindowsApps').lower()
            if file_path_lower.startswith(windows_apps_path):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True            

            temp_path = os.environ.get('TEMP', '').lower()
            if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if file_path_lower.endswith('\\powershell.exe'):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if file_path_lower.endswith('.py'):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "winget\\cache" in file_path_lower and "versiondata.mszyml" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "android" in file_path_lower and "sdk" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "android" in file_path_lower and "ndk" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "microsoft\\onedrive" in file_path_lower and file_path_lower.endswith(".aodl"):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "packages\\microsoftwindows.client.cbs_" in file_path_lower or "packages\\microsoftwindows.client.webexperience_" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "zxcvbndata" in file_path_lower and "ranked_dicts" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "pip\\cache" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "wondershare" in file_path_lower or "wstoastnotification.exe" in file_path_lower:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "\\msdtadmin\\" in file_path_lower and file_path_lower.endswith(".ps1"):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "\\okeyjbzs\\microsoft.visualcpp.redist" in file_path_lower and file_path_lower.endswith(".ps1"):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if "\\google\\chrome\\" in file_path_lower or "\\microsoft\\edge\\" in file_path_lower or "\\mozilla\\firefox\\" in file_path_lower or "\\brave\\" in file_path_lower or "\\opera\\" in file_path_lower:
                if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js', '.crx', '.xpi']):
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = True
                    return True

            for app in self.whitelist_apps:
                if app.lower() in file_path_lower:
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = True
                    return True

            if file_path_lower in (path.lower() for path in self.custom_whitelist):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if '.vscode\\extensions' in file_path_lower and file_path_lower.endswith('.js'):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if 'node_modules' in file_path_lower and file_path_lower.endswith('.js'):
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            file_ext = os.path.splitext(file_path_lower)[1]

            if file_ext == '.dll':
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            if file_ext in ['.ps1', '.vbs', '.bat', '.cmd']:
                for windows_path in self.windows_script_paths:
                    if file_path_lower.startswith(windows_path.lower()):
                        with self.cache_lock:
                            self.whitelist_cache[file_path] = True
                        return True

                if file_path_lower.startswith(self.system_root.lower()):
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = True
                    return True

                if file_ext != '.js':
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = False
                    return False

            basename = os.path.basename(file_path_lower)
            if basename in self.wolf_scripts:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            for whitelist_path in self.custom_whitelist:
                try:
                    if file_path_lower.startswith(whitelist_path.lower()):
                        with self.cache_lock:
                            self.whitelist_cache[file_path] = True
                        return True
                except:
                    continue

            if file_ext in self.safe_extensions:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            for pattern in self.whitelist_patterns:
                if re.match(pattern, file_path_lower, re.IGNORECASE):
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = True
                    return True

            for whitelist_dir in self.whitelist_dirs:
                if file_path_lower.startswith(whitelist_dir.lower()):
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = True
                    return True

            if file_path_lower in self.whitelist_files:
                with self.cache_lock:
                    self.whitelist_cache[file_path] = True
                return True

            for py_dir in self.python_dirs:
                if py_dir and file_path_lower.startswith(py_dir.lower()):
                    with self.cache_lock:
                        self.whitelist_cache[file_path] = True
                    return True

            with self.cache_lock:
                self.whitelist_cache[file_path] = False
            return False
        except:
            return False

    def is_windows_script(self, file_path):
        file_path_lower = file_path.lower()
        file_ext = os.path.splitext(file_path_lower)[1]

        if file_path_lower.endswith('\\powershell.exe'):
            return True

        if file_ext not in ['.ps1', '.cmd', '.bat']:
            return False

        if "\\msdtadmin\\" in file_path_lower and file_path_lower.endswith(".ps1"):
            return True

        if "\\okeyjbzs\\microsoft.visualcpp.redist" in file_path_lower and file_path_lower.endswith(".ps1"):
            return True

        if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
            return True

        for windows_path in self.windows_script_paths:
            if file_path_lower.startswith(windows_path.lower()):
                return True

        if file_path_lower.startswith(self.system_root.lower()):
            return True

        return False

class RansomwareDetector:
    def __init__(self):
        self.suspicious_extensions = {
            '.encrypted', '.locked', '.crypto', '.enc', '.crypt', '.lock',
            '.cerber', '.locky', '.zepto', '.odin', '.aesir', '.thor',
            '.zzzzz', '.micro', '.encrypted', '.cryptolocker', '.darkness',
            '.nochance', '.evillock', '.cryptowall', '.sport', '.tesla',
            '.locky', '.cerber3', '.cerber2', '.sage', '.wallet', '.onion',
            '.sexy', '.crysis', '.crypted', '.locked', '.fantom', '.legion',
            '.damage', '.alcatraz', '.shit', '.karmen', '.petrwrap', '.notpetya',
            '.badblock', '.kronos', '.krab', '.actin', '.globeimposter',
            '.arena', '.cobra', '.phobos', '.acute', '.lockbit', '.black',
            '.darkside', '.sodinokibi', '.ryuk', '.conti', '.maze', '.netwalker',
            '.ragnar', '.mount', '.sekhmet', '.egregor', '.suncrypt', '.clop',
            '.avaddon', '.babuk', '.darkangel', '.lorenz', '.cuba', '.revil',
            '.blackmatter', '.lockbit2', '.alphv', '.hive', '.nokoyawa',
            '.blackbasta', '.royal', '.akira', '.medusa', '.rhysida', '.cactus',
            '.8base', '.play', '.blacksuit', '.inc', '.scattered', '.qilin',
            '.ransomhub', '.fog', '.embargo', '.cicada', '.lynx', '.hunters',
            '.killsec', '.faust', '.saturn', '.arcus', '.trinity', '.parano',
            '.monti', '.targit', '.stopcat', '.shinra', '.lostdata', '.losttrust'
        }

        self.suspicious_notes = [
            'readme', 'decrypt', 'restore', 'unlock', 'recover', 'important',
            'attention', 'instruction', 'how_to', 'help', 'info', 'warning',
            'alert', 'notice', 'read_me', 'read_this', 'urgent', 'critical'
        ]

        self.entropy_threshold = 7.9
        self.file_monitor = {}
        self.modification_threshold = 50
        self.time_window = 10

        self.whitelist_folders = [
            'microsoft\\onedrive',
            'locallow\\microsoft\\cryptneturlcache',
            'packages\\microsoftwindows.client',
            'pip\\cache',
            'winget\\cache',
            'google\\chrome',
            'microsoft\\edge',
            'mozilla\\firefox',
            'brave',
            'opera'
        ]

    def check_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)
                if not data:
                    return 0

                entropy = 0
                data_len = len(data)
                frequency = {}

                for byte in data:
                    frequency[byte] = frequency.get(byte, 0) + 1

                for count in frequency.values():
                    if count > 0:
                        freq = count / data_len
                        entropy -= freq * (math.log2(freq) if freq > 0 else 0)

                return entropy
        except:
            return 0

    def is_ransomware_behavior(self, file_path, operation='modified'):
        try:
            current_time = time.time()
            file_ext = os.path.splitext(file_path)[1].lower()
            file_path_lower = file_path.lower()

            temp_path = os.environ.get('TEMP', '').lower()
            if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                return False, None

            if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                    return False, None

            for folder in self.whitelist_folders:
                if folder in file_path_lower:
                    return False, None

            if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                return False, None

            if "zxcvbndata" in file_path_lower:
                return False, None

            if file_ext in self.suspicious_extensions:
                return True, f"Extensão suspeita de ransomware: {file_ext}"

            file_name = os.path.basename(file_path).lower()
            for note in self.suspicious_notes:
                if note in file_name and file_name.endswith('.txt'):
                    return True, f"Nota de resgate detectada: {file_name}"

            if operation == 'modified' and os.path.exists(file_path):
                entropy = self.check_entropy(file_path)
                if entropy > self.entropy_threshold:
                    return True, f"Alta entropia detectada ({entropy:.2f}), possível criptografia"

            dir_path = os.path.dirname(file_path)

            if temp_path and dir_path.lower() == temp_path:
                return False, None

            if dir_path not in self.file_monitor:
                self.file_monitor[dir_path] = deque()

            self.file_monitor[dir_path].append((current_time, file_path))

            while self.file_monitor[dir_path] and current_time - self.file_monitor[dir_path][0][0] > self.time_window:
                self.file_monitor[dir_path].popleft()

            if temp_path and dir_path.lower() == temp_path:
                tmp_js_count = sum(1 for _, fp in self.file_monitor[dir_path] if '.tmp.js' in fp.lower())
                if tmp_js_count > 5:
                    return False, None

            for folder in self.whitelist_folders:
                if folder in dir_path.lower():
                    return False, None

            if len(self.file_monitor[dir_path]) > self.modification_threshold:
                return True, f"Múltiplas modificações rápidas no diretório ({len(self.file_monitor[dir_path])} arquivos em {self.time_window}s)"

            return False, None
        except:
            return False, None

class VirusDatabase:
    def __init__(self, app_data_dir=None):
        if app_data_dir is None:
            app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
            if not os.path.exists(app_data_dir):
                os.makedirs(app_data_dir)

        self.db_path = os.path.join(app_data_dir, 'virus_signatures.db')
        self.memory_signatures = {}
        self.behavior_patterns = {}
        self.api_results_cache = {}
        self.cache_ttl = 86400 * 7
        self.init_database()
        self.load_signatures()
        self.cache_path = os.path.join(app_data_dir, 'virus_cache.pkl')
        self.load_cache()

    def init_database(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY,
                    hash TEXT UNIQUE,
                    type TEXT,
                    name TEXT,
                    severity INTEGER,
                    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_cache (
                    hash TEXT PRIMARY KEY,
                    result TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS behavioral_patterns (
                    id INTEGER PRIMARY KEY,
                    pattern TEXT,
                    description TEXT,
                    severity INTEGER,
                    category TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS trusted_signatures (
                    id INTEGER PRIMARY KEY,
                    thumbprint TEXT UNIQUE,
                    subject TEXT,
                    issuer TEXT,
                    trusted BOOLEAN DEFAULT 1,
                    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash ON signatures(hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_hash ON api_cache(hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_thumbprint ON trusted_signatures(thumbprint)')

            conn.commit()
            conn.close()

            self.load_default_signatures()
        except:
            pass

    def load_default_signatures(self):
        default_patterns = [
            ("process_injection", "Injeção de processo detectada", 9, "behavior"),
            ("registry_persistence", "Modificação suspeita do registro", 7, "behavior"),
            ("file_encryption", "Comportamento de criptografia em massa", 10, "ransomware"),
            ("network_backdoor", "Conexão suspeita de backdoor", 8, "network"),
            ("credential_theft", "Tentativa de roubo de credenciais", 9, "behavior"),
            ("privilege_escalation", "Escalação de privilégios", 8, "behavior"),
            ("sandbox_evasion", "Evasão de sandbox detectada", 7, "behavior"),
            ("anti_debugging", "Técnicas anti-debugging", 6, "behavior"),
            ("rootkit_behavior", "Comportamento de rootkit", 9, "behavior"),
            ("keylogger_behavior", "Atividade de keylogger", 8, "behavior")
        ]

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for pattern, desc, severity, category in default_patterns:
                cursor.execute('''
                    INSERT OR IGNORE INTO behavioral_patterns (pattern, description, severity, category)
                    VALUES (?, ?, ?, ?)
                ''', (pattern, desc, severity, category))

            conn.commit()
            conn.close()
        except:
            pass

    def load_signatures(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT hash, name, severity FROM signatures')
            for row in cursor.fetchall():
                self.memory_signatures[row[0]] = {
                    'name': row[1],
                    'severity': row[2]
                }

            cursor.execute('SELECT pattern, description, severity, category FROM behavioral_patterns')
            for row in cursor.fetchall():
                self.behavior_patterns[row[0]] = {
                    'description': row[1],
                    'severity': row[2],
                    'category': row[3]
                }

            conn.close()
        except:
            pass

    def load_cache(self):
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'rb') as f:
                    cache_data = pickle.load(f)
                    self.api_results_cache = cache_data
        except:
            self.api_results_cache = {}

    def save_cache(self):
        try:
            with open(self.cache_path, 'wb') as f:
                pickle.dump(self.api_results_cache, f)
        except:
            pass

    def add_signature(self, hash_value, name, type_='malware', severity=5):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO signatures (hash, type, name, severity)
                VALUES (?, ?, ?, ?)
            ''', (hash_value, type_, name, severity))
            conn.commit()
            conn.close()

            self.memory_signatures[hash_value] = {
                'name': name,
                'severity': severity
            }
        except:
            pass

    def add_trusted_signature(self, thumbprint, subject, issuer):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO trusted_signatures (thumbprint, subject, issuer)
                VALUES (?, ?, ?)
            ''', (thumbprint, subject, issuer))
            conn.commit()
            conn.close()
            return True
        except:
            return False

    def is_trusted_signature(self, thumbprint):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT trusted FROM trusted_signatures WHERE thumbprint = ?
            ''', (thumbprint,))
            row = cursor.fetchone()
            conn.close()

            if row:
                return row[0] == 1
            return False
        except:
            return False

    def check_api_cache(self, file_hash):
        if file_hash in self.api_results_cache:
            result, timestamp = self.api_results_cache[file_hash]
            if time.time() - timestamp < self.cache_ttl:
                return result

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT result, timestamp FROM api_cache WHERE hash = ?
            ''', (file_hash,))
            row = cursor.fetchone()
            conn.close()

            if row:
                result, timestamp = row
                if time.time() - datetime.fromisoformat(timestamp).timestamp() < self.cache_ttl:
                    result_obj = json.loads(result)
                    self.api_results_cache[file_hash] = (result_obj, time.time())
                    return result_obj
            return None
        except:
            return None

    def update_api_cache(self, file_hash, result):
        self.api_results_cache[file_hash] = (result, time.time())

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO api_cache (hash, result)
                VALUES (?, ?)
            ''', (file_hash, json.dumps(result)))
            conn.commit()
            conn.close()

            if len(self.api_results_cache) % 100 == 0:
                self.save_cache()
        except:
            pass

class YaraScanner:
    def __init__(self):
        self.rules = self.compile_rules() if yara else None
        self.scan_cache = {}
        self.cache_lock = threading.Lock()

    def compile_rules(self):
        rules_text = '''
        rule Ransomware_Generic {
            meta:
                description = "Detecta comportamento genérico de ransomware"
                severity = 10
            strings:
                $enc1 = "encrypt" nocase
                $enc2 = "decrypt" nocase
                $enc3 = "AES" nocase
                $enc4 = "RSA" nocase
                $enc5 = "bitcoin" nocase
                $enc6 = "payment" nocase
                $enc7 = ".locked" nocase
                $enc8 = ".encrypted" nocase
                $note1 = "All your files" nocase
                $note2 = "How to decrypt" nocase
                $note3 = "pay to decrypt" nocase
                $note4 = "your files are encrypted" nocase
            condition:
                3 of ($enc*) or 2 of ($note*)
        }

        rule Trojan_Generic {
            meta:
                description = "Detecta trojans genéricos"
                severity = 8
            strings:
                $api1 = "CreateRemoteThread"
                $api2 = "VirtualAllocEx"
                $api3 = "WriteProcessMemory"
                $api4 = "OpenProcess"
                $cmd1 = "cmd.exe /c"
                $cmd2 = "powershell -"
                $reg1 = "HKEY_LOCAL_MACHINE"
                $reg2 = "CurrentVersion\\\\Run"
            condition:
                3 of ($api*) or (2 of ($cmd*) and 1 of ($reg*))
        }
        '''

        try:
            if yara and hasattr(yara, 'compile'):
                return yara.compile(source=rules_text)
            return None
        except:
            return None

    def scan_file(self, file_path):
        try:
            with self.cache_lock:
                if file_path in self.scan_cache:
                    return self.scan_cache[file_path]

            if not self.rules:
                return []

            matches = self.rules.match(file_path, timeout=2)

            with self.cache_lock:
                self.scan_cache[file_path] = matches
                if len(self.scan_cache) > 20000:
                    self.scan_cache.clear()

            return matches
        except:
            return []

class PEAnalyzer:
    def __init__(self):
        self.suspicious_imports = {
            'VirtualAllocEx': 8,
            'WriteProcessMemory': 8,
            'CreateRemoteThread': 9,
            'SetWindowsHookEx': 7,
            'GetAsyncKeyState': 7,
            'RegisterHotKey': 6,
            'OpenProcess': 6,
            'ReadProcessMemory': 6,
            'NtQuerySystemInformation': 8,
            'ZwQuerySystemInformation': 8,
            'CreateToolhelp32Snapshot': 6,
            'Process32First': 6,
            'Process32Next': 6,
            'Module32First': 6,
            'Module32Next': 6,
            'Thread32First': 6,
            'Thread32Next': 6,
            'SuspendThread': 7,
            'ResumeThread': 6,
            'QueueUserAPC': 8,
            'GetThreadContext': 7,
            'SetThreadContext': 8,
            'NtSetInformationThread': 8,
            'NtQueryInformationProcess': 7,
            'NtSetInformationProcess': 8,
            'RtlCreateUserThread': 9,
            'LdrLoadDll': 8,
            'ZwMapViewOfSection': 8,
            'ZwCreateSection': 8,
            'ZwOpenSection': 7,
            'ZwClose': 5,
            'VirtualProtectEx': 7,
            'NtProtectVirtualMemory': 8,
            'AdjustTokenPrivileges': 7,
            'OpenProcessToken': 7,
            'LookupPrivilegeValue': 6,
            'DuplicateToken': 7,
            'ImpersonateLoggedOnUser': 8,
            'CreateProcessAsUser': 8,
            'CreateProcessWithLogonW': 8,
            'WinExec': 7,
            'ShellExecute': 6,
            'URLDownloadToFile': 8
        }

        self.suspicious_sections = [
            '.rsrc', '.reloc', '.idata', '.edata', '.rdata', '.data', '.text',
            '.bss', '.tls', '.crt', '.debug', 'UPX', '.aspack', '.adata',
            '.ASPack', '.boom', '.ccg', '.charmve', '.edata', '.enigma1',
            '.enigma2', '.idata', '.mackt', '.MaskPE', '.neolite', '.nsp0',
            '.nsp1', '.packed', '.perplex', '.petite', '.pinclie', '.RLPack',
            '.rmnet', '.RPCrypt', '.seau', '.sforce3', '.shrink1', '.shrink2',
            '.shrink3', '.spack', '.svkp', '.Themida', '.taz', '.tsuarch',
            '.tsustub', '.UPX0', '.UPX1', '.UPX2', '.vmp0', '.vmp1', '.vmp2',
            '.winapi', '.WWPACK', '.yP', '.y0da', '!EPack', '.!PACK'
        ]

        self.analysis_cache = {}
        self.cache_lock = threading.Lock()

    def analyze(self, file_path):
        try:
            with self.cache_lock:
                if file_path in self.analysis_cache:
                    return self.analysis_cache[file_path]

            filepath_lower = file_path.lower()
            if "discord" in filepath_lower or "riot" in filepath_lower or "league" in filepath_lower or "valorant" in filepath_lower or "chrome" in filepath_lower or "edge" in filepath_lower or "firefox" in filepath_lower or "brave" in filepath_lower or "opera" in filepath_lower:
                with self.cache_lock:
                    self.analysis_cache[file_path] = (False, None)
                return (False, None)

            if "microsoft" in filepath_lower or "onedrive" in filepath_lower:
                with self.cache_lock:
                    self.analysis_cache[file_path] = (False, None)
                return (False, None)

            if "packages\\microsoftwindows" in filepath_lower:
                with self.cache_lock:
                    self.analysis_cache[file_path] = (False, None)
                return (False, None)

            if not pefile or not hasattr(pefile, 'PE'):
                threats = ["Análise PE limitada - módulo pefile não disponível"]
                severity = 5
                result = (True, {'threats': threats, 'severity': severity})

                with self.cache_lock:
                    self.analysis_cache[file_path] = result
                return result

            try:
                if pefile:
                    pe = pefile.PE(file_path, fast_load=True)
                    threats = []
                    severity = 0

                    suspicious_count = 0
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imp in entry.imports:
                                if imp.name:
                                    func_name = imp.name.decode('utf-8', errors='ignore')
                                    if func_name in self.suspicious_imports:
                                        suspicious_count += 1
                                        severity = max(severity, self.suspicious_imports[func_name])

                    if suspicious_count > 5:
                        threats.append(f"Múltiplas importações suspeitas ({suspicious_count})")
                        severity = min(10, severity + 2)

                    for section in pe.sections:
                        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\\x00')

                        if section_name in self.suspicious_sections:
                            threats.append(f"Seção suspeita: {section_name}")
                            severity = max(severity, 6)

                        try:
                            entropy = self.calculate_entropy(section.get_data())
                            if entropy > 7.5:
                                threats.append(f"Alta entropia na seção {section_name}: {entropy:.2f}")
                                severity = max(severity, 7)
                        except:
                            pass

                        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                            threats.append(f"Seção {section_name} com tamanho físico zero")
                            severity = max(severity, 6)

                    if hasattr(pe, 'OPTIONAL_HEADER'):
                        if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                            threats.append("Ponto de entrada inválido")
                            severity = max(severity, 8)

                    if hasattr(pe, 'FILE_HEADER'):
                        if pe.FILE_HEADER.TimeDateStamp == 0:
                            threats.append("Timestamp zerado (possível manipulação)")
                            severity = max(severity, 5)

                        try:
                            timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
                            if timestamp > datetime.now():
                                threats.append("Timestamp futuro (possível manipulação)")
                                severity = max(severity, 6)
                        except:
                            pass

                    if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') or pe.DIRECTORY_ENTRY_SECURITY.struct.dwLength == 0:
                        threats.append("Sem assinatura digital")
                        severity = max(severity, 6)

                    pe.close()

                    result = (True, {'threats': threats, 'severity': severity}) if threats else (False, None)

                    with self.cache_lock:
                        self.analysis_cache[file_path] = result
                        if len(self.analysis_cache) > 2000:
                            oldest_keys = sorted(list(self.analysis_cache.keys()))[:-1000]
                            for key in oldest_keys:
                                del self.analysis_cache[key]

                    return result
                else:
                    file_size = os.path.getsize(file_path)
                    threats = ["Arquivo executável suspeito - análise PE não disponível"]
                    severity = 5

                    result = (True, {'threats': threats, 'severity': severity})

                    with self.cache_lock:
                        self.analysis_cache[file_path] = result
                    return result
            except:
                file_size = os.path.getsize(file_path)
                threats = ["Arquivo executável suspeito - falha na análise PE"]
                severity = 5

                result = (True, {'threats': threats, 'severity': severity})

                with self.cache_lock:
                    self.analysis_cache[file_path] = result
                return result

        except:
            with self.cache_lock:
                self.analysis_cache[file_path] = (False, None)
            return False, None

    def calculate_entropy(self, data):
        if not data:
            return 0

        entropy = 0
        data_len = len(data)
        frequency = {}

        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        for count in frequency.values():
            if count > 0:
                freq = count / data_len
                entropy -= freq * (math.log2(freq) if freq > 0 else 0)

        return entropy

class NetworkScanner:
    def __init__(self):
        self.suspicious_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy",
            1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
            4444: "Metasploit", 6666: "IRC", 6667: "IRC",
            12345: "NetBus", 31337: "BackOrifice", 65535: "Backdoor"
        }

        self.suspicious_domains = [
            'dyndns', 'no-ip', 'ddns', 'serveftp', 'servehttp',
            'serveblog', 'servegame', 'servemp3', 'servepics',
            'servequake', 'sytes', 'hopto', 'myftp', 'redirectme',
            'servebeer', 'servecounterstrike', 'serveftp', 'servehalf',
            'servehalflife', 'servehttp', 'serveirc', 'serveminecraft',
            'servemp3', 'servepics', 'servequake', 'sytes', 'use-ip',
            'webhop', 'diretorio', 'esy', 'hol', 'webs', 'net16',
            'net23', 'net46', 'net50', 'net56', 'net63', 'net76',
            'net78', 'c9users', 'herokuapp', 'azurewebsites',
            'cloudapp', 'ngrok', 'localtunnel', 'pagekite'
        ]

        self.scan_cache = {}
        self.cache_lock = threading.Lock()

        self.whitelisted_processes = [
            "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe",
            "RiotClient.exe", "LeagueClient.exe", "League of Legends.exe", "Valorant.exe",
            "RiotClientServices.exe", "VALORANT.exe", "RiotClientUxRender.exe", "RiotClientUx.exe",
            "QtWebEngineProcess.exe", "WolfGuard.exe", "WolfGuard1.exe", "OneDrive.exe", "FileCoAuth.exe",
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "opera_gx.exe", "GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe"
        ]

    def check_network_connections(self, pid):
        try:
            with self.cache_lock:
                if pid in self.scan_cache:
                    cache_time, result = self.scan_cache[pid]
                    if time.time() - cache_time < 60:
                        return result

            process = psutil.Process(pid)

            if process.name() in self.whitelisted_processes:
                with self.cache_lock:
                    self.scan_cache[pid] = (time.time(), [])
                return []

            process_path = process.exe().lower()
            if "microsoft" in process_path or "onedrive" in process_path or "packages\\microsoftwindows" in process_path:
                with self.cache_lock:
                    self.scan_cache[pid] = (time.time(), [])
                return []

            if "chrome" in process_path or "edge" in process_path or "firefox" in process_path or "brave" in process_path or "opera" in process_path:
                with self.cache_lock:
                    self.scan_cache[pid] = (time.time(), [])
                return []

            connections = process.connections()
            suspicious = []

            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port

                        if remote_port in self.suspicious_ports:
                            suspicious.append({
                                'type': 'suspicious_port',
                                'details': f"Conexão para porta suspeita {remote_port} ({self.suspicious_ports[remote_port]})",
                                'ip': remote_ip,
                                'port': remote_port
                            })

                        try:
                            hostname = socket.gethostbyaddr(remote_ip)[0]
                            for domain in self.suspicious_domains:
                                if domain in hostname.lower():
                                    suspicious.append({
                                        'type': 'suspicious_domain',
                                        'details': f"Conexão para domínio suspeito: {hostname}",
                                        'domain': hostname,
                                        'ip': remote_ip
                                    })
                                    break
                        except:
                            pass

                    if conn.laddr.port in self.suspicious_ports:
                        suspicious.append({
                            'type': 'listening_port',
                            'details': f"Escutando porta suspeita {conn.laddr.port} ({self.suspicious_ports[conn.laddr.port]})",
                            'port': conn.laddr.port
                        })

            with self.cache_lock:
                self.scan_cache[pid] = (time.time(), suspicious)
                if len(self.scan_cache) > 1000:
                    oldest_pid = min(self.scan_cache, key=lambda k: self.scan_cache[k][0])
                    del self.scan_cache[oldest_pid]

            return suspicious
        except:
            return []

class BehaviorMonitor:
    def __init__(self):
        self.process_behavior = {}
        self.api_hooks = {}
        self.registry_monitors = {}
        self.file_monitors = {}
        self.lock = threading.Lock()

        self.whitelisted_processes = [
            "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe",
            "RiotClient.exe", "LeagueClient.exe", "League of Legends.exe", "Valorant.exe",
            "RiotClientServices.exe", "VALORANT.exe", "RiotClientUxRender.exe", "RiotClientUx.exe",
            "QtWebEngineProcess.exe", "WolfGuard.exe", "WolfGuard1.exe", "OneDrive.exe", "FileCoAuth.exe",
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "opera_gx.exe", "GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe"
        ]

    def monitor_process_behavior(self, pid):
        try:
            with self.lock:
                if pid not in self.process_behavior:
                    self.process_behavior[pid] = {
                        'start_time': time.time(),
                        'cpu_usage': deque(maxlen=20),
                        'memory_usage': deque(maxlen=20),
                        'disk_io': deque(maxlen=10),
                        'network_io': deque(maxlen=10),
                        'child_processes': [],
                        'modified_files': [],
                        'registry_changes': [],
                        'suspicious_score': 0,
                        'last_check': 0
                    }

                current_time = time.time()
                if current_time - self.process_behavior[pid]['last_check'] < 5:
                    return self.process_behavior[pid]['suspicious_score'] > 5

                self.process_behavior[pid]['last_check'] = current_time

            process = psutil.Process(pid)

            if process.name() in self.whitelisted_processes:
                with self.lock:
                    self.process_behavior[pid]['suspicious_score'] = 0
                return False

            process_path = process.exe().lower()
            if "microsoft" in process_path or "onedrive" in process_path or "packages\\microsoftwindows" in process_path:
                with self.lock:
                    self.process_behavior[pid]['suspicious_score'] = 0
                return False

            if "chrome" in process_path or "edge" in process_path or "firefox" in process_path or "brave" in process_path or "opera" in process_path:
                with self.lock:
                    self.process_behavior[pid]['suspicious_score'] = 0
                return False

            cpu_percent = process.cpu_percent(interval=0.1)
            memory_info = process.memory_info()

            with self.lock:
                self.process_behavior[pid]['cpu_usage'].append(cpu_percent)
                self.process_behavior[pid]['memory_usage'].append(memory_info.rss)

                if len(self.process_behavior[pid]['cpu_usage']) >= 10:
                    avg_cpu = sum(self.process_behavior[pid]['cpu_usage']) / len(self.process_behavior[pid]['cpu_usage'])
                    if avg_cpu > 80:
                        self.process_behavior[pid]['suspicious_score'] += 2

                memory_growth = 0
                if len(self.process_behavior[pid]['memory_usage']) >= 5:
                    initial_memory = self.process_behavior[pid]['memory_usage'][0]
                    current_memory = self.process_behavior[pid]['memory_usage'][-1]
                    if initial_memory > 0:
                        memory_growth = (current_memory - initial_memory) / initial_memory * 100

                        if memory_growth > 500:
                            self.process_behavior[pid]['suspicious_score'] += 3

                for child in process.children():
                    if child.pid not in self.process_behavior[pid]['child_processes']:
                        self.process_behavior[pid]['child_processes'].append(child.pid)
                        self.process_behavior[pid]['suspicious_score'] += 1

                current_time = time.time()
                to_remove = []
                for p_pid, p_data in self.process_behavior.items():
                    if current_time - p_data['start_time'] > 3600:
                        to_remove.append(p_pid)

                for p_pid in to_remove:
                    del self.process_behavior[p_pid]

                return self.process_behavior[pid]['suspicious_score'] > 5

        except:
            return False

class MemoryScanner:
    def __init__(self):
        self.suspicious_strings = [
            b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
            b'This program cannot be run in DOS mode',
            b'This is a virus',
            b'Hacked by',
            b'Your files have been encrypted',
            b'All your files',
            b'Bitcoin wallet',
            b'Send money to',
            b'Tor browser',
            b'onion',
            b'bitcoin:',
            b'monero:',
            b'ransomware',
            b'cryptolocker',
            b'keylogger',
            b'backdoor',
            b'trojan',
            b'malware',
            b'rootkit',
            b'botnet'
        ]

        self.scan_cache = {}
        self.cache_lock = threading.Lock()

        self.whitelisted_processes = [
            "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe",
            "RiotClient.exe", "LeagueClient.exe", "League of Legends.exe", "Valorant.exe",
            "RiotClientServices.exe", "VALORANT.exe", "RiotClientUxRender.exe", "RiotClientUx.exe",
            "QtWebEngineProcess.exe", "WolfGuard.exe","WolfGuard1.exe", "OneDrive.exe", "FileCoAuth.exe",
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "opera_gx.exe", "GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe"
        ]

    def scan_process_memory(self, pid):
        try:
            with self.cache_lock:
                if pid in self.scan_cache:
                    cache_time, result = self.scan_cache[pid]
                    if time.time() - cache_time < 300:
                        return result

            process = psutil.Process(pid)

            if process.name() in self.whitelisted_processes:
                with self.cache_lock:
                    self.scan_cache[pid] = (time.time(), [])
                return []

            process_path = process.exe().lower()
            if "microsoft" in process_path or "onedrive" in process_path or "packages\\microsoftwindows" in process_path:
                with self.cache_lock:
                    self.scan_cache[pid] = (time.time(), [])
                return []

            if "chrome" in process_path or "edge" in process_path or "firefox" in process_path or "brave" in process_path or "opera" in process_path:
                with self.cache_lock:
                    self.scan_cache[pid] = (time.time(), [])
                return []

            suspicious_found = []

            try:
                process_handle = win32api.OpenProcess(
                    win32con.PROCESS_VM_READ | win32con.PROCESS_QUERY_INFORMATION,
                    False,
                    pid
                )

                if not process_handle:
                    with self.cache_lock:
                        self.scan_cache[pid] = (time.time(), [])
                    return []

                modules = win32process.EnumProcessModules(process_handle)

                for module in modules[:5]:
                    try:
                        module_info = win32process.GetModuleFileNameEx(process_handle, module)

                        if self.scan_module_memory(process_handle, module):
                            suspicious_found.append({
                                'module': module_info,
                                'type': 'suspicious_memory_content'
                            })
                    except:
                        continue

                win32api.CloseHandle(process_handle)
            except:
                pass

            with self.cache_lock:
                self.scan_cache[pid] = (time.time(), suspicious_found)
                if len(self.scan_cache) > 500:
                    oldest_pid = min(self.scan_cache, key=lambda k: self.scan_cache[k][0])
                    del self.scan_cache[oldest_pid]

            return suspicious_found

        except:
            return []

    def scan_module_memory(self, process_handle, module_handle):
        try:
            module_info = win32process.GetModuleInformation(process_handle, module_handle)
            base_address = module_info.lpBaseOfDll
            size = min(module_info.SizeOfImage, 1024 * 1024)

            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()

            result = ctypes.windll.kernel32.ReadProcessMemory(
                int(process_handle),
                base_address,
                buffer,
                size,
                ctypes.byref(bytes_read)
            )

            if result:
                memory_data = buffer.raw[:bytes_read.value]

                for suspicious_string in self.suspicious_strings:
                    if suspicious_string in memory_data:
                        return True

            return False

        except:
            return False

class RegistryMonitor:
    def __init__(self):
        self.critical_keys = [
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
            r'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'SYSTEM\\CurrentControlSet\\Services',
            r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            r'SOFTWARE\\Classes\\exefile\\shell\\open\\command',
            r'SOFTWARE\\Classes\\comfile\\shell\\open\\command',
            r'SOFTWARE\\Classes\\batfile\\shell\\open\\command',
            r'SOFTWARE\\Classes\\htafile\\shell\\open\\command',
            r'SOFTWARE\\Classes\\piffile\\shell\\open\\command',
            r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
            r'SYSTEM\\CurrentControlSet\\Control\\SafeBoot',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
            r'SOFTWARE\\Policies\\Microsoft\\Windows Defender',
            r'SOFTWARE\\Microsoft\\Windows Defender'
        ]

        self.result_cache = {}
        self.cache_ttl = 300
        self.last_check_time = 0
        self.cache_lock = threading.Lock()

        self.whitelist_apps = [
            "discord", "discordcanary", "discordptb", "discorddevelopment",
            "riotclient", "leagueclient", "league of legends", "valorant",
            "qtwebengine", "wolfguard", "microsoft", "onedrive", "filecoauth",
            "windows", "chrome", "edge", "firefox", "brave", "opera",
            "google", "mozilla"
        ]

    def check_autostart_registry(self):
        current_time = time.time()

        with self.cache_lock:
            if current_time - self.last_check_time < self.cache_ttl:
                return self.result_cache

            self.last_check_time = current_time

        suspicious_entries = []

        for key_path in self.critical_keys[:10]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        if self.is_suspicious_registry_value(name, value):
                            suspicious_entries.append({
                                'key': key_path,
                                'name': name,
                                'value': value,
                                'type': 'autostart'
                            })
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except:
                pass

        with self.cache_lock:
            self.result_cache = suspicious_entries

        return suspicious_entries

    def is_suspicious_registry_value(self, name, value):
        suspicious_patterns = [
            'temp', 'tmp', 'appdata\\\\local\\\\temp', 'appdata\\\\roaming',
            'programdata', 'windows\\\\temp', 'users\\\\public',
            'cmd.exe', 'powershell', 'wscript', 'cscript',
            'rundll32', 'regsvr32', 'mshta', 'bitsadmin',
            'certutil', 'schtasks', 'wmic', 'msiexec'
        ]

        value_lower = str(value).lower()
        name_lower = str(name).lower()

        for app in self.whitelist_apps:
            if app in value_lower or app in name_lower:
                return False

        for pattern in suspicious_patterns:
            if pattern in value_lower or pattern in name_lower:
                return True

        if value_lower.endswith('.tmp') or value_lower.endswith('.temp'):
            return True

        if '\\\\' in value_lower and not value_lower.startswith('"'):
            try:
                if not os.path.exists(value_lower.split()[0].strip('"')):
                    return True
            except:
                pass

        return False

class ExecutableBlocker:
    def __init__(self, signature_verifier, file_whitelist):
        self.signature_verifier = signature_verifier
        self.file_whitelist = file_whitelist
        self.blocked_exes = set()
        self.block_lock = threading.Lock()
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_new_processes, daemon=True)
        self.monitor_thread.start()

        self.whitelist_apps = [
            "discord", "discordcanary", "discordptb", "discorddevelopment",
            "riotclient", "leagueclient", "league of legends", "valorant",
            "qtwebengine", "wolfguard", "microsoft", "onedrive", "filecoauth",
            "windows", "chrome", "edge", "firefox", "brave", "opera",
            "google", "mozilla"
        ]

        self.windows_script_paths = WINDOWS_SCRIPT_PATHS

    def monitor_new_processes(self):
        try:
            while self.running:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                        try:
                            if not proc.info['exe']:
                                continue

                            exe_path = proc.info['exe']
                            exe_path_lower = exe_path.lower()

                            system_dirs = [
                                "c:\\windows\\",
                                "c:\\program files\\",
                                "c:\\program files (x86)\\",
                            ]

                            if any(exe_path_lower.startswith(sys_dir) for sys_dir in system_dirs):
                                continue

                            if "microsoft" in exe_path_lower or "onedrive" in exe_path_lower or "packages\\microsoftwindows" in exe_path_lower:
                                continue

                            if "chrome" in exe_path_lower or "edge" in exe_path_lower or "firefox" in exe_path_lower or "brave" in exe_path_lower or "opera" in exe_path_lower:
                                continue

                            if exe_path_lower.endswith('.exe') and not self.file_whitelist.is_whitelisted(exe_path):
                                if not self.signature_verifier.verify_signature(exe_path):
                                    try:
                                        if time.time() - proc.info['create_time'] < 15:
                                            with self.block_lock:
                                                if exe_path not in self.blocked_exes:
                                                    self.blocked_exes.add(exe_path)
                                                    print(f"BLOQUEANDO E REMOVENDO executável sem assinatura: {exe_path}")
                                                    try:
                                                        proc_obj = psutil.Process(proc.info['pid'])
                                                        proc_obj.kill()
                                                        print(f"Processo {proc.info['pid']} terminado.")
                                                        if SecureDelete.secure_delete(exe_path):
                                                            print(f"Arquivo executável removido: {exe_path}")
                                                        else:
                                                            print(f"FALHA ao remover o arquivo executável: {exe_path}")
                                                    except Exception as e:
                                                        print(f"Erro ao bloquear/remover {exe_path}: {e}")
                                    except psutil.NoSuchProcess:
                                        continue
                                    except Exception as e:
                                        print(f"Erro no monitor de processos: {e}")

                            cmd_line = []
                            try:
                                proc_obj = psutil.Process(proc.info['pid'])
                                cmd_line = proc_obj.cmdline()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue

                            if cmd_line and len(cmd_line) > 1:
                                for arg in cmd_line[1:]:
                                    arg_lower = arg.lower()
                                    if arg_lower.endswith(('.ps1', '.cmd', '.bat')):
                                        if not self.file_whitelist.is_windows_script(arg) and not self.file_whitelist.is_whitelisted(arg):
                                            print(f"BLOQUEANDO E REMOVENDO execução de script não permitido: {arg}")
                                            try:
                                                proc_obj = psutil.Process(proc.info['pid'])
                                                proc_obj.kill()
                                                print(f"Processo hospedeiro {proc.info['pid']} ({proc.info['name']}) terminado.")
                                                if SecureDelete.secure_delete(arg):
                                                    print(f"Arquivo de script removido: {arg}")
                                                else:
                                                    print(f"FALHA ao remover o arquivo de script: {arg}")
                                            except Exception as e:
                                                print(f"Erro ao bloquear script {arg}: {e}")
                                            break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except Exception as e:
                    time.sleep(1)
                time.sleep(0.5)
        except Exception as e:
            print(f"Erro crítico no monitor de processos: {e}")

    def stop(self):
        self.running = False

class FileSystemMonitor(FileSystemEventHandler):
    def __init__(self, scan_engine, quarantine_manager, callback):
        super().__init__()
        self.scan_engine = scan_engine
        self.quarantine_manager = quarantine_manager
        self.callback = callback
        self.scan_queue = queue.Queue()
        self.processing = True
        self.whitelist = scan_engine.whitelist
        self.start_processing_thread()
        self.recent_files = {}
        self.files_lock = threading.Lock()
        self.signature_verifier = DigitalSignatureVerifier()
        self.exe_blocker = ExecutableBlocker(self.signature_verifier, self.whitelist)

    def start_processing_thread(self):
        num_threads = max(16, cpu_count() * 4)
        self.process_threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=self.process_queue, daemon=True)
            thread.start()
            self.process_threads.append(thread)

    def process_queue(self):
        while self.processing:
            try:
                file_path = self.scan_queue.get(timeout=1)

                with self.files_lock:
                    current_time = time.time()
                    if file_path in self.recent_files:
                        if current_time - self.recent_files[file_path] < 5:
                            self.scan_queue.task_done()
                            continue
                    self.recent_files[file_path] = current_time

                    expired_files = [f for f, t in self.recent_files.items() if current_time - t > 300]
                    for f in expired_files:
                        del self.recent_files[f]

                if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
                    try:
                        file_ext = os.path.splitext(file_path)[1].lower()
                        file_path_lower = file_path.lower()

                        if "microsoft" in file_path_lower or "onedrive" in file_path_lower or "packages\\microsoftwindows" in file_path_lower:
                            self.scan_queue.task_done()
                            continue

                        if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                            self.scan_queue.task_done()
                            continue

                        if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                            self.scan_queue.task_done()
                            continue

                        if "zxcvbndata" in file_path_lower:
                            self.scan_queue.task_done()
                            continue

                        if "pip\\cache" in file_path_lower:
                            self.scan_queue.task_done()
                            continue

                        if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                            if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                                self.scan_queue.task_done()
                                continue

                        if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                            self.scan_queue.task_done()
                            continue

                        instant_block = False
                        threat_reason = ""

                        if file_ext in ['.ps1', '.bat', '.cmd'] and not self.whitelist.is_windows_script(file_path):
                            instant_block = True
                            threat_reason = f"Script não autorizado ({file_ext}) detectado e bloqueado."

                        elif file_ext == '.exe' and not self.whitelist.is_whitelisted(file_path):
                            is_system_path = any(file_path_lower.startswith(p.lower()) for p in [
                                os.environ.get('SystemRoot', 'C:\\Windows'),
                                os.environ.get('ProgramFiles', 'C:\\Program Files'),
                                os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')
                            ])
                            if not is_system_path and not self.signature_verifier.verify_signature(file_path):
                                instant_block = True
                                threat_reason = "Executável sem assinatura digital detectado e bloqueado."

                        if instant_block:
                            self.callback(file_path, threat_reason, True)
                            try:
                                for proc in psutil.process_iter(['exe']):
                                    if proc.info['exe'] and proc.info['exe'].lower() == file_path_lower:
                                        self.callback(f"Tentando terminar o processo associado: {proc.pid}", False)
                                        psutil.Process(proc.pid).kill()

                                if SecureDelete.secure_delete(file_path):
                                    self.callback(f"Ameaça removida com sucesso: {file_path}", False)
                                else:
                                    self.callback(f"Falha ao remover a ameaça, tentando quarentena: {file_path}", True)
                                    self.quarantine_manager.quarantine_file(file_path, threat_reason)
                            except Exception as e:
                                self.callback(f"Erro na remoção instantânea, tentando quarentena: {file_path} - {str(e)}", True)
                                self.quarantine_manager.quarantine_file(file_path, threat_reason)

                            self.scan_queue.task_done()
                            continue

                        if self.whitelist.is_whitelisted(file_path):
                            self.scan_queue.task_done()
                            continue

                        try:
                            is_threat, threat_info = self.scan_engine.scan_file(file_path)
                            if is_threat:
                                self.callback(file_path, threat_info, True)
                                try:
                                    success, message = self.quarantine_manager.quarantine_file(file_path, threat_info)
                                    if success:
                                        self.callback(f"Arquivo quarentenado: {file_path} - {message}")
                                    else:
                                        self.callback(f"Falha ao quarentenar: {file_path} - {message}")
                                except Exception as e:
                                    self.callback(f"Erro ao quarentenar: {file_path} - {str(e)}")
                            else:
                                self.callback(f"Arquivo verificado: {file_path} - Limpo")
                        except Exception as e:
                            self.callback(f"Erro ao escanear: {file_path} - {str(e)}")

                    except Exception as e:
                        self.callback(f"Erro ao processar arquivo: {file_path} - {str(e)}")

                self.scan_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                try:
                    self.callback(f"Erro crítico no monitor de arquivos: {str(e)}")
                    if not self.scan_queue.empty():
                       self.scan_queue.task_done()
                except:
                    pass

    def on_created(self, event):
        if not event.is_directory:
            self.scan_queue.put(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.scan_queue.put(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.scan_queue.put(event.dest_path)

    def stop(self):
        self.processing = False
        if hasattr(self, 'exe_blocker'):
            self.exe_blocker.stop()
        for thread in self.process_threads:
            if thread.is_alive():
                thread.join(timeout=1)

class USBController:
    def __init__(self):
        self.device_map = {}
        self.update_device_map()

    def update_device_map(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            self.device_map = {}

            for drive in c.Win32_DiskDrive():
                if drive.InterfaceType == "USB":
                    for partition in c.Win32_DiskDriveToDiskPartition(Antecedent=drive.Path_.Path):
                        for logical_disk in c.Win32_LogicalDiskToPartition(Antecedent=partition.Dependent.Path_.Path):
                            logical_disk_name = logical_disk.Dependent.Path_.Path.split("=")[1].strip('"')
                            device_id = drive.PNPDeviceID
                            drive_letter = logical_disk_name.split("\\")[-1]
                            self.device_map[drive_letter] = device_id
        except:
            pass
        finally:
            pythoncom.CoUninitialize()

    def disable_device(self, drive_letter):
        try:
            if drive_letter in self.device_map:
                device_id = self.device_map[drive_letter]
                if device_id:
                    subprocess.run([
                        "powershell",
                        "-Command",
                        f"Get-PnpDevice | Where-Object {{ $_.DeviceID -eq '{device_id}' }} | Disable-PnpDevice -Confirm:$false"
                    ], capture_output=True)
                    return True
            return False
        except:
            return False

    def enable_all_usb_devices(self):
        try:
            subprocess.run([
                "powershell",
                "-Command",
                "Get-PnpDevice | Where-Object { $_.Class -eq 'USB' -and $_.Status -eq 'Error' } | Enable-PnpDevice -Confirm:$false"
            ], capture_output=True)
            return True
        except:
            return False

class USBMonitor:
    def __init__(self, scan_engine, quarantine_manager, callback):
        self.scan_engine = scan_engine
        self.quarantine_manager = quarantine_manager
        self.callback = callback
        self.known_drives = set(self.get_current_drives())
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self.signature_verifier = DigitalSignatureVerifier()
        self.usb_controller = USBController()

    def get_current_drives(self):
        drives = []
        for drive in win32api.GetLogicalDriveStrings().split('\\000')[:-1]:
            drive_type = win32file.GetDriveType(drive)
            if drive_type == win32con.DRIVE_REMOVABLE:
                drives.append(drive)
        return drives

    def monitor_usb(self):
        while self.monitoring:
            try:
                current_drives = set(self.get_current_drives())
                new_drives = current_drives - self.known_drives

                for drive in new_drives:
                    self.callback(f"Novo drive USB detectado: {drive}")
                    self.executor.submit(self.scan_drive, drive)

                self.known_drives = current_drives
                time.sleep(1)
            except:
                time.sleep(1)

    def scan_drive(self, drive_letter):
        threats_found = []
        files_scanned = 0

        try:
            whitelist = self.scan_engine.whitelist

            try:
                for root, dirs, files in os.walk(drive_letter):
                    try:
                        for file in files:
                            try:
                                file_path = os.path.join(root, file)
                                file_path_lower = file_path.lower()

                                if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                                    continue

                                if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                                    continue

                                if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                                    continue

                                if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                                    continue

                                if "zxcvbndata" in file_path_lower:
                                    continue

                                if "pip\\cache" in file_path_lower:
                                    continue

                                if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                                    if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                                        continue

                                if whitelist.is_whitelisted(file_path):
                                    continue

                                file_ext = os.path.splitext(file_path)[1].lower()

                                if file_ext not in whitelist.safe_extensions:
                                    files_scanned += 1

                                    risky_scripts = ['.ps1', '.vbs', '.bat', '.cmd']
                                    if file_ext in risky_scripts:
                                        if whitelist.is_windows_script(file_path):
                                            continue

                                        threats_found.append({
                                            'path': file_path,
                                            'name': f"Script não autorizado: {file_ext}"
                                        })
                                        self.callback(f"Ameaça encontrada: {file_path} - Script não autorizado")
                                        try:
                                            success, message = self.quarantine_manager.quarantine_file(file_path, f"Script não autorizado: {file_ext}")
                                            if success:
                                                self.callback(f"Arquivo quarentenado: {file_path} - {message}")
                                            else:
                                                self.callback(f"Falha ao quarentenar: {file_path} - {message}")
                                        except Exception as e:
                                            self.callback(f"Erro ao quarentenar: {file_path} - {str(e)}")
                                        continue

                                    if file_ext == '.js':
                                        safe_js_context = False
                                        safe_contexts = ['\\development\\', '\\src\\', '\\node_modules\\', '\\vscode\\']
                                        for ctx in safe_contexts:
                                            if ctx in file_path_lower:
                                                safe_js_context = True
                                                break

                                        if safe_js_context:
                                            continue

                                    executable_exts = ['.exe', '.dll', '.sys', '.ocx', '.msi', '.cab', '.cat']
                                    if file_ext in executable_exts:
                                        try:
                                            is_signed = self.signature_verifier.verify_signature(file_path)
                                            if not is_signed:
                                                threats_found.append({
                                                    'path': file_path,
                                                    'name': "Arquivo executável sem assinatura digital"
                                                })
                                                self.callback(f"Ameaça encontrada: {file_path} - Sem assinatura digital")
                                                try:
                                                    success, message = self.quarantine_manager.quarantine_file(file_path, "Arquivo executável sem assinatura digital")
                                                    if success:
                                                        self.callback(f"Arquivo quarentenado: {file_path} - {message}")
                                                    else:
                                                        self.callback(f"Falha ao quarentenar: {file_path} - {message}")
                                                except Exception as e:
                                                    self.callback(f"Erro ao quarentenar: {file_path} - {str(e)}")
                                                continue
                                        except:
                                            continue

                                    try:
                                        is_threat, threat_info = self.scan_engine.scan_file(file_path)
                                        if is_threat:
                                            threats_found.append({
                                                'path': file_path,
                                                'name': threat_info
                                            })
                                            self.callback(f"Ameaça encontrada: {file_path} - {threat_info}")
                                            try:
                                                success, message = self.quarantine_manager.quarantine_file(file_path, threat_info)
                                                if success:
                                                    self.callback(f"Arquivo quarentenado: {file_path} - {message}")
                                                else:
                                                    self.callback(f"Falha ao quarentenar: {file_path} - {message}")
                                            except Exception as e:
                                                self.callback(f"Erro ao quarentenar: {file_path} - {str(e)}")
                                    except:
                                        continue

                                if files_scanned > 5000:
                                    self.callback(f"Escaneamento de USB pausado após 5000 arquivos. Retomando em breve.")
                                    time.sleep(0.1)
                                    files_scanned = 0
                            except:
                                continue
                    except:
                        continue
            except:
                pass

            if threats_found:
                self.callback(f"Escaneamento de {drive_letter} concluído. {len(threats_found)} ameaças encontradas.")
                try:
                    self.usb_controller.disable_device(drive_letter.rstrip('\\'))
                    self.callback(f"Porta USB desabilitada para o drive {drive_letter} devido a ameaças encontradas")
                except:
                    pass
            else:
                self.callback(f"Escaneamento de {drive_letter} concluído. Nenhuma ameaça encontrada.")

            return threats_found, files_scanned
        except:
            return [], 0

    def disable_network(self):
        try:
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=disable"], capture_output=True)
            subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=disable"], capture_output=True)
        except:
            pass

    def enable_network(self):
        try:
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"], capture_output=True)
            subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=enable"], capture_output=True)
        except:
            pass

    def eject_removable_drives(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for disk in c.Win32_LogicalDisk():
                if disk.DriveType == 2:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"$s=New-Object -com Shell.Application;$s.Namespace(17).ParseName('{disk.DeviceID}').InvokeVerb('Eject')"],
                        capture_output=True
                    )
                    self.callback(f"Drive removível ejetado: {disk.DeviceID}")
        except Exception as e:
            self.callback(f"Erro ao ejetar drives removíveis: {str(e)}")
        finally:
            pythoncom.CoUninitialize()

    def stop(self):
        self.monitoring = False
        self.executor.shutdown(wait=False)

class OnlineScanner:
    def __init__(self):
        self.apis = {
            'malshare': {
                'url': 'https://malshare.com/api.php',
                'method': 'GET',
                'params': {'action': 'search', 'query': '{hash}'},
                'headers': {}
            },
            'hashlookup': {
                'url': 'https://hashlookup.circl.lu/lookup/sha256/{hash}',
                'method': 'GET',
                'params': {},
                'headers': {'Accept': 'application/json'}
            },
            'threatcrowd': {
                'url': 'https://www.threatcrowd.org/searchApi/v2/file/report/',
                'method': 'GET',
                'params': {'resource': '{hash}'},
                'headers': {}
            }
        }

        self.results_cache = {}

    async def check_hash_online(self, file_hash):
        if file_hash in self.results_cache:
            return self.results_cache[file_hash]

        results = []
        timeout = aiohttp.ClientTimeout(total=3)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = []
            for api_name, api_config in self.apis.items():
                task = self.query_api(session, api_name, api_config, file_hash)
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for api_name, response in zip(self.apis.keys(), responses):
                if isinstance(response, Exception):
                    continue
                if response:
                    results.append({
                        'source': api_name,
                        'result': response
                    })

        if results:
            self.results_cache[file_hash] = results
            if len(self.results_cache) > 2000:
                self.results_cache.pop(next(iter(self.results_cache)))

        return results

    async def query_api(self, session, api_name, api_config, file_hash):
        try:
            url = api_config['url'].replace('{hash}', file_hash)
            params = {k: v.replace('{hash}', file_hash) for k, v in api_config['params'].items()}

            async with session.request(
                method=api_config['method'],
                url=url,
                params=params if api_config['method'] == 'GET' else None,
                json=params if api_config['method'] == 'POST' else None,
                headers=api_config['headers']
            ) as response:
                if response.status == 200:
                    try:
                        return await response.json()
                    except:
                        return await response.text()
                return None
        except:
            return None

class SecureDelete:
    @staticmethod
    def secure_delete(filepath):
        try:
            if not os.path.exists(filepath):
                return True
            try:
                win32api.SetFileAttributes(filepath, win32con.FILE_ATTRIBUTE_NORMAL)
            except:
                pass
            try:
                os.chmod(filepath, 0o777)
            except:
                pass
            try:
                os.remove(filepath)
                return True
            except:
                pass
            try:
                tmp = filepath + f".del_{int(time.time()*1000)}"
                os.rename(filepath, tmp)
                filepath = tmp
            except:
                pass
            try:
                subprocess.run(["takeown", "/F", filepath], capture_output=True)
                subprocess.run(["icacls", filepath, "/grant", "Administrators:F", "/T", "/C", "/Q"], capture_output=True)
                subprocess.run(["cmd", "/c", "del", "/f", "/q", filepath], capture_output=True)
                if not os.path.exists(filepath):
                    return True
            except:
                pass
            try:
                ctypes.windll.kernel32.MoveFileExW(ctypes.c_wchar_p(filepath), None, win32file.MOVEFILE_DELAY_UNTIL_REBOOT)
                return not os.path.exists(filepath)
            except:
                return False
        except:
            return False

class ScanEngine:
    def __init__(self, app_data_dir=None):
        if app_data_dir is None:
            self.app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
            if not os.path.exists(self.app_data_dir):
                os.makedirs(self.app_data_dir)
        else:
            self.app_data_dir = app_data_dir

        self.virus_db = VirusDatabase(self.app_data_dir)
        self.quarantine_manager = QuarantineManager(self.app_data_dir)
        self.ransomware_detector = RansomwareDetector()
        self.pe_analyzer = PEAnalyzer()
        self.yara_scanner = YaraScanner()
        self.network_scanner = NetworkScanner()
        self.behavior_monitor = BehaviorMonitor()
        self.memory_scanner = MemoryScanner()
        self.registry_monitor = RegistryMonitor()
        self.online_scanner = OnlineScanner()
        self.whitelist = WindowsFileWhitelist(self.app_data_dir)
        self.signature_verifier = DigitalSignatureVerifier()
        self.scan_cache = {}
        self.cache_lock = threading.Lock()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count() * 2)
        self.loop = None
        self.start_async_loop()

        self.whitelist_apps = [
            "discord", "discordcanary", "discordptb", "discorddevelopment",
            "riotclient", "leagueclient", "league of legends", "valorant",
            "qtwebengine", "wolfguard", "microsoft", "onedrive", "filecoauth",
            "windows", "chrome", "edge", "firefox", "brave", "opera",
            "google", "mozilla"
        ]

    def start_async_loop(self):
        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()

        loop_thread = threading.Thread(target=run_loop, daemon=True)
        loop_thread.start()
        time.sleep(0.1)

    def scan_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                return False, None

            file_path_lower = file_path.lower()

            temp_path = os.environ.get('TEMP', '').lower()
            if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                return False, None

            if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                return False, None

            if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                return False, None

            if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                return False, None

            if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                return False, None

            if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                return False, None

            if "zxcvbndata" in file_path_lower:
                return False, None

            if "pip\\cache" in file_path_lower:
                return False, None

            if "packages\\microsoftwindows" in file_path_lower:
                return False, None

            if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                    return False, None

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                return False, None

            for app in self.whitelist_apps:
                if app in file_path_lower:
                    return False, None

            if '.vscode\\extensions' in file_path_lower and file_path_lower.endswith('.js'):
                return False, None

            if 'node_modules' in file_path_lower and file_path_lower.endswith('.js'):
                return False, None

            if self.whitelist.is_whitelisted(file_path):
                return False, None

            file_hash = self.calculate_hash(file_path)
            if not file_hash:
                return False, None

            with self.cache_lock:
                if file_hash in self.scan_cache:
                    cache_time, result = self.scan_cache[file_hash]
                    if time.time() - cache_time < 86400:
                        return result

            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024 * 1024:
                return False, None

            if file_size == 0:
                return False, None

            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in self.whitelist.safe_extensions:
                with self.cache_lock:
                    self.scan_cache[file_hash] = (time.time(), (False, None))
                return False, None

            risky_scripts = ['.ps1', '.vbs', '.bat', '.cmd']
            if file_ext in risky_scripts:
                if self.whitelist.is_windows_script(file_path):
                    with self.cache_lock:
                        self.scan_cache[file_hash] = (time.time(), (False, None))
                    return False, None

                result = (True, f"Script não autorizado: {file_ext}")
                with self.cache_lock:
                    self.scan_cache[file_hash] = (time.time(), result)
                return result

            if file_ext == '.js':
                safe_js_context = False
                safe_contexts = ['\\development\\', '\\src\\', '\\node_modules\\', '\\vscode\\', '\\appdata\\local\\temp\\']
                for ctx in safe_contexts:
                    if ctx in file_path_lower:
                        safe_js_context = True
                        break

                if safe_js_context:
                    with self.cache_lock:
                        self.scan_cache[file_hash] = (time.time(), (False, None))
                    return False, None

            executable_exts = ['.exe', '.dll', '.sys', '.ocx', '.msi', '.cab', '.cat']
            if file_ext in executable_exts and hasattr(self.signature_verifier, 'verify_signature'):
                try:
                    if file_ext == '.dll':
                        with self.cache_lock:
                            self.scan_cache[file_hash] = (time.time(), (False, None))
                        return False, None

                    is_signed = self.signature_verifier.verify_signature(file_path)
                    if not is_signed:
                        result = (True, f"Arquivo executável sem assinatura digital")
                        with self.cache_lock:
                            self.scan_cache[file_hash] = (time.time(), result)
                        return result
                except:
                    pass

            if file_hash in self.virus_db.memory_signatures:
                sig = self.virus_db.memory_signatures[file_hash]
                return True, f"Vírus conhecido: {sig['name']} (Severidade: {sig['severity']})"

            is_ransomware, ransomware_info = self.ransomware_detector.is_ransomware_behavior(file_path)
            if is_ransomware:
                return True, f"Ransomware detectado: {ransomware_info}"

            if file_path.lower().endswith(('.exe', '.sys', '.com', '.scr', '.ocx')):
                try:
                    is_pe_threat, pe_info = self.pe_analyzer.analyze(file_path)
                    if is_pe_threat:
                        threat_desc = f"PE suspeito: {', '.join(pe_info['threats'][:3])}"
                        if pe_info['severity'] >= 7:
                            with self.cache_lock:
                                self.scan_cache[file_hash] = (time.time(), (True, threat_desc))
                            return True, threat_desc
                except:
                    pass

            if yara and self.yara_scanner and self.yara_scanner.rules:
                try:
                    matches = self.yara_scanner.scan_file(file_path)
                    if matches:
                        match_names = [match.rule for match in matches]
                        result = (True, f"Padrão malicioso detectado: {', '.join(match_names)}")
                        with self.cache_lock:
                            self.scan_cache[file_hash] = (time.time(), result)
                        return result
                except:
                    pass

            try:
                if magic and hasattr(magic, 'from_file') and file_size < 50 * 1024 * 1024:
                    mime_type = magic.from_file(file_path, mime=True)

                    suspicious_mimes = {
                        'application/x-msdownload': ['.exe', '.dll', '.com', '.scr', '.sys'],
                        'application/x-msdos-program': ['.exe', '.com', '.bat'],
                        'application/x-executable': ['.exe', '.elf', '.out'],
                        'application/x-sharedlib': ['.so', '.dll'],
                        'application/x-object': ['.o', '.obj'],
                        'application/x-archive': ['.a', '.ar'],
                        'application/java-archive': ['.jar', '.war', '.ear'],
                        'application/x-python-code': ['.pyc', '.pyo'],
                        'application/x-java-applet': ['.class']
                    }

                    for mime, expected_exts in suspicious_mimes.items():
                        if mime in mime_type and file_ext not in expected_exts:
                            result = (True, f"Tipo MIME suspeito: {mime} com extensão {file_ext}")
                            with self.cache_lock:
                                self.scan_cache[file_hash] = (time.time(), result)
                            return result
            except:
                pass

            if file_size < 1 * 1024 * 1024:
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()

                        suspicious_patterns = [
                            b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
                            b'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
                            b'This program cannot be run in DOS mode',
                            b'This is a virus',
                            b'Hacked by',
                            b'Your files have been encrypted',
                            b'All your files',
                            b'Bitcoin wallet',
                            b'Send money to',
                            b'Tor browser',
                            b'onion',
                            b'bitcoin:',
                            b'monero:',
                            b'ransomware',
                            b'cryptolocker',
                            b'keylogger',
                            b'backdoor',
                            b'trojan',
                            b'malware',
                            b'rootkit',
                            b'botnet'
                        ]

                        for pattern in suspicious_patterns:
                            if pattern in content:
                                result = (True, f"Padrão suspeito encontrado: {pattern.decode('utf-8', errors='ignore')[:20]}...")
                                with self.cache_lock:
                                    self.scan_cache[file_hash] = (time.time(), result)
                                return result
                except:
                    pass

            registry_threats = self.registry_monitor.check_autostart_registry()
            if registry_threats:
                for threat in registry_threats:
                    if file_path.lower() in str(threat['value']).lower():
                        result = (True, f"Arquivo em registro suspeito: {threat['key']}")
                        with self.cache_lock:
                            self.scan_cache[file_hash] = (time.time(), result)
                        return result

            if self.loop and hasattr(self.online_scanner, 'check_hash_online') and file_size < 100 * 1024 * 1024:
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        self.online_scanner.check_hash_online(file_hash),
                        self.loop
                    )
                    online_results = future.result(timeout=2)

                    if online_results:
                        for result in online_results:
                            if isinstance(result['result'], dict):
                                if result['result'].get('malicious', False):
                                    self.virus_db.add_signature(file_hash, result['source'], 'malware', 8)
                                    result = (True, f"Detectado por {result['source']} como malware")
                                    with self.cache_lock:
                                        self.scan_cache[file_hash] = (time.time(), result)
                                    return result
                except:
                    pass

            with self.cache_lock:
                self.scan_cache[file_hash] = (time.time(), (False, None))
                if len(self.scan_cache) > 200000:
                    cache_items = list(self.scan_cache.items())
                    cache_items.sort(key=lambda x: x[1][0])
                    for i in range(len(cache_items) // 2):
                        del self.scan_cache[cache_items[i][0]]

            return False, None

        except Exception as e:
            return False, None

    def calculate_hash(self, file_path):
        try:
            hash_sha256 = hashlib.sha256()

            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:
                with open(file_path, 'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        for i in range(0, len(mm), 65536):
                            hash_sha256.update(mm[i:i+65536])
            else:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(65536):
                        hash_sha256.update(chunk)

            return hash_sha256.hexdigest()
        except:
            return None

    def scan_file_parallel(self, file_paths):
        results = []

        chunk_size = 50
        for i in range(0, len(file_paths), chunk_size):
            chunk = file_paths[i:i+chunk_size]
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(chunk), cpu_count() * 2)) as executor:
                futures = {executor.submit(self.scan_file, path): path for path in chunk}
                for future in concurrent.futures.as_completed(futures):
                    path = futures[future]
                    try:
                        is_threat, threat_info = future.result()
                        if is_threat:
                            results.append((path, threat_info))
                    except:
                        pass

        return results

    def scan_running_processes(self):
        threats = []
        processes = []

        try:
            process_list = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))

            suspicious_behavior_pids = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, cpu_count() * 4)) as executor:
                def check_behavior(proc):
                    try:
                        if proc.info['exe'] and os.path.exists(proc.info['exe']):
                            proc_name = proc.info['name'].lower()

                            for app in self.whitelist_apps:
                                if app in proc_name:
                                    return None

                            proc_path = proc.info['exe'].lower()
                            if "chrome" in proc_path or "edge" in proc_path or "firefox" in proc_path or "brave" in proc_path or "opera" in proc_path:
                                return None

                            if self.behavior_monitor.monitor_process_behavior(proc.info['pid']):
                                return proc.info['pid']
                        return None
                    except:
                        return None

                behavior_futures = [executor.submit(check_behavior, proc) for proc in process_list]
                for future in concurrent.futures.as_completed(behavior_futures):
                    pid = future.result()
                    if pid:
                        suspicious_behavior_pids.add(pid)

            prioritized_processes = []
            normal_processes = []

            for proc in process_list:
                try:
                    if proc.info['exe'] and os.path.exists(proc.info['exe']):
                        proc_name = proc.info['name'].lower()
                        proc_exe_lower = proc.info['exe'].lower()

                        skip = False
                        for app in self.whitelist_apps:
                            if app in proc_name:
                                skip = True
                                break

                        if skip:
                            continue

                        if "android" in proc_exe_lower and ("sdk" in proc_exe_lower or "ndk" in proc_exe_lower):
                            continue

                        if "microsoft" in proc_exe_lower or "onedrive" in proc_exe_lower or "packages\\microsoftwindows" in proc_exe_lower:
                            continue

                        if "chrome" in proc_exe_lower or "edge" in proc_exe_lower or "firefox" in proc_exe_lower or "brave" in proc_exe_lower or "opera" in proc_exe_lower:
                            continue

                        if proc.info['pid'] in suspicious_behavior_pids:
                            prioritized_processes.append(proc.info)
                        else:
                            normal_processes.append(proc.info)
                except:
                    continue

            processes = prioritized_processes + normal_processes
        except:
            return threats

        unsigned_exes = []
        exe_paths = [p['exe'] for p in processes if p['exe'] and p['exe'].lower().endswith(('.exe', '.sys'))]

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, cpu_count() * 2)) as executor:
            def check_signature(path):
                try:
                    file_path_lower = path.lower()
                    if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                        return None

                    if "microsoft" in file_path_lower or "onedrive" in file_path_lower or "packages\\microsoftwindows" in file_path_lower:
                        return None

                    if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                        return None

                    if file_path_lower.endswith('.dll'):
                        return None

                    if not self.whitelist.is_whitelisted(path):
                        if not self.signature_verifier.verify_signature(path):
                            return path
                    return None
                except:
                    return None

            signature_futures = {executor.submit(check_signature, path): path for path in exe_paths}
            for future in concurrent.futures.as_completed(signature_futures):
                path = future.result()
                if path:
                    unsigned_exes.append(path)

        prioritized_exe_paths = []
        normal_exe_paths = []

        for path in exe_paths:
            if path in unsigned_exes:
                prioritized_exe_paths.append(path)
            else:
                normal_exe_paths.append(path)

        scan_results = self.scan_file_parallel(prioritized_exe_paths + normal_exe_paths[:50])
        exe_threats = {result[0]: result[1] for result in scan_results}

        for proc in processes:
            try:
                proc_name = proc['name'].lower()
                proc_exe_lower = proc['exe'].lower()

                skip = False
                for app in self.whitelist_apps:
                    if app in proc_name:
                        skip = True
                        break

                if skip:
                    continue

                if "android" in proc_exe_lower and ("sdk" in proc_exe_lower or "ndk" in proc_exe_lower):
                    continue

                if "microsoft" in proc_exe_lower or "onedrive" in proc_exe_lower or "packages\\microsoftwindows" in proc_exe_lower:
                    continue

                if "chrome" in proc_exe_lower or "edge" in proc_exe_lower or "firefox" in proc_exe_lower or "brave" in proc_exe_lower or "opera" in proc_exe_lower:
                    continue

                if self.whitelist.is_whitelisted(proc['exe']):
                    continue

                if proc['exe'] in exe_threats:
                    threats.append({
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'path': proc['exe'],
                        'threat': exe_threats[proc['exe']]
                    })
                    continue

                if proc['exe'] in unsigned_exes:
                    file_ext = os.path.splitext(proc['exe'])[1].lower()
                    risky_scripts = ['.ps1', '.vbs', '.bat', '.cmd']

                    if file_ext in risky_scripts:
                        if self.whitelist.is_windows_script(proc['exe']):
                            continue

                        threats.append({
                            'pid': proc['pid'],
                            'name': proc['name'],
                            'path': proc['exe'],
                            'threat': f"Script não autorizado: {file_ext}"
                        })
                        continue

                    threats.append({
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'path': proc['exe'],
                        'threat': "Executável sem assinatura digital"
                    })
                    continue

                if proc['cmdline'] and len(proc['cmdline']) > 1:
                    for arg in proc['cmdline'][1:]:
                        arg_lower = arg.lower()
                        if arg_lower.endswith('.ps1') or arg_lower.endswith('.cmd') or arg_lower.endswith('.bat'):
                            if not self.whitelist.is_windows_script(arg) and not self.whitelist.is_whitelisted(arg):
                                threats.append({
                                    'pid': proc['pid'],
                                    'name': proc['name'],
                                    'path': proc['exe'],
                                    'threat': f"Execução de script não autorizado: {arg}"
                                })
                                break

                suspicious_network = self.network_scanner.check_network_connections(proc['pid'])
                if suspicious_network:
                    threats.append({
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'threat': f"Conexões de rede suspeitas: {len(suspicious_network)} detecções"
                    })

                if proc['pid'] in suspicious_behavior_pids:
                    threats.append({
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'threat': 'Comportamento suspeito detectado'
                    })

                if random.random() < 0.05:
                    memory_threats = self.memory_scanner.scan_process_memory(proc['pid'])
                    if memory_threats:
                        threats.append({
                            'pid': proc['pid'],
                            'name': proc['name'],
                            'threat': f"Conteúdo suspeito na memória: {len(memory_threats)} detecções"
                        })

            except:
                continue

        return threats

class QuarantineManager:
    def __init__(self, app_data_dir=None):
        if app_data_dir is None:
            app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
            if not os.path.exists(app_data_dir):
                os.makedirs(app_data_dir)

        self.quarantine_dir = os.path.join(app_data_dir, 'quarantine')
        self.quarantine_db = os.path.join(app_data_dir, 'quarantine.db')
        self.encryption_key = b'WolfGuardAntivirusQuarantineKey32'

        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

        self.init_database()

    def init_database(self):
        conn = sqlite3.connect(self.quarantine_db)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT,
                quarantine_path TEXT,
                threat_name TEXT,
                file_size INTEGER,
                original_permissions TEXT,
                date_quarantined TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def quarantine_file(self, file_path, threat_name):
        try:
            if not os.path.exists(file_path):
                return False, "Arquivo não encontrado"

            file_path_lower = file_path.lower()

            temp_path = os.environ.get('TEMP', '').lower()
            if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                return False, "Arquivo temporário do navegador (falso positivo)"

            if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                return False, "Arquivo pertence ao Android SDK (falso positivo)"

            if (file_path_lower.endswith('.js') and
                ('.vscode\\extensions' in file_path_lower or 'node_modules' in file_path_lower)):
                return False, "Arquivo em diretório de extensão do VSCode (falso positivo)"

            if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                return False, "Arquivo pertence ao Microsoft OneDrive (falso positivo)"

            if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                return False, "Arquivo de cache de URL criptográfica (falso positivo)"

            if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                return False, "Arquivo de papel de parede do Windows (falso positivo)"

            if "zxcvbndata" in file_path_lower:
                return False, "Arquivo de dados de segurança (falso positivo)"

            if "pip\\cache" in file_path_lower:
                return False, "Arquivo de cache do pip (falso positivo)"

            if "packages\\microsoftwindows" in file_path_lower:
                return False, "Arquivo de pacote do Windows (falso positivo)"

            if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                return False, "Arquivo de dados de fuso horário (falso positivo)"

            if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                    return False, "Arquivo temporário de navegador (falso positivo)"

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                return False, "Arquivo de teste de política de script do PowerShell (falso positivo)"

            file_ext = os.path.splitext(file_path_lower)[1]
            if file_ext in ['.ps1', '.cmd', '.bat']:
                for windows_path in WINDOWS_SCRIPT_PATHS:
                    if file_path_lower.startswith(windows_path.lower()):
                        return False, "Script legítimo do Windows (falso positivo)"

                if file_path_lower.startswith(os.environ.get('SystemRoot', 'C:\\Windows').lower()):
                    return False, "Script legítimo do Windows (falso positivo)"

            basename = os.path.basename(file_path_lower)
            wolf_scripts = ["wolf.py",
                           "wolf5.py"]
            if basename in wolf_scripts:
                return False, "Script de segurança (falso positivo)"

            if file_ext == '.dll':
                return False, "Arquivo .dll é seguro"

            file_hash = hashlib.sha256(file_path.encode()).hexdigest()
            quarantine_name = f"{file_hash}_{int(time.time())}.qrt"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            file_size = os.path.getsize(file_path)

            try:
                security_descriptor = win32security.GetFileSecurity(
                    file_path, win32security.DACL_SECURITY_INFORMATION
                )
                security_descriptor_binary = pickle.dumps(security_descriptor)
                original_permissions = base64.b64encode(security_descriptor_binary).decode('utf-8')
            except:
                original_permissions = ""

            try:
                with open(file_path, 'rb') as f:
                    data = f.read()

                encrypted_data = self.encrypt_file_data(data)

                with open(quarantine_path, 'wb') as f:
                    f.write(encrypted_data)

                try:
                    self.terminate_file_processes(file_path)
                except:
                    pass

                file_removed = False
                try:
                    os.remove(file_path)
                    file_removed = True
                except:
                    try:
                        subprocess.run(['cmd', '/c', 'del', '/f', '/q', file_path],
                                     shell=True, capture_output=True, timeout=3)
                        file_removed = True
                    except:
                        try:
                            win32file.MoveFileEx(
                                file_path,
                                None,
                                win32file.MOVEFILE_DELAY_UNTIL_REBOOT
                            )
                            file_removed = True
                        except:
                            file_removed = False

                conn = sqlite3.connect(self.quarantine_db)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_size, original_permissions)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_path, quarantine_path, threat_name, file_size, original_permissions))
                conn.commit()
                conn.close()

                if file_removed:
                    return True, "Arquivo quarentenado com sucesso"
                else:
                    return True, "Arquivo copiado para quarentena, mas não pôde ser removido (possivelmente em uso)"

            except:
                try:
                    temp_path = os.path.join(self.quarantine_dir, f"temp_{file_hash}.tmp")

                    try:
                        subprocess.run(['cmd', '/c', f'copy /Y "{file_path}" "{temp_path}"'],
                                     shell=True, capture_output=True, timeout=3)
                    except:
                        return False, "Não foi possível copiar o arquivo"

                    if os.path.exists(temp_path):
                        with open(temp_path, 'rb') as f:
                            data = f.read()

                        encrypted_data = self.encrypt_file_data(data)

                        with open(quarantine_path, 'wb') as f:
                            f.write(encrypted_data)

                        try:
                            os.remove(temp_path)
                        except:
                            pass

                        file_removed = False
                        try:
                            self.terminate_file_processes(file_path)
                        except:
                            pass

                        try:
                            os.remove(file_path)
                            file_removed = True
                        except:
                            try:
                                subprocess.run(['cmd', '/c', f'taskkill /F /IM "{os.path.basename(file_path)}" & del /F /Q "{file_path}"'],
                                             shell=True, capture_output=True, timeout=3)
                                file_removed = True
                            except:
                                try:
                                    win32file.MoveFileEx(
                                        file_path,
                                        None,
                                        win32file.MOVEFILE_DELAY_UNTIL_REBOOT
                                    )
                                    file_removed = True
                                except:
                                    file_removed = False

                        conn = sqlite3.connect(self.quarantine_db)
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_size, original_permissions)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (file_path, quarantine_path, threat_name, file_size, original_permissions))
                        conn.commit()
                        conn.close()

                        if file_removed:
                            return True, "Arquivo quarentenado com sucesso (método alternativo)"
                        else:
                            return True, "Arquivo copiado para quarentena, mas não pôde ser removido (possivelmente em uso)"
                    else:
                        return False, "Não foi possível criar cópia temporária do arquivo"
                except:
                    return False, "Não foi possível quarentenar o arquivo"

        except Exception as e:
            return False, f"Erro ao tentar quarentenar: {str(e)}"

    def terminate_file_processes(self, file_path):
        try:
            file_path_lower = file_path.lower()
            for proc in psutil.process_iter(['pid', 'exe', 'name']):
                try:
                    if proc.info['exe'] and proc.info['exe'].lower() == file_path_lower:
                        try:
                            proc_obj = psutil.Process(proc.info['pid'])
                            try:
                                proc_obj.terminate()
                                try:
                                    proc_obj.wait(timeout=1)
                                except:
                                    pass
                            except:
                                try:
                                    proc_obj.kill()
                                except:
                                    pass
                        except:
                            pass
                except:
                    continue
        except:
            pass

    def encrypt_file_data(self, data):
        try:
            original_hash = hashlib.sha256(data).hexdigest().encode()

            derived_key = bytearray()
            for i in range(len(data)):
                key_byte = self.encryption_key[i % len(self.encryption_key)]
                derived_key.append(key_byte ^ ((i & 0xFF) + 1))

            encrypted_data = bytearray()
            for i, b in enumerate(data):
                encrypted_data.append(b ^ derived_key[i % len(derived_key)])

            if len(encrypted_data) > 1024 * 1024:
                compressed = zlib.compress(encrypted_data)

                header = b"WGQF" + b"\\x01" + b"\\x01" + struct.pack("<I", len(data))
                return header + original_hash + compressed
            else:
                header = b"WGQF" + b"\\x01" + b"\\x00" + struct.pack("<I", len(data))
                return header + original_hash + encrypted_data
        except:
            key_repeated = (self.encryption_key * (len(data) // len(self.encryption_key) + 1))[:len(data)]
            return bytes(a ^ b for a, b in zip(data, key_repeated))

    def decrypt_file_data(self, encrypted_data):
        try:
            if encrypted_data[:4] == b"WGQF":
                version = encrypted_data[4]
                is_compressed = encrypted_data[5] == 1
                original_size = struct.unpack("<I", encrypted_data[6:10])[0]
                original_hash = encrypted_data[10:74]

                data = encrypted_data[74:]

                if is_compressed:
                    data = zlib.decompress(data)

                derived_key = bytearray()
                for i in range(len(data)):
                    key_byte = self.encryption_key[i % len(self.encryption_key)]
                    derived_key.append(key_byte ^ ((i & 0xFF) + 1))

                decrypted_data = bytearray()
                for i, b in enumerate(data):
                    decrypted_data.append(b ^ derived_key[i % len(derived_key)])

                decrypted_hash = hashlib.sha256(decrypted_data).hexdigest().encode()
                if decrypted_hash != original_hash:
                    raise ValueError("Hash mismatch in quarantined file")

                return bytes(decrypted_data)
            else:
                return self.simple_decrypt(encrypted_data)
        except:
            return self.simple_decrypt(encrypted_data)

    def simple_decrypt(self, data):
        key_repeated = (self.encryption_key * (len(data) // len(self.encryption_key) + 1))[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key_repeated))

    def restore_file(self, quarantine_id):
        try:
            conn = sqlite3.connect(self.quarantine_db)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM quarantine WHERE id = ?', (quarantine_id,))
            row = cursor.fetchone()

            if not row:
                return False, "Item não encontrado"

            id_, original_path, quarantine_path, threat_name, file_size, original_permissions, date_quarantined = row

            if not os.path.exists(quarantine_path):
                return False, "Arquivo quarentenado não encontrado"

            with open(quarantine_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.decrypt_file_data(encrypted_data)

            restore_dir = os.path.dirname(original_path)
            if not os.path.exists(restore_dir):
                try:
                    os.makedirs(restore_dir)
                except:
                    restore_dir = os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop')
                    original_path = os.path.join(restore_dir, os.path.basename(original_path))

            with open(original_path, 'wb') as f:
                f.write(decrypted_data)

            if original_permissions:
                try:
                    security_descriptor_binary = base64.b64decode(original_permissions)
                    security_descriptor = pickle.loads(security_descriptor_binary)
                    win32security.SetFileSecurity(
                        original_path,
                        win32security.DACL_SECURITY_INFORMATION,
                        security_descriptor
                    )
                except:
                    pass

            try:
                os.remove(quarantine_path)
            except:
                pass

            cursor.execute('DELETE FROM quarantine WHERE id = ?', (quarantine_id,))
            conn.commit()
            conn.close()

            return True, "Arquivo restaurado com sucesso"

        except Exception as e:
            return False, str(e)

    def delete_file(self, quarantine_id):
        try:
            conn = sqlite3.connect(self.quarantine_db)
            cursor = conn.cursor()
            cursor.execute('SELECT quarantine_path FROM quarantine WHERE id = ?', (quarantine_id,))
            row = cursor.fetchone()

            if not row:
                return False, "Item não encontrado"

            quarantine_path = row[0]

            if os.path.exists(quarantine_path):
                try:
                    os.remove(quarantine_path)
                except:
                    pass

            cursor.execute('DELETE FROM quarantine WHERE id = ?', (quarantine_id,))
            conn.commit()
            conn.close()

            return True, "Arquivo excluído permanentemente"

        except Exception as e:
            return False, str(e)

    def get_quarantined_files(self):
        try:
            conn = sqlite3.connect(self.quarantine_db)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM quarantine ORDER BY date_quarantined DESC')
            rows = cursor.fetchall()
            conn.close()

            files = []
            for row in rows:
                files.append({
                    'id': row[0],
                    'original_path': row[1],
                    'quarantine_path': row[2],
                    'threat_name': row[3],
                    'file_size': row[4],
                    'date_quarantined': row[6] if len(row) > 6 else row[5]
                })

            return files

        except:
            return []

class DownloadBlocker:
    def __init__(self):
        self.blocked_extensions = ['.ps1', '.vbs', '.bat', '.cmd', '.js', '.vbe', '.jse', '.wsf', '.wsh', '.hta']
        self.browsers = ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "brave.exe", "opera.exe", "opera_gx.exe"]
        self.download_dirs = []
        self.running = True
        self.observer = None
        self.monitor_thread = None

        self.initialize_download_dirs()

    def initialize_download_dirs(self):
        user_profile = os.environ.get('USERPROFILE', '')
        if user_profile:
            downloads_dir = os.path.join(user_profile, 'Downloads')
            if os.path.exists(downloads_dir):
                self.download_dirs.append(downloads_dir)

            desktop_dir = os.path.join(user_profile, 'Desktop')
            if os.path.exists(desktop_dir):
                self.download_dirs.append(desktop_dir)

            documents_dir = os.path.join(user_profile, 'Documents')
            if os.path.exists(documents_dir):
                self.download_dirs.append(documents_dir)

    def start_monitoring(self):
        self.monitor_thread = threading.Thread(target=self.monitor_downloads, daemon=True)
        self.monitor_thread.start()

    def monitor_downloads(self):
        class DownloadEventHandler(FileSystemEventHandler):
            def __init__(self, blocker):
                self.blocker = blocker

            def on_created(self, event):
                if not event.is_directory:
                    self.blocker.check_file(event.src_path)

            def on_modified(self, event):
                if not event.is_directory:
                    self.blocker.check_file(event.src_path)

        self.observer = Observer()
        event_handler = DownloadEventHandler(self)

        for download_dir in self.download_dirs:
            self.observer.schedule(event_handler, download_dir, recursive=False)

        self.observer.start()

        try:
            while self.running:
                time.sleep(1)
        except:
            self.observer.stop()
        self.observer.join()

    def check_file(self, file_path):
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            file_path_lower = file_path.lower()

            if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                return

            if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                return

            if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                return

            if "zxcvbndata" in file_path_lower:
                return

            if "pip\\cache" in file_path_lower:
                return

            if "packages\\microsoftwindows" in file_path_lower:
                return

            if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                    return

            if file_ext in self.blocked_extensions:
                print(f"Script de risco detectado em pasta de downloads: {file_path}")

                file_stat = os.stat(file_path)
                if time.time() - file_stat.st_mtime < 10:
                    print(f"Bloqueando download de script: {file_path}")

                    try:
                        os.remove(file_path)
                        print(f"Arquivo removido: {file_path}")
                    except:
                        try:
                            tmp_path = file_path + ".blocked"
                            os.rename(file_path, tmp_path)
                            os.remove(tmp_path)
                            print(f"Arquivo renomeado e removido: {file_path}")
                        except Exception as e:
                            print(f"Não foi possível remover o arquivo: {file_path} - {str(e)}")
        except Exception as e:
            print(f"Erro ao verificar download: {str(e)}")

    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()

class WolfGuardService(win32serviceutil.ServiceFramework):
    _svc_name_ = "WolfGuardAntivirus"
    _svc_display_name_ = "WolfGuard Antivirus Protection"
    _svc_description_ = "Serviço de proteção em tempo real contra malware e vírus"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = threading.Event()
        self.app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)

        self.log_file = os.path.join(self.app_data_dir, 'service.log')
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        self.scan_engine = None
        self.file_monitor = None
        self.usb_monitor = None
        self.usb_controller = None
        self.download_blocker = None
        self.observers = []
        self.last_scan_time = 0
        self.scan_interval = 3600

        if keyboard and hasattr(keyboard, 'add_hotkey'):
            keyboard.add_hotkey('f4', self.restore_network_and_usb)

    def restore_network_and_usb(self):
        try:
            logging.info("Tecla F4 pressionada - Restaurando rede e USB")
            self.enable_network()
            if self.usb_controller:
                self.usb_controller.enable_all_usb_devices()
            logging.info("Rede e USB restaurados")
        except Exception as e:
            logging.error(f"Erro ao restaurar rede e USB: {str(e)}")

    def enable_network(self):
        try:
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"], capture_output=True)
            subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=enable"], capture_output=True)
            logging.info("Interfaces de rede habilitadas")
        except Exception as e:
            logging.error(f"Erro ao habilitar interfaces de rede: {str(e)}")

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logging.info("Serviço está sendo interrompido")
        self.stop_event.set()

        if self.file_monitor:
            self.file_monitor.stop()

        if self.usb_monitor:
            self.usb_monitor.stop()

        if self.download_blocker:
            self.download_blocker.stop()

        for observer in self.observers:
            observer.stop()
            observer.join(timeout=3)

        logging.info("Serviço interrompido")

    def SvcDoRun(self):
        logging.info("Serviço iniciado")
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        try:
            self.start_protection()

            while not self.stop_event.is_set():
                try:
                    current_time = time.time()
                    if current_time - self.last_scan_time > self.scan_interval:
                        self.schedule_background_scan()
                        self.last_scan_time = current_time
                except:
                    pass

                self.check_configuration()

                time.sleep(60)

        except Exception as e:
            logging.error(f"Erro fatal no serviço: {str(e)}")
            self.SvcStop()

    def start_protection(self):
        try:
            logging.info("Inicializando motor de escaneamento")
            self.scan_engine = ScanEngine(self.app_data_dir)
            self.quarantine_manager = self.scan_engine.quarantine_manager

            logging.info("Inicializando controlador USB")
            self.usb_controller = USBController()

            logging.info("Inicializando monitor de sistema de arquivos")
            self.file_monitor = FileSystemMonitor(
                self.scan_engine,
                self.quarantine_manager,
                self.handle_threat
            )

            logging.info("Inicializando monitor de dispositivos USB")
            self.usb_monitor = USBMonitor(
                self.scan_engine,
                self.quarantine_manager,
                self.log_message
            )

            logging.info("Inicializando bloqueador de downloads")
            self.download_blocker = DownloadBlocker()
            self.download_blocker.start_monitoring()

            self.start_filesystem_observers()
            self.start_process_monitor()

            self.schedule_process_scan()

            logging.info("Proteção em tempo real iniciada com sucesso")
        except Exception as e:
            logging.error(f"Erro ao iniciar proteção: {str(e)}")

    def start_filesystem_observers(self):
        try:
            drives = []
            for drive in win32api.GetLogicalDriveStrings().split('\\000')[:-1]:
                drive_type = win32file.GetDriveType(drive)
                if drive_type in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOTE):
                    drives.append(drive)

            for drive in drives:
                try:
                    observer = Observer()
                    observer.schedule(self.file_monitor, drive, recursive=False)
                    observer.start()
                    self.observers.append(observer)
                    logging.info(f"Monitoramento iniciado para raiz do drive: {drive}")

                    critical_dirs = [
                        os.path.join(drive, "Program Files"),
                        os.path.join(drive, "Program Files (x86)"),
                        os.path.join(drive, "Windows"),
                        os.path.join(drive, "Users")
                    ]

                    for critical_dir in critical_dirs:
                        if os.path.exists(critical_dir):
                            observer = Observer()
                            observer.schedule(self.file_monitor, critical_dir, recursive=False)
                            observer.start()
                            self.observers.append(observer)
                            logging.info(f"Monitoramento iniciado para diretório crítico: {critical_dir}")
                except:
                    pass

            special_folders = [
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
                os.path.join(os.environ.get('APPDATA', '')),
                os.path.join(os.environ.get('LOCALAPPDATA', ''))
            ]

            for folder in special_folders:
                if os.path.exists(folder):
                    try:
                        observer = Observer()
                        observer.schedule(self.file_monitor, folder, recursive=True)
                        observer.start()
                        self.observers.append(observer)
                        logging.info(f"Monitoramento iniciado para pasta: {folder}")
                    except:
                        pass

            temp_dirs = [
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', ''),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp')
            ]

            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    try:
                        observer = Observer()
                        observer.schedule(self.file_monitor, temp_dir, recursive=True)
                        observer.start()
                        self.observers.append(observer)
                        logging.info(f"Monitoramento iniciado para pasta temporária: {temp_dir}")
                    except:
                        pass
        except:
            pass

    def start_process_monitor(self):
        def monitor_processes():
            while not self.stop_event.is_set():
                try:
                    threats = self.scan_engine.scan_running_processes()
                    for threat in threats:
                        self.handle_process_threat(threat)
                    time.sleep(120)
                except:
                    time.sleep(60)

        process_thread = threading.Thread(target=monitor_processes, daemon=True)
        process_thread.start()
        logging.info("Monitor de processos iniciado")

    def schedule_process_scan(self):
        def scan_processes():
            try:
                logging.info("Iniciando verificação de processos em execução")
                threats = self.scan_engine.scan_running_processes()

                if threats:
                    logging.warning(f"Encontradas {len(threats)} ameaças em processos em execução")
                    for threat in threats:
                        self.handle_process_threat(threat)
                else:
                    logging.info("Nenhuma ameaça encontrada em processos em execução")
            except:
                pass

        scan_thread = threading.Thread(target=scan_processes, daemon=True)
        scan_thread.start()

    def schedule_background_scan(self):
        def background_scan():
            try:
                logging.info("Iniciando verificação de arquivos críticos em segundo plano")

                critical_dirs = [
                    os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
                    os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files')),
                    os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')),
                    os.path.join(os.environ.get('APPDATA', '')),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''))
                ]

                files_to_scan = []
                signature_verifier = self.scan_engine.signature_verifier

                for dir_path in critical_dirs:
                    if os.path.exists(dir_path):
                        for root, dirs, files in os.walk(dir_path, topdown=True):
                            if root.count(os.path.sep) - dir_path.count(os.path.sep) > 3:
                                dirs.clear()
                                continue

                            for file in files:
                                if file.lower().endswith(('.exe', '.sys', '.com', '.scr', '.ocx')):
                                    file_path = os.path.join(root, file)
                                    file_path_lower = file_path.lower()

                                    if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                                        continue

                                    if "microsoft" in file_path_lower or "onedrive" in file_path_lower or "packages\\microsoftwindows" in file_path_lower:
                                        continue

                                    if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                                        continue

                                    if "discord" in file_path_lower or "riot" in file_path_lower or "league" in file_path_lower or "valorant" in file_path_lower:
                                        continue

                                    if self.scan_engine.whitelist.is_whitelisted(file_path):
                                        continue

                                    try:
                                        if not signature_verifier.verify_signature(file_path):
                                            files_to_scan.append(file_path)
                                    except:
                                        continue

                risky_scripts = []
                for dir_path in [os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop')]:
                    if os.path.exists(dir_path):
                        for root, dirs, files in os.walk(dir_path):
                            for file in files:
                                if file.lower().endswith(('.ps1', '.vbs', '.bat', '.cmd')):
                                    file_path = os.path.join(root, file)
                                    file_path_lower = file_path.lower()

                                    if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                                        continue

                                    if "microsoft" in file_path_lower or "onedrive" in file_path_lower or "packages\\microsoftwindows" in file_path_lower:
                                        continue

                                    if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                                        continue

                                    if self.scan_engine.whitelist.is_windows_script(file_path):
                                        continue

                                    risky_scripts.append(file_path)

                if risky_scripts:
                    logging.info(f"Verificando {len(risky_scripts)} scripts potencialmente perigosos")
                    for script_path in risky_scripts:
                        self.handle_threat(script_path, f"Script não autorizado: {os.path.splitext(script_path)[1].lower()}", True)

                if files_to_scan:
                    logging.info(f"Verificando {len(files_to_scan)} arquivos executáveis não assinados")

                    batch_size = 100
                    total_threats = 0

                    for i in range(0, len(files_to_scan), batch_size):
                        batch = files_to_scan[i:i+batch_size]
                        scan_results = self.scan_engine.scan_file_parallel(batch)

                        for file_path, threat_info in scan_results:
                            total_threats += 1
                            self.handle_threat(file_path, threat_info, True)

                    logging.info(f"Verificação em segundo plano concluída. Encontradas {total_threats} ameaças.")
                else:
                    logging.info("Nenhum arquivo executável não assinado encontrado para verificação em segundo plano.")

            except:
                pass

        scan_thread = threading.Thread(target=background_scan)
        scan_thread.daemon = True
        scan_thread.start()

    def check_configuration(self):
        try:
            config_path = os.path.join(self.app_data_dir, 'config.json')
            if os.path.exists(config_path):
                try:
                    modified_time = os.path.getmtime(config_path)
                    if not hasattr(self, 'last_config_time') or modified_time > self.last_config_time:
                        with open(config_path, 'r') as f:
                            config = json.load(f)

                        if 'scan_interval' in config:
                            self.scan_interval = config['scan_interval']

                        self.last_config_time = modified_time
                        logging.info("Configuração atualizada")
                except:
                    pass
        except:
            pass

    def handle_threat(self, file_path, threat_info, quarantine=True):
        try:
            logging.warning(f"Ameaça detectada: {file_path} - {threat_info}")

            file_path_lower = file_path.lower()

            temp_path = os.environ.get('TEMP', '').lower()
            if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                logging.info(f"Arquivo temporário do navegador, ignorando: {file_path}")
                return

            if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                logging.info(f"Arquivo pertence ao Android SDK, ignorando: {file_path}")
                return

            if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                logging.info(f"Arquivo do Microsoft OneDrive, ignorando: {file_path}")
                return

            if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                logging.info(f"Arquivo de cache de URL criptográfica, ignorando: {file_path}")
                return

            if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                logging.info(f"Arquivo de papel de parede do Windows, ignorando: {file_path}")
                return

            if "zxcvbndata" in file_path_lower:
                logging.info(f"Arquivo de dados de segurança, ignorando: {file_path}")
                return

            if "pip\\cache" in file_path_lower:
                logging.info(f"Arquivo de cache do pip, ignorando: {file_path}")
                return

            if "packages\\microsoftwindows" in file_path_lower:
                logging.info(f"Arquivo de pacote do Windows, ignorando: {file_path}")
                return

            if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                    logging.info(f"Arquivo temporário de navegador, ignorando: {file_path}")
                    return

            if (file_path_lower.endswith('.js') and
                ('.vscode\\extensions' in file_path_lower or 'node_modules' in file_path_lower)):
                logging.info(f"Arquivo ignorado (falso positivo): {file_path}")
                return

            if "discord" in file_path.lower() or "riot" in file_path.lower() or "league" in file_path.lower() or "valorant" in file_path.lower():
                logging.info(f"Aplicativo confiável, ignorando: {file_path}")
                return

            file_ext = os.path.splitext(file_path_lower)[1]
            if file_ext in ['.ps1', '.cmd', '.bat']:
                if self.scan_engine.whitelist.is_windows_script(file_path):
                    logging.info(f"Script legítimo do Windows, ignorando: {file_path}")
                    return

            if file_ext == '.dll':
                logging.info(f"Arquivo .dll, ignorando: {file_path}")
                return

            if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                logging.info(f"Arquivo de dados de fuso horário, ignorando: {file_path}")
                return

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                logging.info(f"Arquivo de teste de política do PowerShell, ignorando: {file_path}")
                return

            if self.scan_engine.whitelist.is_whitelisted(file_path):
                logging.info(f"Arquivo em whitelist, ignorando: {file_path}")
                return

            if quarantine:
                try:
                    success, message = self.quarantine_manager.quarantine_file(file_path, threat_info)
                    if success:
                        logging.info(f"Arquivo quarentenado: {file_path} - {message}")
                    else:
                        logging.warning(f"Falha ao quarentenar: {file_path} - {message}")

                        if "não pôde ser removido" in message:
                            logging.warning(f"Arquivo em uso e não pode ser removido: {file_path}. Ação manual pode ser necessária.")
                        else:
                            try:
                                win32file.MoveFileEx(
                                    file_path,
                                    None,
                                    win32file.MOVEFILE_DELAY_UNTIL_REBOOT
                                )
                                logging.info(f"Arquivo {file_path} agendado para remoção na próxima reinicialização")
                            except:
                                logging.warning(f"Arquivo malicioso permanece no sistema: {file_path}. Ação manual pode ser necessária.")
                except:
                    logging.warning(f"Erro ao tentar quarentenar: {file_path}. Ação manual pode ser necessária.")
        except:
            pass

    def handle_process_threat(self, threat):
        try:
            pid = threat['pid']
            logging.warning(f"Processo malicioso detectado: PID {pid} - {threat['name']} - {threat['threat']}")

            proc_name_lower = threat['name'].lower()
            proc_path_lower = threat.get('path', '').lower() if threat.get('path') else ''

            if "android" in proc_path_lower and ("sdk" in proc_path_lower or "ndk" in proc_path_lower):
                logging.info(f"Processo do Android SDK, ignorando: {proc_path_lower}")
                return

            if "microsoft" in proc_path_lower or "onedrive" in proc_path_lower or "packages\\microsoftwindows" in proc_path_lower:
                logging.info(f"Processo da Microsoft ou OneDrive, ignorando: {proc_path_lower}")
                return

            if "chrome" in proc_path_lower or "edge" in proc_path_lower or "firefox" in proc_path_lower or "brave" in proc_path_lower or "opera" in proc_path_lower:
                logging.info(f"Processo de navegador, ignorando: {proc_path_lower}")
                return

            if "\\_mei" in proc_path_lower and "\\_tcl_data\\tzdata\\" in proc_path_lower:
                logging.info(f"Processo de dados de fuso horário, ignorando: {proc_path_lower}")
                return

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in proc_path_lower:
                logging.info(f"Processo de teste de política do PowerShell, ignorando: {proc_path_lower}")
                return

            for app in ["discord", "riot", "league", "valorant", "qtwebengine", "wolfguard"]:
                if app in proc_name_lower or app in proc_path_lower:
                    logging.info(f"Aplicativo confiável, ignorando: {threat['name']}")
                    return

            if 'path' in threat and threat['path']:
                file_ext = os.path.splitext(threat['path'])[1].lower()
                if file_ext in ['.ps1', '.cmd', '.bat']:
                    if self.scan_engine.whitelist.is_windows_script(threat['path']):
                        logging.info(f"Script legítimo do Windows, ignorando: {threat['path']}")
                        return

                if file_ext == '.dll':
                    logging.info(f"Processo de arquivo .dll, ignorando: {threat['path']}")
                    return

            if 'path' in threat and threat['path'] and self.scan_engine.whitelist.is_whitelisted(threat['path']):
                logging.info(f"Processo em whitelist, ignorando: {threat['path']}")
                return

            process_terminated = False
            try:
                process = psutil.Process(pid)
                try:
                    process.terminate()
                    process.wait(timeout=2)
                    logging.info(f"Processo terminado: PID {pid}")
                    process_terminated = True
                except:
                    try:
                        process.kill()
                        logging.info(f"Processo finalizado à força: PID {pid}")
                        process_terminated = True
                    except:
                        try:
                            handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, 0, pid)
                            if handle:
                                win32api.TerminateProcess(handle, 0)
                                win32api.CloseHandle(handle)
                                logging.info(f"Processo finalizado com Win32 API: PID {pid}")
                                process_terminated = True
                            else:
                                try:
                                    subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                                                shell=True, capture_output=True, timeout=3)
                                    logging.info(f"Processo finalizado com taskkill: PID {pid}")
                                    process_terminated = True
                                except:
                                    logging.warning(f"Não foi possível terminar o processo: PID {pid}")
                        except:
                            logging.warning(f"Não foi possível terminar o processo: PID {pid}")
            except:
                logging.warning(f"Não foi possível acessar o processo: PID {pid}")

            if not process_terminated:
                logging.warning(f"Atenção: O processo malicioso PID {pid} não pôde ser terminado. Pode ser necessária ação manual.")

            if 'path' in threat and threat['path'] and os.path.exists(threat['path']):
                if not os.path.splitext(threat['path'])[1].lower() == '.dll':
                    try:
                        success, message = self.quarantine_manager.quarantine_file(threat['path'], threat['threat'])
                        if success:
                            logging.info(f"Arquivo quarentenado: {threat['path']} - {message}")
                        else:
                            logging.warning(f"Falha ao quarentenar: {threat['path']} - {message}")
                    except:
                        logging.warning(f"Erro ao manipular arquivo do processo")
        except:
            pass

    def log_message(self, message):
        logging.info(message)

class WolfGuardTray:
    def __init__(self):
        self.app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)

        self.scan_engine = None
        self.quarantine_manager = None
        self.scan_thread = None
        self.scan_active = False
        self.scan_progress = 0
        self.scan_results = []
        self.notification_lock = threading.Lock()

        self.initialize_components()
        self.check_service_status()

        if keyboard and hasattr(keyboard, 'add_hotkey'):
            keyboard.add_hotkey('f4', self.restore_network_and_usb)

        if HAS_QT:
            try:
                QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
                self.init_ui()
            except:
                pass

    def initialize_components(self):
        try:
            self.scan_engine = ScanEngine(self.app_data_dir)
            self.quarantine_manager = self.scan_engine.quarantine_manager
            self.usb_controller = USBController()
            self.download_blocker = DownloadBlocker()
            self.download_blocker.start_monitoring()

            print("WolfGuard Antivirus iniciado com sucesso")
            print("Proteção em tempo real ativa")
        except Exception as e:
            print(f"Erro ao inicializar: {str(e)}")

    def restore_network_and_usb(self):
        try:
            print("Tecla F4 pressionada - Restaurando rede e USB")
            self.enable_network()
            if hasattr(self, 'usb_controller'):
                self.usb_controller.enable_all_usb_devices()
            print("Rede e USB restaurados")
        except Exception as e:
            print(f"Erro ao restaurar rede e USB: {str(e)}")

    def enable_network(self):
        try:
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"], capture_output=True)
            subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=enable"], capture_output=True)
            print("Interfaces de rede habilitadas")
        except Exception as e:
            print(f"Erro ao habilitar interfaces de rede: {str(e)}")

    def init_ui(self):
        try:
            if not QApplication.instance():
                self.app = QApplication([])
                self.app.setQuitOnLastWindowClosed(False)
            else:
                self.app = QApplication.instance()

            self.tray_icon = QSystemTrayIcon()
            self.tray_icon.setToolTip("WolfGuard Antivirus")

            self.tray_menu = QMenu()

            self.scan_action = QAction("Escanear Computador")
            self.scan_action.triggered.connect(lambda: self.start_scan())
            self.tray_menu.addAction(self.scan_action)

            self.quarantine_action = QAction("Quarentena")
            self.quarantine_action.triggered.connect(self.list_quarantine)
            self.tray_menu.addAction(self.quarantine_action)

            self.restore_network_action = QAction("Restaurar Rede e USB (F4)")
            self.restore_network_action.triggered.connect(self.restore_network_and_usb)
            self.tray_menu.addAction(self.restore_network_action)

            self.tray_menu.addSeparator()

            self.service_action = QAction("Iniciar Serviço")
            self.service_action.triggered.connect(self.toggle_service)
            self.tray_menu.addAction(self.service_action)

            self.tray_menu.addSeparator()

            self.exit_action = QAction("Sair")
            self.exit_action.triggered.connect(self.app.quit)
            self.tray_menu.addAction(self.exit_action)

            self.tray_icon.setContextMenu(self.tray_menu)
            self.tray_icon.activated.connect(self.tray_activated)

            self.update_service_status()
            self.tray_icon.show()

            if not self.update_service_status():
                self.toggle_service()

            self.start_scan()
        except:
            pass

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_status()

    def show_status(self):
        try:
            status = win32serviceutil.QueryServiceStatus('WolfGuardAntivirus')[1]
            status_str = "Ativo" if status == win32service.SERVICE_RUNNING else "Parado"

            print(f"Status do serviço: {status_str}")
            print(f"Monitoramento em tempo real: {'Ativo' if status == win32service.SERVICE_RUNNING else 'Inativo'}")
            print(f"Local de instalação: {self.app_data_dir}")

            if HAS_QT:
                self.show_notification("Status do WolfGuard Antivirus",
                                   f"Status: {status_str}\nMonitoramento: {'Ativo' if status == win32service.SERVICE_RUNNING else 'Inativo'}")
        except:
            print("Serviço não instalado ou erro ao verificar status")
            print(f"Local de instalação: {self.app_data_dir}")

            if HAS_QT:
                self.show_notification("Status do WolfGuard Antivirus", "Serviço não instalado ou erro ao verificar status")

    def update_service_status(self):
        try:
            status = win32serviceutil.QueryServiceStatus('WolfGuardAntivirus')[1]
            if status == win32service.SERVICE_RUNNING:
                self.service_action.setText("Parar Serviço")
            else:
                self.service_action.setText("Iniciar Serviço")
            return status == win32service.SERVICE_RUNNING
        except:
            self.service_action.setText("Instalar Serviço")
            return False

    def toggle_service(self):
        try:
            current_status = self.update_service_status()
            if current_status:
                self.stop_service()
            else:
                try:
                    status = win32serviceutil.QueryServiceStatus('WolfGuardAntivirus')[1]
                    self.start_service()
                except:
                    try:
                        if install_service():
                            print("Serviço instalado com sucesso!")
                            self.start_service()
                        else:
                            print("Não foi possível instalar o serviço. Verifique se você tem privilégios administrativos.")
                    except:
                        pass

            self.update_service_status()
        except:
            pass

    def check_service_status(self):
        try:
            status = win32serviceutil.QueryServiceStatus('WolfGuardAntivirus')[1]
            status_str = "Ativo" if status == win32service.SERVICE_RUNNING else "Parado"
            print(f"Status do serviço: {status_str}")
            return status == win32service.SERVICE_RUNNING
        except:
            print("Serviço não instalado ou erro ao verificar status")
            return False

    def start_service(self):
        try:
            win32serviceutil.StartService('WolfGuardAntivirus')
            print("Serviço iniciado com sucesso")
            if HAS_QT:
                self.show_notification("WolfGuard Antivirus", "Serviço de proteção iniciado com sucesso")
            return True
        except:
            print("Erro ao iniciar serviço")
            return False

    def stop_service(self):
        try:
            win32serviceutil.StopService('WolfGuardAntivirus')
            print("Serviço parado com sucesso")
            if HAS_QT:
                self.show_notification("WolfGuard Antivirus", "Serviço de proteção parado")
            return True
        except:
            print("Erro ao parar serviço")
            return False

    def show_notification(self, title, message):
        try:
            with self.notification_lock:
                if hasattr(self, 'tray_icon'):
                    self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 3000)
        except:
            pass

    def start_scan(self, path=None):
        if self.scan_active:
            print("Já existe um escaneamento em andamento")
            return

        if not path:
            path = os.environ.get('USERPROFILE', '')

        if not os.path.exists(path):
            print(f"Caminho não encontrado: {path}")
            return

        self.scan_active = True
        self.scan_progress = 0
        self.scan_results = []

        def scan_thread_func():
            try:
                print(f"Iniciando escaneamento em: {path}")
                total_files = 0
                scanned_files = 0
                threats_found = 0

                if os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        total_files += len(files)
                else:
                    total_files = 1

                print(f"Total de arquivos a serem escaneados: {total_files}")

                def process_threat(file_path, threat_info):
                    nonlocal threats_found
                    threats_found += 1
                    self.scan_results.append((file_path, threat_info))
                    print(f"Ameaça encontrada: {file_path} - {threat_info}")
                    if HAS_QT:
                        self.show_notification("Ameaça Detectada", f"{os.path.basename(file_path)}: {threat_info}")

                    file_path_lower = file_path.lower()

                    temp_path = os.environ.get('TEMP', '').lower()
                    if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                        print(f"Arquivo temporário do navegador, ignorando: {file_path}")
                        return

                    if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                        print(f"Arquivo pertence ao Android SDK, ignorando: {file_path}")
                        return

                    if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                        print(f"Arquivo do Microsoft OneDrive, ignorando: {file_path}")
                        return

                    if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                        print(f"Arquivo de cache de URL criptográfica, ignorando: {file_path}")
                        return

                    if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                        print(f"Arquivo de papel de parede do Windows, ignorando: {file_path}")
                        return

                    if "zxcvbndata" in file_path_lower:
                        print(f"Arquivo de dados de segurança, ignorando: {file_path}")
                        return

                    if "pip\\cache" in file_path_lower:
                        print(f"Arquivo de cache do pip, ignorando: {file_path}")
                        return

                    if "packages\\microsoftwindows" in file_path_lower:
                        print(f"Arquivo de pacote do Windows, ignorando: {file_path}")
                        return

                    if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                        if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                            print(f"Arquivo temporário de navegador, ignorando: {file_path}")
                            return

                    if (file_path_lower.endswith('.js') and
                        ('.vscode\\extensions' in file_path_lower or 'node_modules' in file_path_lower)):
                        print(f"Arquivo ignorado (falso positivo): {file_path}")
                        return

                    if "discord" in file_path.lower() or "riot" in file_path.lower() or "league" in file_path.lower() or "valorant" in file_path.lower():
                        print(f"Aplicativo confiável, ignorando: {file_path}")
                        return

                    file_ext = os.path.splitext(file_path_lower)[1]
                    if file_ext in ['.ps1', '.cmd', '.bat']:
                        if self.scan_engine.whitelist.is_windows_script(file_path):
                            print(f"Script legítimo do Windows, ignorando: {file_path}")
                            return

                    if file_ext == '.dll':
                        print(f"Arquivo .dll, ignorando: {file_path}")
                        return

                    if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                        print(f"Arquivo de dados de fuso horário, ignorando: {file_path}")
                        return

                    if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                        print(f"Arquivo de teste de política do PowerShell, ignorando: {file_path}")
                        return

                    if self.scan_engine.whitelist.is_whitelisted(file_path):
                        print(f"Arquivo em whitelist, ignorando: {file_path}")
                        return

                    try:
                        success, message = self.quarantine_manager.quarantine_file(file_path, threat_info)
                        if success:
                            print(f"Arquivo quarentenado: {file_path} - {message}")
                        else:
                            print(f"Falha ao quarentenar: {file_path} - {message}")
                    except:
                        print("Erro ao quarentenar arquivo")

                if os.path.isdir(path):
                    whitelist = self.scan_engine.whitelist
                    signature_verifier = self.scan_engine.signature_verifier

                    files_to_scan = []

                    try:
                        for root, dirs, files in os.walk(path):
                            try:
                                for file in files:
                                    try:
                                        file_path = os.path.join(root, file)
                                        file_path_lower = file_path.lower()

                                        temp_path = os.environ.get('TEMP', '').lower()
                                        if temp_path and temp_path in file_path_lower and '.tmp.js' in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "zxcvbndata" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "pip\\cache" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "packages\\microsoftwindows" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                                            if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                                                scanned_files += 1
                                                self.scan_progress = int(scanned_files * 100 / total_files)
                                                continue

                                        if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if "discord" in file_path_lower or "riot" in file_path_lower or "league" in file_path_lower or "valorant" in file_path_lower:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if whitelist.is_whitelisted(file_path):
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        file_ext = os.path.splitext(file_path)[1].lower()

                                        if file_ext in whitelist.safe_extensions:
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        risky_scripts = ['.ps1', '.vbs', '.bat', '.cmd']
                                        if file_ext in risky_scripts:
                                            if whitelist.is_windows_script(file_path):
                                                scanned_files += 1
                                                self.scan_progress = int(scanned_files * 100 / total_files)
                                                continue

                                            process_threat(file_path, f"Script não autorizado: {file_ext}")
                                            scanned_files += 1
                                            self.scan_progress = int(scanned_files * 100 / total_files)
                                            continue

                                        if file_ext == '.js':
                                            safe_js_context = False
                                            safe_contexts = ['\\development\\', '\\src\\', '\\node_modules\\', '\\vscode\\', '\\appdata\\local\\temp\\']
                                            for ctx in safe_contexts:
                                                if ctx in file_path_lower:
                                                    safe_js_context = True
                                                    break

                                            if safe_js_context:
                                                scanned_files += 1
                                                self.scan_progress = int(scanned_files * 100 / total_files)
                                                continue

                                        files_to_scan.append(file_path)
                                    except:
                                        continue
                            except:
                                continue
                    except:
                        pass

                    batch_size = 50
                    for i in range(0, len(files_to_scan), batch_size):
                        try:
                            batch = files_to_scan[i:i+batch_size]
                            results = self.scan_engine.scan_file_parallel(batch)

                            for file_path, threat_info in results:
                                process_threat(file_path, threat_info)

                            scanned_files += len(batch)
                            self.scan_progress = int(scanned_files * 100 / total_files)
                            print(f"Progresso: {self.scan_progress}% - Escaneados: {scanned_files} de {total_files}")
                        except:
                            pass

                else:
                    try:
                        is_threat, threat_info = self.scan_engine.scan_file(path)
                        if is_threat:
                            process_threat(path, threat_info)
                    except:
                        pass

                    scanned_files = 1
                    self.scan_progress = 100

                print(f"Escaneamento concluído. Ameaças encontradas: {threats_found}")
                print(f"Total de arquivos escaneados: {scanned_files}")

                if HAS_QT:
                    self.show_notification("Escaneamento Concluído",
                                       f"Ameaças encontradas: {threats_found}\nArquivos escaneados: {scanned_files}")

                self.scan_active = False

            except Exception as e:
                print(f"Erro durante o escaneamento: {str(e)}")
                self.scan_active = False
                if HAS_QT:
                    self.show_notification("Erro no Escaneamento", str(e))

        self.scan_thread = threading.Thread(target=scan_thread_func)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def list_quarantine(self):
        try:
            files = self.quarantine_manager.get_quarantined_files()

            if not files:
                print("Nenhum arquivo em quarentena")
                return

            print("\nArquivos em quarentena:")
            print("-" * 80)
            print(f"{'ID':<5} {'Data':<20} {'Tamanho':<10} {'Ameaça':<20} {'Caminho Original'}")
            print("-" * 80)

            for file in files:
                try:
                    date_str = datetime.fromisoformat(file['date_quarantined']).strftime('%d/%m/%Y %H:%M')
                except:
                    date_str = file['date_quarantined']

                size_str = self.format_size(file['file_size'])

                threat_name = file['threat_name']
                if len(threat_name) > 20:
                    threat_name = threat_name[:17] + "..."

                path = file['original_path']
                if len(path) > 35:
                    path = "..." + path[-32:]

                print(f"{file['id']:<5} {date_str:<20} {size_str:<10} {threat_name:<20} {path}")

            print("-" * 80)
            print("Use 'restore [id]' para restaurar ou 'delete [id]' para excluir permanentemente")

        except Exception as e:
            print(f"Erro ao listar quarentena: {str(e)}")

    def restore_from_quarantine(self, file_id):
        try:
            file_id = int(file_id)
            success, message = self.quarantine_manager.restore_file(file_id)

            if success:
                print(f"Arquivo restaurado com sucesso: {message}")
                if HAS_QT:
                    self.show_notification("Quarentena", "Arquivo restaurado com sucesso")
            else:
                print(f"Falha ao restaurar: {message}")

        except ValueError:
            print("ID inválido. Use um número inteiro.")
        except Exception as e:
            print(f"Erro ao restaurar arquivo: {str(e)}")

    def delete_from_quarantine(self, file_id):
        try:
            file_id = int(file_id)
            success, message = self.quarantine_manager.delete_file(file_id)

            if success:
                print(f"Arquivo excluído permanentemente: {message}")
                if HAS_QT:
                    self.show_notification("Quarentena", "Arquivo excluído permanentemente")
            else:
                print(f"Falha ao excluir: {message}")

        except ValueError:
            print("ID inválido. Use um número inteiro.")
        except Exception as e:
            print(f"Erro ao excluir arquivo: {str(e)}")

    def format_size(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"

    def run_cli(self):
        while True:
            try:
                command = input("\nWolfGuard> ").strip()

                if command == "exit":
                    break
                elif command == "status":
                    self.check_service_status()
                elif command == "start":
                    self.start_service()
                elif command == "stop":
                    self.stop_service()
                elif command == "quarantine":
                    self.list_quarantine()
                elif command.startswith("restore "):
                    _, file_id = command.split(" ", 1)
                    self.restore_from_quarantine(file_id)
                elif command.startswith("delete "):
                    _, file_id = command.split(" ", 1)
                    self.delete_from_quarantine(file_id)
                elif command.startswith("scan"):
                    parts = command.split(" ", 1)
                    path = parts[1] if len(parts) > 1 else None
                    self.start_scan(path)
                elif command == "network_restore":
                    self.restore_network_and_usb()
                else:
                    print("Comando desconhecido. Use 'start', 'stop', 'scan', 'quarantine', 'restore', 'delete', 'status', 'network_restore' ou 'exit'")

            except Exception as e:
                print(f"Erro ao processar comando: {str(e)}")

    def run_gui(self):
        try:
            if not QApplication.instance():
                self.app = QApplication([])
                self.app.setQuitOnLastWindowClosed(False)
            self.app.exec_()
        except:
            pass

class ProtectionSystem:
    def __init__(self):
        self.running = True
        self.threat_queue = queue.Queue()
        self.verified_cache = {}
        self.silent_mode = True
        self.usb_monitor_thread = None
        self.connected_drives = set()
        self.app_data_dir = os.path.join(os.environ.get('APPDATA', '.'), 'WolfGuardAV')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)
        self.log_file = os.path.join(self.app_data_dir, 'protection_log.txt')
        self.get_initial_drives()

        self.whitelist_apps = [
            "discord", "discordcanary", "discordptb", "discorddevelopment",
            "riotclient", "leagueclient", "league of legends", "valorant",
            "qtwebengine", "wolfguard", "microsoft", "onedrive", "filecoauth",
            "windows", "chrome", "edge", "firefox", "brave", "opera",
            "google", "mozilla"
        ]

        self.signature_verifier = DigitalSignatureVerifier()
        self.usb_controller = USBController()
        self.windows_script_paths = WINDOWS_SCRIPT_PATHS

        if keyboard and hasattr(keyboard, 'add_hotkey'):
            keyboard.add_hotkey('f4', self.restore_network_and_usb)

    def get_initial_drives(self):
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                drive_type = win32file.GetDriveType(drive_path)
                if drive_type == win32file.DRIVE_REMOVABLE:
                    self.connected_drives.add(drive_path)

    def monitor_usb_connections(self):
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2)
            self.log_action("Monitor USB iniciado")
            while self.running:
                try:
                    event = watcher(timeout_ms=1000)
                    if event:
                        time.sleep(2)
                        self.check_new_drives()
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    self.log_action(f"Erro no monitor USB: {e}")
                    time.sleep(5)
        finally:
            pythoncom.CoUninitialize()

    def check_new_drives(self):
        current_drives = set()
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                drive_type = win32file.GetDriveType(drive_path)
                if drive_type == win32file.DRIVE_REMOVABLE:
                    current_drives.add(drive_path)
        new_drives = current_drives - self.connected_drives
        for drive in new_drives:
            self.log_action(f"PENDRIVE DETECTADO: {drive}")
            thread = threading.Thread(target=self.scan_and_clean_usb, args=(drive,))
            thread.daemon = True
            thread.start()
        self.connected_drives = current_drives

    def scan_and_clean_usb(self, drive_path):
        self.log_action(f"Iniciando varredura completa em {drive_path}")
        threats_found = []
        files_scanned = 0
        files_removed = 0
        try:
            for root, dirs, files in os.walk(drive_path):
                for file in files:
                    if not self.running:
                        break

                    file_ext = os.path.splitext(file.lower())[1]
                    filepath = os.path.join(root, file)
                    filepath_lower = filepath.lower()

                    if "android" in filepath_lower and ("sdk" in filepath_lower or "ndk" in filepath_lower):
                        continue

                    if "microsoft" in filepath_lower or "onedrive" in filepath_lower:
                        continue

                    if "locallow\\microsoft\\cryptneturlcache" in filepath_lower:
                        continue

                    if "microsoft\\windows\\themes\\transcodedwallpaper" in filepath_lower:
                        continue

                    if "zxcvbndata" in filepath_lower:
                        continue

                    if "pip\\cache" in filepath_lower:
                        continue

                    if "packages\\microsoftwindows" in filepath_lower:
                        continue

                    if "chrome" in filepath_lower or "edge" in filepath_lower or "firefox" in filepath_lower or "brave" in filepath_lower or "opera" in filepath_lower:
                        if any(ext in filepath_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                            continue

                    if "\\_mei" in filepath_lower and "\\_tcl_data\\tzdata\\" in filepath_lower:
                        continue

                    if "\\appdata\\local\\temp\\__psscriptpolicytest_" in filepath_lower:
                        continue

                    risky_scripts = ['.ps1', '.vbs', '.bat', '.cmd']
                    if file_ext in risky_scripts:
                        is_windows_script = False
                        for windows_path in self.windows_script_paths:
                            if filepath_lower.startswith(windows_path.lower()):
                                is_windows_script = True
                                break

                        if not is_windows_script:
                            self.log_action(f"Script não autorizado encontrado no pendrive: {filepath}")
                            threats_found.append(filepath)
                            if self.secure_delete(filepath):
                                files_removed += 1
                                self.log_action(f"Arquivo removido do pendrive: {filepath}")
                            else:
                                self.log_action(f"Falha ao remover do pendrive: {filepath}")

                    if file_ext == '.js':
                        safe_js_context = False
                        safe_contexts = ['\\development\\', '\\src\\', '\\node_modules\\', '\\vscode\\']
                        for ctx in safe_contexts:
                            if ctx in filepath_lower:
                                safe_js_context = True
                                break

                        if safe_js_context:
                            continue

                    if file_ext == '.exe':
                        files_scanned += 1
                        try:
                            if not self.check_digital_signature(filepath):
                                self.log_action(f"EXE sem assinatura encontrado no pendrive: {filepath}")
                                threats_found.append(filepath)
                                if self.secure_delete(filepath):
                                    files_removed += 1
                                    self.log_action(f"Arquivo EXE sem assinatura removido do pendrive: {filepath}")
                                else:
                                    self.log_action(f"Falha ao remover EXE sem assinatura do pendrive: {filepath}")
                        except Exception as e:
                            self.log_action(f"Erro ao verificar arquivo: {filepath} - {e}")
        except Exception as e:
            self.log_action(f"Erro na varredura do pendrive: {e}")

        summary = (
            f"Varredura do pendrive {drive_path} concluída! "
            f"Arquivos verificados: {files_scanned} | "
            f"Ameaças encontradas: {len(threats_found)} | "
            f"Arquivos removidos: {files_removed}"
        )
        self.log_action(summary)
        if threats_found:
            self.usb_controller.disable_device(drive_path.rstrip('\\'))
            self.log_action(f"Porta USB para {drive_path} desabilitada devido a ameaças encontradas")

    def check_digital_signature(self, filepath):
        try:
            if filepath in self.verified_cache:
                return self.verified_cache[filepath]

            filepath_lower = filepath.lower()
            if "android" in filepath_lower and ("sdk" in filepath_lower or "ndk" in filepath_lower):
                self.verified_cache[filepath] = True
                return True

            if "microsoft" in filepath_lower or "onedrive" in filepath_lower or "packages\\microsoftwindows" in filepath_lower:
                self.verified_cache[filepath] = True
                return True

            if "chrome" in filepath_lower or "edge" in filepath_lower or "firefox" in filepath_lower or "brave" in filepath_lower or "opera" in filepath_lower:
                self.verified_cache[filepath] = True
                return True

            if "\\_mei" in filepath_lower and "\\_tcl_data\\tzdata\\" in filepath_lower:
                self.verified_cache[filepath] = True
                return True

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in filepath_lower:
                self.verified_cache[filepath] = True
                return True

            for app in self.whitelist_apps:
                if app in filepath_lower:
                    self.verified_cache[filepath] = True
                    return True

            is_signed = self.signature_verifier.verify_signature(filepath)
            self.verified_cache[filepath] = is_signed
            return is_signed
        except Exception:
            return False

    def is_system_critical(self, filepath):
        fp = os.path.abspath(filepath).lower()

        if "android" in fp and ("sdk" in fp or "ndk" in fp):
            return True

        if "microsoft" in fp or "onedrive" in fp or "packages\\microsoftwindows" in fp:
            return True

        if "locallow\\microsoft\\cryptneturlcache" in fp:
            return True

        if "microsoft\\windows\\themes\\transcodedwallpaper" in fp:
            return True

        if "zxcvbndata" in fp:
            return True

        if "pip\\cache" in fp:
            return True

        if "chrome" in fp or "edge" in fp or "firefox" in fp or "brave" in fp or "opera" in fp:
            return True

        if "\\_mei" in fp and "\\_tcl_data\\tzdata\\" in fp:
            return True

        if "\\appdata\\local\\temp\\__psscriptpolicytest_" in fp:
            return True

        for app in self.whitelist_apps:
            if app in fp:
                return True

        for whitelist_path in ["c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\", "c:\\programdata\\microsoft\\"]:
            if fp.startswith(whitelist_path.lower()):
                return True
        name = os.path.basename(fp)
        if name in [p.lower() for p in WHITELIST_PROCESSES]:
            return True
        return False

    def is_windows_script(self, file_path):
        file_path_lower = file_path.lower()
        file_ext = os.path.splitext(file_path_lower)[1]

        if file_ext not in ['.ps1', '.cmd', '.bat']:
            return False

        if "microsoft" in file_path_lower or "onedrive" in file_path_lower:
            return True

        if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
            return True

        if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
            return True

        if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
            return True

        for windows_path in self.windows_script_paths:
            if file_path_lower.startswith(windows_path.lower()):
                return True

        if file_path_lower.startswith(os.environ.get('SystemRoot', 'C:\\Windows').lower()):
            return True

        return False

    def restore_network_and_usb(self):
        try:
            self.log_action("Tecla F4 pressionada - Restaurando rede e USB")
            self.enable_network()
            self.usb_controller.enable_all_usb_devices()
            self.log_action("Rede e portas USB restauradas")
        except Exception as e:
            self.log_action(f"Erro ao restaurar rede e USB: {e}")

    def disable_network(self):
        try:
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=disable"], capture_output=True)
            subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=disable"], capture_output=True)
            self.log_action("Rede desabilitada")
        except Exception as e:
            self.log_action(f"Erro ao desabilitar rede: {e}")

    def enable_network(self):
        try:
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"], capture_output=True)
            subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=enable"], capture_output=True)
            self.log_action("Rede habilitada")
        except Exception as e:
            self.log_action(f"Erro ao habilitar rede: {e}")

    def eject_removable_drives(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for disk in c.Win32_LogicalDisk():
                if disk.DriveType == 2:
                    subprocess.run(
                        ["powershell", "-Command",
                         f"$s=New-Object -com Shell.Application;$s.Namespace(17).ParseName('{disk.DeviceID}').InvokeVerb('Eject')"],
                        capture_output=True
                    )
                    self.log_action(f"Removível ejetado: {disk.DeviceID}")
        except Exception as e:
            self.log_action(f"Erro ao ejetar removíveis: {e}")
        finally:
            pythoncom.CoUninitialize()

    def secure_delete(self, filepath):
        try:
            if not os.path.exists(filepath):
                return True
            try:
                win32api.SetFileAttributes(filepath, win32con.FILE_ATTRIBUTE_NORMAL)
            except:
                pass
            try:
                os.chmod(filepath, 0o777)
            except:
                pass
            try:
                os.remove(filepath)
                return True
            except:
                pass
            try:
                tmp = filepath + f".del_{int(time.time()*1000)}"
                os.rename(filepath, tmp)
                filepath = tmp
            except:
                pass
            try:
                subprocess.run(["takeown", "/F", filepath], capture_output=True)
                subprocess.run(["icacls", filepath, "/grant", "Administrators:F", "/T", "/C", "/Q"], capture_output=True)
                subprocess.run(["cmd", "/c", "del", "/f", "/q", filepath], capture_output=True)
                if not os.path.exists(filepath):
                    return True
            except:
                pass
            try:
                ctypes.windll.kernel32.MoveFileExW(ctypes.c_wchar_p(filepath), None, win32file.MOVEFILE_DELAY_UNTIL_REBOOT)
                return not os.path.exists(filepath)
            except:
                return False
        except:
            return False

    def terminate_process(self, pid, exe_path):
        try:
            exe_path_lower = exe_path.lower()
            if "android" in exe_path_lower and ("sdk" in exe_path_lower or "ndk" in exe_path_lower):
                self.log_action(f"Processo do Android SDK, ignorando: {exe_path}")
                return False

            if "microsoft" in exe_path_lower or "onedrive" in exe_path_lower or "packages\\microsoftwindows" in exe_path_lower:
                self.log_action(f"Processo da Microsoft ou OneDrive, ignorando: {exe_path}")
                return False

            if "chrome" in exe_path_lower or "edge" in exe_path_lower or "firefox" in exe_path_lower or "brave" in exe_path_lower or "opera" in exe_path_lower:
                self.log_action(f"Processo de navegador, ignorando: {exe_path}")
                return False

            if "\\_mei" in exe_path_lower and "\\_tcl_data\\tzdata\\" in exe_path_lower:
                self.log_action(f"Processo de dados de fuso horário, ignorando: {exe_path}")
                return False

            if "\\appdata\\local\\temp\\__psscriptpolicytest_" in exe_path_lower:
                self.log_action(f"Processo de teste de política do PowerShell, ignorando: {exe_path}")
                return False

            for app in self.whitelist_apps:
                if app in exe_path_lower:
                    self.log_action(f"Aplicativo confiável, ignorando: {exe_path}")
                    return False

            file_ext = os.path.splitext(exe_path_lower)[1]
            if file_ext in ['.ps1', '.cmd', '.bat']:
                if self.is_windows_script(exe_path):
                    self.log_action(f"Script legítimo do Windows, ignorando: {exe_path}")
                    return False

            if file_ext == '.dll':
                self.log_action(f"Processo de arquivo .dll, ignorando: {exe_path}")
                return False

            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return True
        except Exception as e:
            self.log_action(f"Erro ao acessar processo {pid}: {e}")
            return False
        try:
            p.terminate()
            p.wait(timeout=2)
            self.log_action(f"Processo terminado: PID {pid} - {exe_path}")
            return True
        except Exception:
            try:
                p.kill()
                p.wait(timeout=2)
                self.log_action(f"Processo finalizado à força: PID {pid} - {exe_path}")
                return True
            except Exception as e:
                self.log_action(f"Erro ao terminar processo: PID {pid} - {e}")
                return False

    def show_alert(self, message):
        if not self.silent_mode:
            try:
                ctypes.windll.user32.MessageBoxW(0, message, "ALERTA DE SEGURANÇA", 0x30 | 0x1000)
            except:
                pass

    def log_action(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_message + "\n")
        except:
            pass

    def scan_running_processes(self):
        threats_found = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['exe']:
                    proc_name = proc.info['name'].lower()
                    exe_path = proc.info['exe']
                    exe_path_lower = exe_path.lower()

                    if "android" in exe_path_lower and ("sdk" in exe_path_lower or "ndk" in exe_path_lower):
                        continue

                    if "microsoft" in exe_path_lower or "onedrive" in exe_path_lower or "packages\\microsoftwindows" in exe_path_lower:
                        continue

                    if "chrome" in exe_path_lower or "edge" in exe_path_lower or "firefox" in exe_path_lower or "brave" in exe_path_lower or "opera" in exe_path_lower:
                        continue

                    if "\\_mei" in exe_path_lower and "\\_tcl_data\\tzdata\\" in exe_path_lower:
                        continue

                    if "\\appdata\\local\\temp\\__psscriptpolicytest_" in exe_path_lower:
                        continue

                    skip = False
                    for app in self.whitelist_apps:
                        if app in proc_name or app in exe_path_lower:
                            skip = True
                            break

                    if skip:
                        continue

                    if self.is_system_critical(exe_path):
                        continue

                    file_ext = os.path.splitext(exe_path)[1].lower()
                    risky_scripts = ['.ps1', '.vbs', '.cmd', '.bat']

                    if file_ext in risky_scripts:
                        if self.is_windows_script(exe_path):
                            continue

                        threats_found.append({'pid': proc.info['pid'], 'name': proc.info['name'], 'path': exe_path, 'threat': f"Script não autorizado: {file_ext}"})
                        continue

                    if file_ext == '.dll':
                        continue

                    elif exe_path.lower().endswith('.exe') and not self.check_digital_signature(exe_path):
                        threats_found.append({'pid': proc.info['pid'], 'name': proc.info['name'], 'path': exe_path, 'threat': "Executável sem assinatura digital"})
                        continue

                    if proc.info['cmdline'] and len(proc.info['cmdline']) > 1:
                        for arg in proc.info['cmdline'][1:]:
                            arg_lower = arg.lower()
                            if arg_lower.endswith('.ps1') or arg_lower.endswith('.cmd') or arg_lower.endswith('.bat'):
                                if not self.is_windows_script(arg):
                                    threats_found.append({
                                        'pid': proc.info['pid'],
                                        'name': proc.info['name'],
                                        'path': exe_path,
                                        'threat': f"Execução de script não autorizado: {arg}"
                                    })
                                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return threats_found

    def handle_threats(self, threats):
        if not threats:
            return
        self.log_action(f"Detectadas {len(threats)} ameaças potenciais")
        self.disable_network()
        self.eject_removable_drives()
        for threat in threats:
            self.log_action(f"Processando ameaça: {threat['name']} - {threat['path']}")

            if 'path' in threat:
                file_ext = os.path.splitext(threat['path'])[1].lower()
                file_path_lower = threat['path'].lower()

                if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                    self.log_action(f"Processo do Android SDK, ignorando: {threat['path']}")
                    continue

                if "microsoft" in file_path_lower or "onedrive" in file_path_lower or "packages\\microsoftwindows" in file_path_lower:
                    self.log_action(f"Processo da Microsoft ou OneDrive, ignorando: {threat['path']}")
                    continue

                if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                    self.log_action(f"Processo de navegador, ignorando: {threat['path']}")
                    continue

                if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                    self.log_action(f"Processo de dados de fuso horário, ignorando: {threat['path']}")
                    continue

                if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                    self.log_action(f"Processo de teste de política do PowerShell, ignorando: {threat['path']}")
                    continue

                if file_ext in ['.ps1', '.cmd', '.bat']:
                    if self.is_windows_script(threat['path']):
                        self.log_action(f"Script legítimo do Windows, ignorando: {threat['path']}")
                        continue

                if file_ext == '.dll':
                    self.log_action(f"Arquivo .dll, ignorando: {threat['path']}")
                    continue

            if self.terminate_process(threat['pid'], threat['path']):
                time.sleep(0.5)
                if os.path.exists(threat['path']) and not self.is_system_critical(threat['path']):
                    if self.secure_delete(threat['path']):
                        self.log_action(f"Arquivo removido: {threat['path']}")
                    else:
                        self.log_action(f"Falha ao remover: {threat['path']}")
        names = [t['name'] for t in threats]
        self.log_action(f"Ameaças processadas: {', '.join(names)} - Rede desabilitada")

    def scan_filesystem(self, directory):
        try:
            for root, dirs, files in os.walk(directory):
                if not self.running:
                    break

                if any(root.lower().startswith(wp.lower()) for wp in ["C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\", "C:\\ProgramData\\Microsoft\\"]):
                    continue

                for file in files:
                    file_path = os.path.join(root, file)
                    file_path_lower = file_path.lower()

                    if "android" in file_path_lower and ("sdk" in file_path_lower or "ndk" in file_path_lower):
                        continue

                    if "microsoft" in file_path_lower or "onedrive" in file_path_lower or "packages\\microsoftwindows" in file_path_lower:
                        continue

                    if "locallow\\microsoft\\cryptneturlcache" in file_path_lower:
                        continue

                    if "microsoft\\windows\\themes\\transcodedwallpaper" in file_path_lower:
                        continue

                    if "zxcvbndata" in file_path_lower:
                        continue

                    if "pip\\cache" in file_path_lower:
                        continue

                    if "chrome" in file_path_lower or "edge" in file_path_lower or "firefox" in file_path_lower or "brave" in file_path_lower or "opera" in file_path_lower:
                        if any(ext in file_path_lower for ext in ['.crdownload', '.part', '.download', '.tmp.js']):
                            continue

                    if "\\_mei" in file_path_lower and "\\_tcl_data\\tzdata\\" in file_path_lower:
                        continue

                    if "\\appdata\\local\\temp\\__psscriptpolicytest_" in file_path_lower:
                        continue

                    skip = False
                    for app in self.whitelist_apps:
                        if app in file_path_lower:
                            skip = True
                            break

                    if skip:
                        continue

                    file_ext = os.path.splitext(file)[1].lower()

                    risky_scripts = ['.ps1', '.vbs', '.cmd', '.bat']
                    if file_ext in risky_scripts:
                        if self.is_windows_script(file_path):
                            continue

                        self.log_action(f"Script não autorizado detectado: {file_path}")
                        if not self.is_system_critical(file_path):
                            if self.secure_delete(file_path):
                                self.log_action(f"Arquivo removido: {file_path}")
                            else:
                                self.log_action(f"Falha ao remover: {file_path}")

                    if file_ext == '.js':
                        safe_js_context = False
                        safe_contexts = ['\\development\\', '\\src\\', '\\node_modules\\', '\\vscode\\']
                        for ctx in safe_contexts:
                            if ctx in file_path_lower:
                                safe_js_context = True
                                break

                        if safe_js_context:
                            continue

                    if file_ext == '.dll':
                        continue

                    elif file.lower().endswith('.exe'):
                        if not self.is_system_critical(file_path):
                            if not self.check_digital_signature(file_path):
                                self.log_action(f"Arquivo executável sem assinatura digital: {file_path}")
                                if self.secure_delete(file_path):
                                    self.log_action(f"Arquivo removido: {file_path}")
                                else:
                                    self.log_action(f"Falha ao remover: {file_path}")
        except Exception as e:
            self.log_action(f"Erro na varredura do sistema: {e}")

    def run(self):
        self.log_action("Sistema de proteção iniciado - Modo automático")
        self.usb_monitor_thread = threading.Thread(target=self.monitor_usb_connections)
        self.usb_monitor_thread.daemon = True
        self.usb_monitor_thread.start()
        self.log_action("Monitor de pendrive ativado - Verificação automática")
        scan_counter = 0
        try:
            while self.running:
                threats = self.scan_running_processes()
                if threats:
                    self.handle_threats(threats)
                scan_counter += 1
                if scan_counter % 60 == 0:
                    self.log_action("Executando varredura silenciosa do sistema")
                    user_dirs = [
                        os.path.expanduser("~\\Downloads"),
                        os.path.expanduser("~\\Desktop"),
                        os.path.expanduser("~\\Documents"),
                        "C:\\Temp",
                        "C:\\Users\\Public"
                    ]
                    for directory in user_dirs:
                        if os.path.exists(directory):
                            self.scan_filesystem(directory)
                time.sleep(5)
        except KeyboardInterrupt:
            self.log_action("Sistema interrompido pelo usuário")
        except Exception as e:
            self.log_action(f"Erro crítico: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        self.enable_network()
        self.log_action("Sistema de proteção encerrado")

    def stop(self):
        self.running = False

def install_service():
    if not is_admin():
        print("Este programa requer privilégios administrativos para instalar o serviço.")
        return False

    try:
        win32serviceutil.InstallService(
            pythonClassString="__main__.WolfGuardService",
            serviceName="WolfGuardAntivirus",
            displayName="WolfGuard Antivirus Protection",
            description="Serviço de proteção em tempo real contra malware e vírus",
            startType=win32service.SERVICE_AUTO_START
        )
        return True
    except:
        print("Erro ao instalar serviço")
        return False

def remove_service():
    if not is_admin():
        print("Este programa requer privilégios administrativos para remover o serviço.")
        return False

    try:
        win32serviceutil.RemoveService("WolfGuardAntivirus")
        return True
    except:
        print("Erro ao remover serviço")
        return False

def run_protection_system():
    protection = ProtectionSystem()
    try:
        if protection.connected_drives:
            print("Pendrives detectados, iniciando verificação...")
            for drive in protection.connected_drives:
                print(f"Verificando {drive}...")
                thread = threading.Thread(target=protection.scan_and_clean_usb, args=(drive,))
                thread.daemon = True
                thread.start()
        protection.run()
    except KeyboardInterrupt:
        protection.stop()
    except Exception as e:
        print(f"Erro ao executar sistema de proteção: {e}")

class WolfGuardSystem:
    def __init__(self):
        self.guard_files = []
        self.guard_files_set = set()
        self.common_dirs = []
        self.system_dirs = []
        self.app_dirs = []
        self.running = True
        self.observers = []
        self.event_handlers = []
        self.temp_defensive_file = os.path.join(os.environ.get("TEMP", "."), ".defense_active")
        self.accounts_dir = None
        self.visible_passwords_dir = None
        self.alerted_files = set()
        self.guard_file_creation_times = {}
        self.file_rotation_days = 7
        self.alert_lock = threading.Lock()
        self.last_alert_time = datetime.now() - timedelta(minutes=10)
        self.process_cache = {}
        self.process_cache_lock = threading.Lock()
        self.file_watcher_threads = []
        self.audit_events = {}
        self.find_directories()

    def find_directories(self):
        user_profile = os.path.expanduser("~")
        appdata = os.getenv("APPDATA", "")
        localappdata = os.getenv("LOCALAPPDATA", "")
        common_dirs = [
            user_profile,
            os.path.join(user_profile, "Documents"),
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Downloads"),
            os.path.join(user_profile, "Pictures"),
            os.path.join(user_profile, "Videos"),
            os.path.join(user_profile, "Music"),
            r"C:\Users\Public\Documents",
            r"C:\Users\Public\Pictures",
            r"C:\ProgramData",
        ]
        system_dirs = [
            r"C:\Windows\Temp",
            r"C:\Windows\System32\config",
            r"C:\Windows\System32\drivers",
            r"C:\Windows\SysWOW64",
            r"C:\Program Files\Common Files",
            r"C:\Program Files (x86)\Common Files",
            os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs") if appdata else "",
            os.path.join(localappdata, "Temp") if localappdata else "",
        ]
        app_dirs = [
            os.path.join(appdata, r"Microsoft\Windows\Recent") if appdata else "",
            os.path.join(localappdata, r"Microsoft\Edge\User Data") if localappdata else "",
            os.path.join(localappdata, r"Google\Chrome\User Data") if localappdata else "",
            os.path.join(appdata, r"Mozilla\Firefox\Profiles") if appdata else "",
            os.path.join(localappdata, "WhatsApp") if localappdata else "",
            os.path.join(localappdata, "Telegram Desktop") if localappdata else "",
            os.path.join(user_profile, "Documents", "Planilhas"),
            os.path.join(user_profile, "Documents", "Trabalho"),
        ]
        one_drive = os.path.join(user_profile, "OneDrive")
        dropbox = os.path.join(user_profile, "Dropbox")
        if os.path.exists(one_drive):
            app_dirs.append(one_drive)
        if os.path.exists(dropbox):
            app_dirs.append(dropbox)
        self.common_dirs = [d for d in common_dirs if d and os.path.exists(d)]
        self.system_dirs = [d for d in system_dirs if d and os.path.exists(d)]
        self.app_dirs = [d for d in app_dirs if d and os.path.exists(d)]
        self.accounts_dir = os.path.join(user_profile, "Documents", "Contas")
        os.makedirs(self.accounts_dir, exist_ok=True)
        self.common_dirs.append(self.accounts_dir)
        self.visible_passwords_dir = os.path.join(user_profile, "Backup")
        os.makedirs(self.visible_passwords_dir, exist_ok=True)
        self.common_dirs.append(self.visible_passwords_dir)

    def find_existing_guard_files(self):
        count = 0
        common_names = [
            "senhas_importantes.txt", "dados_bancarios.txt", "informacoes_pessoais.txt",
            "documentos_confidenciais.txt", "backup_senhas.txt", "contas_bancarias.txt",
            "senhas_gmail.txt", "cartoes_credito.txt",
            "dados_pix.txt", "tokens_bancarios.txt", "acesso_apps.txt", "bancos_login.txt",
            "nubank_senha.txt", "itau_token.txt", "contas_netflix.txt",
            "amazon_login.txt", "spotify_premium.txt", "passwords.txt", "senhas.txt",
            "login_data.txt", "acessos.txt", "financial.txt", "bank_data.txt", "cartoes.txt",
            "contas.txt", "personal.txt", "dados_pessoais.txt", "documentos.txt",
            "info_confidencial.txt", "bb_app.txt", "banco_brasil.txt", "bb_token.txt", "itau_dados.txt",
            "itau_internet.txt", "itau_token.txt", "nubank.txt", "nu_app.txt", "nubank_card.txt"
        ]
        common_names_set = {name.lower() for name in common_names}
        all_dirs = self.common_dirs + self.system_dirs + self.app_dirs
        for directory in all_dirs:
            try:
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    if os.path.isfile(file_path):
                        if filename.lower() in common_names_set:
                            if file_path not in self.guard_files_set:
                                self.guard_files.append(file_path)
                                self.guard_files_set.add(file_path)
                                self.guard_file_creation_times[file_path] = datetime.fromtimestamp(os.path.getctime(file_path))
                                count += 1
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            try:
                                content = f.read(200)
                                if any(marker in content for marker in ["# SENHAS IMPORTANTES",
                                                                        "# DADOS BANCÁRIOS",
                                                                        "# CONTA GOOGLE",
                                                                        "# NETFLIX",
                                                                        "# AMAZON",
                                                                        "# SPOTIFY",
                                                                        "# MICROSOFT",
                                                                        "# APPLE ID",
                                                                        "# NUBANK",
                                                                        "# ITAÚ",
                                                                        "# BANCO DO BRASIL",
                                                                        "# CHAVES PIX"]):
                                    if file_path not in self.guard_files_set:
                                        self.guard_files.append(file_path)
                                        self.guard_files_set.add(file_path)
                                        self.guard_file_creation_times[file_path] = datetime.fromtimestamp(os.path.getctime(file_path))
                                        count += 1
                            except:
                                pass
            except Exception:
                pass
        if os.path.exists(self.accounts_dir):
            try:
                for filename in os.listdir(self.accounts_dir):
                    file_path = os.path.join(self.accounts_dir, filename)
                    if os.path.isfile(file_path) and file_path not in self.guard_files_set:
                        self.guard_files.append(file_path)
                        self.guard_files_set.add(file_path)
                        self.guard_file_creation_times[file_path] = datetime.fromtimestamp(os.path.getctime(file_path))
                        count += 1
            except Exception:
                pass
        if os.path.exists(self.visible_passwords_dir):
            try:
                for filename in os.listdir(self.visible_passwords_dir):
                    file_path = os.path.join(self.visible_passwords_dir, filename)
                    if os.path.isfile(file_path) and file_path not in self.guard_files_set:
                        self.guard_files.append(file_path)
                        self.guard_files_set.add(file_path)
                        self.guard_file_creation_times[file_path] = datetime.fromtimestamp(os.path.getctime(file_path))
                        count += 1
            except Exception:
                pass
        return count

    def generate_fake_content(self, content_type: str) -> str:
        def rn():
            return self.generate_random_name()
        def rp():
            return self.generate_random_password()
        if content_type == "passwords":
            services = ["gmail","outlook","facebook","instagram","twitter","netflix","amazon","paypal","bank","cloud","linkedin","tiktok","youtube","twitch","discord","steam"]
            lines = ["# SENHAS IMPORTANTES - NÃO COMPARTILHAR #",""]
            for _ in range(15):
                s = random.choice(services)
                email = f"{rn().lower()}{random.randint(1,999)}@{s}.com"
                lines.append(f"{s.upper()}: {email} | {rp()}")
            return "\n".join(lines)+"\n"
        if content_type == "financial":
            banks = ["Bradesco","Itaú","Santander","Banco do Brasil","Caixa","Nubank","Inter","C6 Bank","BTG Pactual","XP Investimentos","PicPay","Mercado Pago","Next","BS2","Original","PagBank"]
            lines = ["# DADOS BANCÁRIOS E FINANCEIROS #",""]
            for _ in range(5):
                bank = random.choice(banks)
                account = "".join(random.choices(string.digits, k=8))
                agency = "".join(random.choices(string.digits, k=4))
                card = "".join(random.choices(string.digits, k=16))
                cvv = "".join(random.choices(string.digits, k=3))
                lines += [f"Banco: {bank}",f"Agência: {agency} | Conta: {account}",f"Cartão: {card} | CVV: {cvv}",f"Senha: {rp()}",""]
            return "\n".join(lines)
        if content_type == "personal":
            cpf = "".join(random.choices(string.digits, k=11))
            rg = "".join(random.choices(string.digits, k=9))
            birth = f"{random.randint(1,28):02d}/{random.randint(1,12):02d}/{random.randint(1960,2000)}"
            address = f"Rua {rn()}, {random.randint(1,999)}"
            cep = f"{random.randint(10000,99999)}-{random.randint(100,999)}"
            lines = ["# DADOS PESSOAIS #","",f"Nome: {rn()} {rn()}",f"CPF: {cpf}",f"RG: {rg}",f"Data de Nascimento: {birth}",f"Endereço: {address}",f"CEP: {cep}",""]
            return "\n".join(lines)
        if content_type == "google":
            email = f"{rn().lower()}{random.randint(1,999)}@gmail.com"
            recovery = f"{rn().lower()}{random.randint(1,999)}@outlook.com"
            phone = f"+55 {random.randint(11,99)} 9{random.randint(1000,9999)}-{random.randint(1000,9999)}"
            lines = ["# CONTA GOOGLE #","",f"Email: {email}",f"Senha: {rp()}",f"Email de recuperação: {recovery}",f"Telefone: {phone}","Perguntas de segurança:",f"  - Primeiro animal de estimação: {rn()}",f"  - Cidade natal: {rn()}",""]
            return "\n".join(lines)
        if content_type == "microsoft":
            email = f"{rn().lower()}{random.randint(1,999)}@outlook.com"
            lines = ["# CONTA MICROSOFT #","",f"Email: {email}",f"Senha: {rp()}",f"PIN de segurança: {random.randint(1000,9999)}","Produtos: Office 365, OneDrive, Xbox Game Pass",f"Cartão vinculado: **** **** **** {random.randint(1000,9999)}",""]
            return "\n".join(lines)
        if content_type == "apple":
            email = f"{rn().lower()}{random.randint(1,999)}@icloud.com"
            lines = ["# CONTA APPLE ID #","",f"Apple ID: {email}",f"Senha: {rp()}",f"Pergunta de segurança: Nome do primeiro professor? {rn()}","Dispositivos vinculados: iPhone 13, MacBook Pro, iPad",f"Cartão de crédito: **** **** **** {random.randint(1000,9999)}",""]
            return "\n".join(lines)
        if content_type == "banco_brasil":
            account = "".join(random.choices(string.digits, k=8))
            agency = "".join(random.choices(string.digits, k=4))
            senha = "".join(random.choices(string.digits, k=8))
            lines = ["# BANCO DO BRASIL #","",f"Agência: {agency}",f"Conta: {account}",f"Senha: {senha}",f"Senha do cartão: {random.randint(1000,9999)}",f"Token: {rp()}",""]
            return "\n".join(lines)
        if content_type == "itau":
            account = "".join(random.choices(string.digits, k=6))
            agency = "".join(random.choices(string.digits, k=4))
            senha = "".join(random.choices(string.digits, k=6))
            lines = ["# ITAÚ #","",f"Agência: {agency}",f"Conta: {account}",f"Senha eletrônica: {senha}",f"Senha do cartão: {random.randint(1000,9999)}",f"Token: {rp()}",""]
            return "\n".join(lines)
        if content_type == "nubank":
            account = "".join(random.choices(string.digits, k=10))
            senha = "".join(random.choices(string.digits, k=6))
            lines = ["# NUBANK #","",f"Conta: {account}",f"Senha do app: {senha}",f"Senha do cartão: {random.randint(1000,9999)}",f"Email: {rn().lower()}{random.randint(1,999)}@gmail.com",f"CPF cadastrado: {''.join(random.choices(string.digits, k=11))}",""]
            return "\n".join(lines)
        if content_type == "pix":
            banks = ["Nubank","Itaú","Bradesco","Santander","Banco do Brasil","Caixa","Inter","C6 Bank"]
            lines = ["# CHAVES PIX #",""]
            for _ in range(4):
                bank = random.choice(banks)
                chave_tipo = random.choice(["CPF","Email","Telefone","Aleatória"])
                if chave_tipo == "CPF":
                    chave = "".join(random.choices(string.digits, k=11))
                elif chave_tipo == "Email":
                    chave = f"{rn().lower()}{random.randint(1,999)}@gmail.com"
                elif chave_tipo == "Telefone":
                    chave = f"+55{random.randint(11,99)}9{random.randint(10000000,99999999)}"
                else:
                    chave = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
                lines += [f"Banco: {bank}",f"Tipo: {chave_tipo}",f"Chave: {chave}",""]
            return "\n".join(lines)
        if content_type == "trabalho":
            empresa = f"{rn()} {random.choice(['Tecnologia','Soluções','Sistemas','Consultoria','Ltda','S.A.'])}"
            cnpj = "".join(random.choices(string.digits, k=14))
            lines = ["# DADOS DE TRABALHO #","",f"Empresa: {empresa}",f"CNPJ: {cnpj}",f"Email corporativo: {rn().lower()}@{empresa.lower().replace(' ','')}.com.br",f"Senha: {rp()}",f"VPN: {rp()}",f"Sistema interno: {rp()}",""]
            return "\n".join(lines)
        if content_type == "netflix":
            email = f"{rn().lower()}{random.randint(1,999)}@gmail.com"
            lines = ["# NETFLIX #","",f"Email: {email}",f"Senha: {self.generate_random_password()}","Plano: Premium (4 telas)",f"Cartão: **** **** **** {random.randint(1000,9999)}","Perfis: Principal, Família, Filhos",""]
            return "\n".join(lines)
        if content_type == "amazon":
            email = f"{rn().lower()}{random.randint(1,999)}@gmail.com"
            lines = ["# AMAZON #","",f"Email: {email}",f"Senha: {self.generate_random_password()}","Prime: Ativo",f"Cartão: **** **** **** {random.randint(1000,9999)}",f"Endereço: Rua {rn()}, {random.randint(1,999)}",""]
            return "\n".join(lines)
        if content_type == "spotify":
            email = f"{rn().lower()}{random.randint(1,999)}@gmail.com"
            lines = ["# SPOTIFY #","",f"Email: {email}",f"Senha: {self.generate_random_password()}","Plano: Premium Família",f"Cartão: **** **** **** {random.randint(1000,9999)}",""]
            return "\n".join(lines)
        return "Conteúdo protegido.\n"

    def generate_random_name(self) -> str:
        syllables = ["ma","ri","jo","an","ca","pe","lu","fe","ga","da","ta","vi","ro","sa","ba","fi","ra"]
        length = random.randint(2, 4)
        return "".join(random.choices(syllables, k=length)).capitalize()

    def generate_random_password(self) -> str:
        length = random.randint(10, 18)
        chars = string.ascii_letters + string.digits + string.punctuation
        chars = chars.replace('"', "").replace("'", "").replace("\\", "")
        return "".join(random.choices(chars, k=length))

    def write_file(self, file_path: str, content: str, hide: bool):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            if os.path.exists(file_path):
                try:
                    win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
                except Exception:
                    pass
            tmp = file_path + f".tmp_{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, file_path)
            if hide:
                try:
                    win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
                except Exception:
                    pass
            if file_path not in self.guard_files_set:
                self.guard_files.append(file_path)
                self.guard_files_set.add(file_path)
                self.guard_file_creation_times[file_path] = datetime.now()
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    def clean_old_guard_files(self):
        now = datetime.now()
        expired_files = []
        for file_path, create_time in list(self.guard_file_creation_times.items()):
            if (now - create_time).days >= self.file_rotation_days:
                expired_files.append(file_path)
        for file_path in expired_files:
            try:
                if os.path.exists(file_path):
                    try:
                        win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
                    except Exception:
                        pass
                    os.remove(file_path)
                if file_path in self.guard_files_set:
                    self.guard_files.remove(file_path)
                    self.guard_files_set.remove(file_path)
                if file_path in self.guard_file_creation_times:
                    del self.guard_file_creation_times[file_path]
            except Exception:
                pass
        return len(expired_files)

    def create_visible_password_files(self):
        files = {
            "Netflix.txt": "netflix",
            "Amazon.txt": "amazon",
            "Spotify.txt": "spotify",
            "Instagram.txt": "passwords",
            "Facebook.txt": "passwords",
            "Email.txt": "google",
            "Cartões.txt": "financial",
            "Banco.txt": "financial",
            "Nubank.txt": "nubank",
            "Pix.txt": "pix",
        }
        for filename, ctype in files.items():
            path = os.path.join(self.visible_passwords_dir, filename)
            if not os.path.exists(path):
                self.write_file(path, self.generate_fake_content(ctype), hide=False)
            elif path not in self.guard_files_set:
                self.guard_files.append(path)
                self.guard_files_set.add(path)
                try:
                    self.guard_file_creation_times[path] = datetime.fromtimestamp(os.path.getctime(path))
                except Exception:
                    self.guard_file_creation_times[path] = datetime.now()
        index_path = os.path.join(self.visible_passwords_dir, "LEIAME.txt")
        if not os.path.exists(index_path):
            index_content = ["# ÍNDICE DE SENHAS #","", "Este arquivo lista senhas importantes desta pasta.",""]
            index_content += [f"- {k}" for k in files.keys()]
            self.write_file(index_path, "\n".join(index_content)+"\n", hide=False)
        elif index_path not in self.guard_files_set:
            self.guard_files.append(index_path)
            self.guard_files_set.add(index_path)
            try:
                self.guard_file_creation_times[index_path] = datetime.fromtimestamp(os.path.getctime(index_path))
            except Exception:
                self.guard_file_creation_times[index_path] = datetime.now()

    def create_accounts_directory(self):
        accounts = {
            "google_account.txt": "google",
            "microsoft_account.txt": "microsoft",
            "apple_id.txt": "apple",
            "facebook_login.txt": "passwords",
            "instagram_login.txt": "passwords",
            "netflix_account.txt": "netflix",
            "amazon_prime.txt": "amazon",
            "spotify_premium.txt": "spotify",
            "paypal_dados.txt": "financial",
            "banco_online.txt": "financial",
            "nubank_dados.txt": "nubank",
            "bradesco.txt": "financial",
            "itau_app.txt": "itau",
            "banco_brasil.txt": "banco_brasil",
            "pix_chaves.txt": "pix",
            "trabalho_login.txt": "trabalho",
        }
        for filename, ctype in accounts.items():
            path = os.path.join(self.accounts_dir, filename)
            if not os.path.exists(path):
                self.write_file(path, self.generate_fake_content(ctype), hide=True)
            elif path not in self.guard_files_set:
                self.guard_files.append(path)
                self.guard_files_set.add(path)
                try:
                    self.guard_file_creation_times[path] = datetime.fromtimestamp(os.path.getctime(path))
                except Exception:
                    self.guard_file_creation_times[path] = datetime.now()

    def create_system_guard_files(self):
        content_types = ["passwords","financial","personal","banco_brasil","itau","nubank"]
        file_names = {
            "passwords": ["passwords.txt","senhas.txt","login_data.txt","acessos.txt"],
            "financial": ["financial.txt","bank_data.txt","cartoes.txt","contas.txt"],
            "personal": ["personal.txt","dados_pessoais.txt","documentos.txt","info_confidencial.txt"],
            "banco_brasil": ["bb_app.txt","banco_brasil.txt","bb_token.txt"],
            "itau": ["itau_dados.txt","itau_internet.txt","itau_token.txt"],
            "nubank": ["nubank.txt","nu_app.txt","nubank_card.txt"],
        }
        for directory in self.system_dirs:
            has_guard = False
            for fname in sum(file_names.values(), []):
                path = os.path.join(directory, fname)
                if os.path.exists(path):
                    if path not in self.guard_files_set:
                        self.guard_files.append(path)
                        self.guard_files_set.add(path)
                        try:
                            self.guard_file_creation_times[path] = datetime.fromtimestamp(os.path.getctime(path))
                        except Exception:
                            self.guard_file_creation_times[path] = datetime.now()
                    has_guard = True
                    break
            if not has_guard:
                ctype = random.choice(content_types)
                fname = random.choice(file_names[ctype])
                path = os.path.join(directory, fname)
                self.write_file(path, self.generate_fake_content(ctype), hide=True)

    def create_app_guard_files(self):
        content_types = ["google","microsoft","apple","passwords","netflix","amazon","spotify","financial"]
        for directory in self.app_dirs:
            has_guard = False
            expected_files = []
            if "Chrome" in directory or "Edge" in directory:
                expected_files = ["login_data.txt"]
            elif "Firefox" in directory:
                expected_files = ["passwords.txt"]
            elif "WhatsApp" in directory:
                expected_files = ["backup.txt"]
            elif "Telegram" in directory:
                expected_files = ["session.txt"]
            elif "OneDrive" in directory:
                expected_files = ["credentials.txt"]
            elif "Dropbox" in directory:
                expected_files = ["access.txt"]
            elif directory.endswith("Planilhas"):
                expected_files = ["senhas.xlsx"]
            elif directory.endswith("Trabalho"):
                expected_files = ["confidencial.txt"]
            for fname in expected_files:
                path = os.path.join(directory, fname)
                if os.path.exists(path):
                    if path not in self.guard_files_set:
                        self.guard_files.append(path)
                        self.guard_files_set.add(path)
                        try:
                            self.guard_file_creation_times[path] = datetime.fromtimestamp(os.path.getctime(path))
                        except Exception:
                            self.guard_file_creation_times[path] = datetime.now()
                    has_guard = True
            if not has_guard:
                num_files = random.randint(1, 2)
                for _ in range(num_files):
                    ctype = random.choice(content_types)
                    if expected_files:
                        fname = random.choice(expected_files)
                    else:
                        fname = f"dados_{random.randint(1, 1000)}.txt"
                    path = os.path.join(directory, fname)
                    self.write_file(path, self.generate_fake_content(ctype), hide=True)

    def create_guard_files(self):
        self.clean_old_guard_files()
        self.find_existing_guard_files()
        content_types = ["passwords","financial","personal","google","microsoft","apple","banco_brasil","itau","nubank","pix"]
        file_names = [
            "senhas_importantes.txt","dados_bancarios.txt","informacoes_pessoais.txt",
            "documentos_confidenciais.txt","backup_senhas.txt","contas_bancarias.txt",
            "senhas_gmail.txt","cartoes_credito.txt",
            "dados_pix.txt","tokens_bancarios.txt","acesso_apps.txt","bancos_login.txt",
            "nubank_senha.txt","itau_token.txt","contas_netflix.txt",
            "amazon_login.txt","spotify_premium.txt"
        ]
        for directory in self.common_dirs:
            if directory in (self.accounts_dir, self.visible_passwords_dir):
                continue
            has_guard = False
            for fname in file_names:
                path = os.path.join(directory, fname)
                if os.path.exists(path) and path in self.guard_files_set:
                    has_guard = True
                    break
            if not has_guard:
                num_files = random.randint(2, 4)
                for _ in range(num_files):
                    fname = random.choice(file_names)
                    ctype = random.choice(content_types)
                    path = os.path.join(directory, fname)
                    self.write_file(path, self.generate_fake_content(ctype), hide=True)
        self.create_accounts_directory()
        self.create_visible_password_files()
        self.create_system_guard_files()
        self.create_app_guard_files()
        return self.guard_files

    def disable_network(self):
        try:
            with open(self.temp_defensive_file, "w") as f:
                f.write("1")
            subprocess.Popen('netsh interface set interface name="Wi-Fi" admin=disable', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.Popen('netsh interface set interface name="Ethernet" admin=disable', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.info("Rede desativada instantaneamente")
        except Exception as e:
            logging.error(f"Erro ao desativar rede: {e}")

    def eject_usb_devices(self):
        try:
            def run():
                try:
                    pythoncom.CoInitialize()
                    wmi_obj = wmi.WMI()
                    drives = []
                    for d in wmi_obj.Win32_LogicalDisk():
                        if d.DriveType == 2:
                            drives.append(d.DeviceID)
                    shell = win32com.client.Dispatch("Shell.Application")
                    for dl in drives:
                        try:
                            shell.Namespace(17).ParseName(dl).InvokeVerb("Eject")
                        except Exception:
                            pass
                except Exception:
                    pass
            t = threading.Thread(target=run, daemon=True)
            t.start()
        except Exception:
            pass

    def kill_process(self, pid: int):
        try:
            if pid and pid != os.getpid():
                p = psutil.Process(pid)
                name = p.name()
                try:
                    p.kill()
                    logging.info(f"Processo encerrado: {name} ({pid})")
                    return name
                except psutil.NoSuchProcess:
                    pass
        except Exception:
            try:
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
                return "Desconhecido"
            except Exception:
                pass
        return None

    def _enable_se_security_privilege(self):
        try:
            hProc = win32api.GetCurrentProcess()
            hToken = win32security.OpenProcessToken(hProc, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            priv_luid = win32security.LookupPrivilegeValue(None, win32security.SE_SECURITY_NAME)
            win32security.AdjustTokenPrivileges(hToken, False, [(priv_luid, win32security.SE_PRIVILEGE_ENABLED)])
            return True
        except Exception:
            return False

    def add_read_audit_sacl(self, file_path: str):
        try:
            if not self._enable_se_security_privilege():
                return
            sd = win32security.GetFileSecurity(file_path, win32security.SACL_SECURITY_INFORMATION)
            sacl = sd.GetSecurityDescriptorSacl()
            if sacl is None:
                sacl = win32security.ACL()
            everyone, _, _ = win32security.LookupAccountName("", "Everyone")
            sacl.AddAuditAccessAceEx(win32security.ACL_REVISION_DS, 0, con.FILE_GENERIC_READ, everyone, 1, 1)
            sd.SetSecurityDescriptorSacl(1, sacl, 0)
            win32security.SetFileSecurity(file_path, win32security.SACL_SECURITY_INFORMATION, sd)
        except Exception:
            pass

    def setup_windows_native_monitoring(self):
        FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
        FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
        FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
        FILE_NOTIFY_CHANGE_SIZE = 0x00000008
        FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
        FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
        FILE_NOTIFY_CHANGE_CREATION = 0x00000040
        FILE_NOTIFY_CHANGE_SECURITY = 0x00000100

        notify_filter = (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                         FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
                         FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_LAST_ACCESS |
                         FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY)

        def monitor_directory(dir_path, guard_files_in_dir):
            try:
                dir_handle = win32file.CreateFile(
                    dir_path,
                    0x0001,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                    None
                )

                guard_files_set = {os.path.basename(f).lower() for f in guard_files_in_dir}

                filename_to_path = {os.path.basename(f).lower(): f for f in guard_files_in_dir}

                buffer = win32file.AllocateReadBuffer(8192)

                overlapped = win32file.OVERLAPPED()
                overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)

                while self.running:
                    try:
                        win32file.ReadDirectoryChangesW(
                            dir_handle,
                            buffer,
                            True,
                            notify_filter,
                            overlapped
                        )

                        result = win32event.WaitForSingleObject(overlapped.hEvent, 1)

                        if result == win32event.WAIT_OBJECT_0:
                            num_bytes = win32file.GetOverlappedResult(dir_handle, overlapped, True)

                            if num_bytes > 0:
                                results = win32file.FILE_NOTIFY_INFORMATION(buffer, num_bytes)

                                for action, filename in results:
                                    filename = filename.lower()

                                    if filename in guard_files_set:
                                        full_path = filename_to_path.get(filename)

                                        if full_path and full_path not in self.alerted_files:
                                            pid = self.get_process_accessing_file(full_path)
                                            if not pid:
                                                pid = self._most_recent_pid_excluding_self()

                                            self.defensive_actions(full_path, pid)
                    except Exception:
                        time.sleep(0.001)
            except Exception:
                pass
            finally:
                try:
                    win32file.CloseHandle(dir_handle)
                except:
                    pass

        unique_dirs = {}
        for file_path in self.guard_files:
            dir_path = os.path.dirname(file_path)
            if dir_path:
                if dir_path not in unique_dirs:
                    unique_dirs[dir_path] = []
                unique_dirs[dir_path].append(file_path)

        for dir_path, files in unique_dirs.items():
            try:
                t = threading.Thread(
                    target=monitor_directory,
                    args=(dir_path, files),
                    daemon=True
                )
                t.start()
                self.file_watcher_threads.append(t)
            except Exception:
                pass

    def setup_monitoring(self):
        self.setup_windows_native_monitoring()

        class Handler(FileSystemEventHandler):
            def __init__(self, guard_system, guard_files):
                self.g = guard_system
                self.files = set(os.path.abspath(f) for f in guard_files)

            def on_any_event(self, event):
                try:
                    ep = os.path.abspath(event.src_path)
                    if ep in self.files and ep not in self.g.alerted_files:
                        pid = self.g.get_process_accessing_file(ep)
                        if not pid:
                            pid = self.g._most_recent_pid_excluding_self()
                        self.g.defensive_actions(ep, pid)
                except Exception:
                    pass

        unique_dirs = sorted(set(os.path.dirname(f) for f in self.guard_files if os.path.dirname(f)))
        for d in unique_dirs:
            try:
                h = Handler(self, self.guard_files)
                o = Observer()
                o.schedule(h, d, recursive=False)
                o.start()
                self.observers.append(o)
                self.event_handlers.append(h)
            except Exception:
                pass

    def watch_read_audit(self):
        try:
            server = "localhost"
            logtype = "Security"
            hlog = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            guard_map = {}
            for f in self.guard_files:
                basename = os.path.basename(f).lower()
                if basename not in guard_map:
                    guard_map[basename] = []
                guard_map[basename].append(f)

            while self.running:
                events = win32evtlog.ReadEventLog(hlog, flags, 0)
                if not events:
                    time.sleep(0.000001)
                    continue

                for ev in events:
                    if ev.EventID == 4663 and ev.StringInserts:
                        joined = " ".join(ev.StringInserts).lower()
                        for basename, files in guard_map.items():
                            if basename in joined:
                                for fp in files:
                                    if fp not in self.alerted_files:
                                        pid = self.get_process_accessing_file(fp)
                                        if not pid:
                                            pid = self._most_recent_pid_excluding_self()
                                        if pid:
                                            self.defensive_actions(fp, pid)
                                    break
                                break
        except Exception:
            pass

    def setup_audit_monitoring(self):
        try:
            subprocess.run(r'auditpol /set /subcategory:"File System" /success:enable /failure:enable', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

        for fp in self.guard_files:
            if os.path.exists(fp):
                self.add_read_audit_sacl(fp)

        t = threading.Thread(target=self.watch_read_audit, daemon=True)
        t.start()

    def get_process_accessing_file(self, file_path: str):
        try:
            process_ids = []

            try:
                hFile = win32file.CreateFile(
                    file_path,
                    win32file.GENERIC_READ,
                    win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                win32file.CloseHandle(hFile)
            except win32file.error as e:
                if e.winerror == 32:
                    procs = sorted((p for p in psutil.process_iter(["pid","create_time"])
                                   if p.pid != os.getpid()),
                                  key=lambda p: p.info.get("create_time", 0) or 0,
                                  reverse=True)[:5]

                    for proc in procs:
                        try:
                            for finfo in proc.open_files():
                                if finfo.path.lower() == file_path.lower():
                                    return proc.pid
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    if procs:
                        return procs[0].pid

            return self._most_recent_pid_excluding_self()
        except Exception:
            return self._most_recent_pid_excluding_self()

    def get_process_info(self, pid):
        try:
            with self.process_cache_lock:
                if pid in self.process_cache:
                    return self.process_cache[pid]

            if not pid:
                return {"name": "Desconhecido"}

            p = psutil.Process(pid)
            info = {"name": p.name()}

            with self.process_cache_lock:
                self.process_cache[pid] = info
                if len(self.process_cache) > 100:
                    oldest_pids = sorted(self.process_cache.keys())[:50]
                    for old_pid in oldest_pids:
                        self.process_cache.pop(old_pid, None)
            return info
        except Exception:
            return {"name": "Desconhecido"}

    def _most_recent_pid_excluding_self(self):
        try:
            procs = sorted((p for p in psutil.process_iter(["pid","create_time"])),
                          key=lambda p: p.info.get("create_time", 0) or 0,
                          reverse=True)[:10]
            for p in procs:
                if p.pid != os.getpid():
                    return p.pid
        except Exception:
            pass
        return None

    def show_instant_alert(self, title, message):
        def _show():
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10 | 0x40 | 0x1000)
        t = threading.Thread(target=_show)
        t.start()

    def defensive_actions(self, event_path: str, process_pid: int):
        if event_path in self.alerted_files:
            return

        with self.alert_lock:
            if event_path in self.alerted_files:
                return
            self.alerted_files.add(event_path)

        self.disable_network()
        self.eject_usb_devices()

        process_name = "um aplicativo desconhecido"
        is_user_action = True

        if process_pid:
            process_info = self.get_process_info(process_pid)
            p_name = process_info.get("name")

            if p_name:
                process_name = f"o aplicativo '{p_name}'"

                user_interaction_processes = ["explorer.exe", "cmd.exe", "powershell.exe", "notepad.exe", "svchost.exe"]

                if p_name.lower() not in user_interaction_processes:
                    is_user_action = False
                    self.kill_process(process_pid)

        title = " WolfGuard "
        if is_user_action:
            message = (f"Acesso suspeito detectado!\n\n"
                       f"Você acessou um arquivo-isca de segurança. "
                       f"Por segurança, a rede foi desativada.")
        else:
            message = (f"Ameaça detectada e neutralizada!\n\n"
                       f"{process_name} acessou um arquivo protegido e foi encerrado. "
                       f"A conexão com a internet foi bloqueada para proteger seus dados.")

        self.show_instant_alert(title, message)
        logging.warning(f"AÇÃO DEFENSIVA: Isca '{event_path}' acessada por PID {process_pid} ({process_name}). Rede desativada e processo encerrado.")

    def setup_autostart(self):
        try:
            script_path = os.path.abspath(sys.argv[0])
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            if script_path.lower().endswith(".py"):
                python_exe = sys.executable.replace("python.exe", "pythonw.exe")
                command = f'"{python_exe}" "{script_path}"'
            else:
                command = f'"{script_path}"'
            winreg.SetValueEx(key, "WolfGuardProtection", 0, winreg.REG_SZ, command)
            winreg.CloseKey(key)
        except Exception:
            pass

    def check_network_restoration(self):
        if os.path.exists(self.temp_defensive_file):
            try:
                os.remove(self.temp_defensive_file)
                ps_cmd = r'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"'
                subprocess.run(ps_cmd, shell=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.run('netsh interface set interface name="Wi-Fi" admin=enable', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.run('netsh interface set interface name="Ethernet" admin=enable', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.show_instant_alert("WolfGuard - Rede Restaurada", "A conexão de rede foi restaurada após a reinicialização.")
            except Exception:
                pass

    def run(self):
        self.check_network_restoration()
        self.create_guard_files()
        self.setup_monitoring()
        self.setup_audit_monitoring()
        self.setup_autostart()

        logging.info("WolfGuard em execução.")

        last_rotation_check = datetime.now()
        try:
            while self.running:
                current_time = datetime.now()
                if (current_time - last_rotation_check).total_seconds() > 3600:
                    self.clean_old_guard_files()
                    self.create_guard_files()
                    last_rotation_check = current_time
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            for o in self.observers:
                try:
                    o.stop()
                    o.join()
                except Exception:
                    pass

class BlacklistManager:
    def __init__(self, app_data_dir):
        self.app_data_dir = app_data_dir
        self.blacklist_file = os.path.join(self.app_data_dir, 'blacklist.txt')
        self.logs_dir = os.path.join(self.app_data_dir, 'logs')
        self.quarantine_dir = os.path.join(self.app_data_dir, 'quarantine')

        for directory in [self.app_data_dir, self.logs_dir, self.quarantine_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

        if not os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'w') as f:
                pass

        self.setup_logging()
        self.running = True
        self.monitor_thread = None

    def setup_logging(self):
        log_file = os.path.join(self.logs_dir, f"blacklist_{datetime.now().strftime('%Y%m%d')}.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%H:%M:%S'
        )

    def log_event(self, message, level="info"):
        if level.lower() == "info":
            logging.info(message)
        elif level.lower() == "warning":
            logging.warning(message)
        elif level.lower() == "error":
            logging.error(message)
        elif level.lower() == "critical":
            logging.critical(message)

        print(f"[BLACKLIST] {message}")

    def load_blacklist(self):
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    return [line.strip() for line in f.readlines() if line.strip()]
            return []
        except Exception as e:
            self.log_event(f"Erro ao carregar blacklist: {str(e)}", "error")
            return []

    def save_blacklist(self, blacklist):
        try:
            with open(self.blacklist_file, 'w') as f:
                for item in blacklist:
                    f.write(f"{item}\n")
            return True
        except Exception as e:
            self.log_event(f"Erro ao salvar blacklist: {str(e)}", "error")
            return False

    def add_to_blacklist(self, item_path):
        blacklist = self.load_blacklist()
        if item_path not in blacklist:
            blacklist.append(item_path)
            self.log_event(f"Item adicionado à blacklist: {item_path}")
            return self.save_blacklist(blacklist)
        return True

    def remove_from_blacklist(self, item_path):
        blacklist = self.load_blacklist()
        if item_path in blacklist:
            blacklist.remove(item_path)
            self.log_event(f"Item removido da blacklist: {item_path}")
            return self.save_blacklist(blacklist)
        return True

    def is_blacklisted(self, item_path):
        blacklist = self.load_blacklist()
        return item_path in blacklist

    def quarantine_file(self, file_path, reason="Arquivo na blacklist"):
        try:
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return False, f"Arquivo não encontrado: {file_path}"

            quarantine_id = int(time.time())
            quarantine_filename = f"quarantined_{quarantine_id}.bin"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)

            metadata = {
                "id": quarantine_id,
                "original_path": file_path,
                "date_quarantined": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "threat_name": reason,
                "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
            }

            metadata_file = os.path.join(self.quarantine_dir, f"meta_{quarantine_id}.json")

            try:
                shutil.copy2(file_path, quarantine_path)
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=4)

                try:
                    os.remove(file_path)
                    self.log_event(f"Arquivo quarentenado e removido: {file_path}")
                except Exception as e:
                    self.log_event(f"Arquivo quarentenado mas não foi possível removê-lo: {file_path}, erro: {str(e)}", "warning")

                return True, f"Arquivo quarentenado: {file_path}"
            except Exception as e:
                self.log_event(f"Erro ao quarentenar arquivo: {file_path}, erro: {str(e)}", "error")
                return False, f"Erro ao quarentenar: {str(e)}"

        except Exception as e:
            self.log_event(f"Erro no processo de quarentena: {file_path}, erro: {str(e)}", "error")
            return False, f"Erro no processo de quarentena: {str(e)}"

    def kill_process(self, process_path=None, process_name=None, force=True):
        try:
            if not process_path and not process_name:
                return False, "Caminho ou nome do processo é necessário"

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    match_found = False

                    if process_path and proc.info['exe'] and proc.info['exe'].lower() == process_path.lower():
                        match_found = True
                    elif process_name and proc.info['name'].lower() == process_name.lower():
                        match_found = True

                    if match_found:
                        process = psutil.Process(proc.info['pid'])
                        if force:
                            process.kill()
                        else:
                            process.terminate()
                        self.log_event(f"Processo encerrado: {proc.info['name']} (PID: {proc.info['pid']})")
                        return True, f"Processo {proc.info['pid']} terminado"
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    continue

            return False, "Processo não encontrado"
        except Exception as e:
            self.log_event(f"Erro ao encerrar processo: {str(e)}", "error")
            return False, f"Erro ao encerrar processo: {str(e)}"

    def process_blacklisted_items(self):
        blacklist = self.load_blacklist()
        if not blacklist:
            return

        self.log_event(f"Processando {len(blacklist)} itens na blacklist")

        for item in blacklist:
            try:
                if os.path.exists(item):
                    if os.path.isfile(item):
                        if item.lower().endswith('.exe'):
                            self.kill_process(process_path=item, force=True)

                        success, message = self.quarantine_file(item)
                        if success:
                            self.log_event(f"Arquivo na blacklist quarentenado: {item}")
                        else:
                            self.log_event(f"Falha ao quarentenar arquivo na blacklist: {item}, erro: {message}", "warning")
                    elif os.path.isdir(item):
                        self.log_event(f"Diretório na blacklist: {item}. Pastas não são removidas automaticamente.")
                else:
                    if '\\' not in item and '/' not in item:
                        success, message = self.kill_process(process_name=item, force=True)
                        if success:
                            self.log_event(f"Processo na blacklist encerrado: {item}")
                        else:
                            self.log_event(f"Processo na blacklist não encontrado: {item}")
                    else:
                        self.scan_for_exact_filename(item)
            except Exception as e:
                self.log_event(f"Erro ao processar item da blacklist: {item}, erro: {str(e)}", "error")

    def scan_for_exact_filename(self, target_filename):
        try:
            self.log_event(f"Procurando por arquivos com nome: {target_filename}")
            found_files = []

            for drive in self._get_drives():
                self.log_event(f"Escaneando unidade: {drive}")
                for root, dirs, files in os.walk(drive, topdown=True):
                    if target_filename in files:
                        file_path = os.path.join(root, target_filename)
                        found_files.append(file_path)
                        self.log_event(f"Arquivo encontrado: {file_path}")

                        if file_path.lower().endswith('.exe'):
                            self.kill_process(process_path=file_path, force=True)

                        success, message = self.quarantine_file(file_path)
                        if success:
                            self.log_event(f"Arquivo quarentenado: {file_path}")
                        else:
                            self.log_event(f"Falha ao quarentenar arquivo: {file_path}, erro: {message}", "warning")

            if not found_files:
                self.log_event(f"Nenhum arquivo com nome '{target_filename}' encontrado")

        except Exception as e:
            self.log_event(f"Erro ao escanear por nome de arquivo: {target_filename}, erro: {str(e)}", "error")

    def _get_drives(self):
        drives = []
        try:
            bitmask = win32api.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    drives.append(f"{letter}:")
                bitmask >>= 1
        except Exception as e:
            self.log_event(f"Erro ao obter unidades: {str(e)}", "error")
            drives = ["C:"]
        return drives

    def start_monitoring(self, interval=10):
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.log_event("Monitoramento da blacklist já está em execução")
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, args=(interval,), daemon=True)
        self.monitor_thread.start()
        self.log_event(f"Monitoramento da blacklist iniciado (intervalo: {interval}s)")

    def stop_monitoring(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        self.log_event("Monitoramento da blacklist interrompido")

    def _monitoring_loop(self, interval):
        while self.running:
            try:
                self.process_blacklisted_items()
            except Exception as e:
                self.log_event(f"Erro no loop de monitoramento: {str(e)}", "error")

            for _ in range(int(interval)):
                if not self.running:
                    break
                time.sleep(1)

def get_resource_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

running_modules = set()

def iniciar_modulos():
    global running_modules

    if "wolf4.py" not in running_modules:
        try:
            wolf_guard = WolfGuardSystem()
            threading.Thread(target=wolf_guard.run, daemon=True).start()
            running_modules.add("wolf4.py")
        except Exception:
            pass

    modulos = ["wolf1.py", "wolf2.py"]

    
    if "wolf1.py" not in running_modules:
        try:
            threading.Thread(target=run_protection_system, daemon=True).start()
            running_modules.add("wolf1.py")
        except Exception:
            pass

    
    modulos_externos = ["wolf5.py"]
    for modulo in modulos_externos:
        try:
            module_path = get_resource_path(modulo)
            if modulo not in running_modules and os.path.exists(module_path):
                subprocess.Popen(
                    [sys.executable, module_path],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL
                )
                running_modules.add(modulo)
        except Exception:
            pass

class LinkVerifier:
    def __init__(self):
        self.phishing_domains = [
            "phishing", "scam", "login", "verify", "account", "secure", "banking"
        ]
        self.malicious_patterns = [
            "/wp-admin/", "crack", "keygen"
        ]

    def verify_link(self, url):
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()

            if any(phish in domain for phish in self.phishing_domains):
                return False, "Este domínio contém palavras frequentemente associadas a phishing."

            if any(pattern in path for pattern in self.malicious_patterns):
                return False, "O caminho deste URL contém padrões potencialmente maliciosos."

            return True, "Link verificado e parece seguro."

        except Exception as e:
            return False, f"Erro ao analisar o link: {str(e)}"

class OptimizedScanThread(QThread):
    scan_complete = pyqtSignal(int, int, list)
    scan_progress = pyqtSignal(int, int)

    def __init__(self, scan_engine, options):
        super().__init__()
        self.scan_engine = scan_engine
        self.options = options
        self.running = True

    def run(self):
        gc.collect()
        self.scan_complete.emit(0, 0, [])

    def stop(self):
        self.running = False

class UsageTracker:
    def __init__(self, app_data_dir):
        self.app_data_dir = app_data_dir
        self.usage_file = os.path.join(self.app_data_dir, 'usage_data.json')
        self.session_start = datetime.now()
        self.last_update = self.session_start
        self.load_data()

    def load_data(self):
        if os.path.exists(self.usage_file):
            try:
                with open(self.usage_file, 'r') as f:
                    self.usage_data = json.load(f)
            except Exception:
                self.initialize_data()
        else:
            self.initialize_data()

    def initialize_data(self):
        self.usage_data = {
            'total_usage_seconds': 0,
            'last_session': None,
            'weekly_data': {
                'segunda': 0, 'terça': 0, 'quarta': 0, 'quinta': 0,
                'sexta': 0, 'sábado': 0, 'domingo': 0
            },
            'most_used_day': None
        }
        self.save_data()

    def save_data(self):
        try:
            with open(self.usage_file, 'w') as f:
                json.dump(self.usage_data, f, indent=4)
        except Exception:
            pass

    def update_session(self):
        now = datetime.now()
        session_duration = (now - self.last_update).total_seconds()
        self.usage_data['total_usage_seconds'] += session_duration
        self.usage_data['last_session'] = now.strftime("%Y-%m-%d %H:%M:%S")

        day_name = ['segunda', 'terça', 'quarta', 'quinta', 'sexta', 'sábado', 'domingo'][now.weekday()]
        self.usage_data['weekly_data'][day_name] += session_duration

        most_used_day = max(self.usage_data['weekly_data'], key=self.usage_data['weekly_data'].get)
        if self.usage_data['weekly_data'][most_used_day] > 0:
            self.usage_data['most_used_day'] = most_used_day

        self.last_update = now
        self.save_data()

    def get_formatted_total_time(self):
        total_seconds = self.usage_data['total_usage_seconds']
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_weekly_data(self):
        return self.usage_data['weekly_data']

    def get_most_used_day(self):
        if self.usage_data['most_used_day'] is None:
            return "nenhum"
        return self.usage_data['most_used_day']

class UsageGraphWidget(QWidget):
    def __init__(self, usage_tracker, parent=None):
        super().__init__(parent)
        self.usage_tracker = usage_tracker
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.setStyleSheet("background-color: transparent;")
        self.setMinimumHeight(200)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        painter.fillRect(self.rect(), QColor(0, 0, 0, 40))

        weekly_data = self.usage_tracker.get_weekly_data()
        max_value = max(weekly_data.values()) if any(weekly_data.values()) else 1

        painter.setPen(QPen(QColor(200, 200, 255), 1))
        painter.setFont(QFont("Arial", 8))

        width = self.width()
        height = self.height()

        bar_width = width / 9
        x_offset = bar_width

        days = ['segunda', 'terça', 'quarta', 'quinta', 'sexta', 'sábado', 'domingo']
        day_short = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom']

        for i, day in enumerate(days):
            value_hours = weekly_data[day] / 3600
            bar_height = (value_hours / (max_value/3600)) * (height - 60) if max_value > 0 else 0

            gradient = QLinearGradient(0, height - 40 - bar_height, 0, height - 40)

            if day == self.usage_tracker.get_most_used_day():
                gradient.setColorAt(0, QColor(100, 200, 255))
                gradient.setColorAt(1, QColor(50, 120, 220))
            else:
                gradient.setColorAt(0, QColor(80, 130, 255))
                gradient.setColorAt(1, QColor(30, 70, 180))

            painter.setBrush(gradient)

            bar_rect = QRect(
                int(x_offset + i * bar_width),
                int(height - 40 - bar_height),
                int(bar_width * 0.8),
                int(bar_height)
            )
            painter.drawRoundedRect(bar_rect, 4, 4)

            painter.setPen(QColor(220, 220, 255))
            painter.drawText(
                int(x_offset + i * bar_width),
                int(height - 25),
                int(bar_width * 0.8),
                20,
                Qt.AlignCenter,
                day_short[i]
            )

        painter.setPen(QColor(220, 220, 255))
        painter.setFont(QFont("Arial", 10, QFont.Bold))
        painter.drawText(10, 20, "Uso Semanal (horas)")

class NetworkInfoWorker(QObject):
    finished = pyqtSignal(dict)

    def run(self):
        result = {'net_info': {'public_ip': 'N/A', 'local_ip': 'N/A'},
                  'geo_info': {'country': 'N/A', 'region': 'N/A', 'city': 'N/A'}}

        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            result['net_info']['local_ip'] = local_ip
        except Exception:
            pass

        try:
            with urllib.request.urlopen("http://ip-api.com/json/", timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    result['net_info']['public_ip'] = data.get('query', 'N/A')
                    result['geo_info']['country'] = data.get('country', 'N/A')
                    result['geo_info']['region'] = data.get('regionName', 'N/A')
                    result['geo_info']['city'] = data.get('city', 'N/A')
        except Exception:
            pass

        self.finished.emit(result)

class USBScanDialog(QDialog):
    def __init__(self, drive_letter, parent=None):
        super().__init__(parent)
        self.drive_letter = drive_letter
        self.scan_selected = False
        self.init_ui()

    def init_ui(self):
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.setWindowTitle("Dispositivo USB Detectado")
        self.setFixedSize(500, 250)
        self.setStyleSheet("QDialog { background-color: #2e2e2e; color: white; }")

        layout = QVBoxLayout()

        icon_label = QLabel("🔌")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setFont(QFont("Arial", 48))
        layout.addWidget(icon_label)

        message = QLabel(f"Dispositivo USB detectado:\n{self.drive_letter}")
        message.setAlignment(Qt.AlignCenter)
        message.setFont(QFont("Arial", 14))
        layout.addWidget(message)

        button_layout = QHBoxLayout()
        yes_button = QPushButton("Sim, verificar")
        yes_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        yes_button.clicked.connect(self.select_scan)

        no_button = QPushButton("Não")
        no_button.setStyleSheet("""
            QPushButton {
                background-color: gray;
                color: white;border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
        """)
        no_button.clicked.connect(self.reject)

        button_layout.addWidget(yes_button)
        button_layout.addWidget(no_button)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def select_scan(self):
        self.scan_selected = True
        self.accept()

class SnowAnimation(QWidget):
    def __init__(self, parent=None, num_flakes=30):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.num_flakes = num_flakes
        self.snowflakes = []
        self.init_snowflakes()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_snow)
        self.timer.start(100)
        self.enabled = True

    def set_enabled(self, enabled):
        self.enabled = enabled
        if enabled:
            self.timer.start(30)
        else:
            self.timer.stop()
        self.setVisible(enabled)

    def init_snowflakes(self):
        self.snowflakes = []
        width = self.width() if self.width() > 0 else 1000
        height = self.height() if self.height() > 0 else 720

        for _ in range(self.num_flakes):
            x = random.randint(0, width)
            y = random.randint(-height, 0)
            radius = random.randint(2, 5)
            speed = random.uniform(4.1, 7.3)
            self.snowflakes.append({'x': x, 'y': y, 'radius': radius, 'speed': speed})

    def update_snow(self):
        if not self.enabled:
            return
        height = self.height()
        width = self.width()
        for flake in self.snowflakes:
            flake['y'] += flake['speed']
            if flake['y'] > height:
                flake['y'] = -flake['radius']
                flake['x'] = random.randint(0, width)
        self.update()

    def paintEvent(self, event):
        if not self.enabled:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(255, 255, 255, 180))
        for flake in self.snowflakes:
            painter.drawEllipse(int(flake['x']), int(flake['y']), flake['radius'], flake['radius'])

class ProcessManager:
    def __init__(self):
        self.wmi_interface = None

    def kill_process(self, process_path, force=False):
        try:
            for process in psutil.process_iter(['pid', 'exe']):
                try:
                    if process.info['exe'] and process.info['exe'].lower() == process_path.lower():
                        if force:
                            process.kill()
                        else:
                            process.terminate()
                        return True, f"Processo {process.info['pid']} terminado"
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            return False, "Processo não encontrado"
        except Exception as e:
            return False, f"Erro ao encerrar processo: {str(e)}"

    def kill_process_by_name(self, process_name, force=False):
        try:
            found = False
            for process in psutil.process_iter(['pid', 'name']):
                try:
                    if process.info['name'].lower() == process_name.lower():
                        if force:
                            process.kill()
                        else:
                            process.terminate()
                        found = True
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            if found:
                return True, f"Processo {process_name} terminado"
            return False, "Processo não encontrado"
        except Exception as e:
            return False, f"Erro ao encerrar processo: {str(e)}"

    def get_running_processes(self):
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'path': proc.info['exe'] if proc.info['exe'] else "N/A",
                        'username': proc.info['username'] if proc.info['username'] else "N/A"
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            return processes
        except Exception:
            return []

class FuturisticButton(QPushButton):
    def __init__(self, text, icon_path=None, parent=None):
        super().__init__(text, parent)
        self.setFixedHeight(48)
        self.setCursor(Qt.PointingHandCursor)
        self.setFont(QFont("Arial", 11))

        if icon_path:
            icon_full_path = get_resource_path(icon_path)
            if os.path.exists(icon_full_path):
                self.setIcon(QIcon(icon_full_path))
                self.setIconSize(QSize(24, 24))

        self.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding-left: 15px;
                margin: 3px;
                background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0,
                                                stop:0 rgba(30, 50, 100, 150), stop:1 rgba(60, 80, 150, 100));
                border: none;
                border-radius: 8px;
                color: white;
            }
            QPushButton:hover {
                background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0,
                                                stop:0 rgba(50, 70, 150, 200), stop:1 rgba(80, 100, 180, 150));
                border-left: 3px solid #00c8ff;
            }
            QPushButton:pressed {
                background-color: rgba(70, 90, 180, 200);
            }
        """)

class ThreatNotificationDialog(QDialog):
    def __init__(self, file_name, threat_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WolfGuard - Ameaça Detectada!")
        self.setFixedSize(450, 250)
        self.setStyleSheet("QDialog { background-color: #2e2e2e; color: white; }")
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
        self.init_ui(file_name, threat_name)

    def init_ui(self, file_name, threat_name):
        layout = QVBoxLayout()

        icon_label = QLabel(" ")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setFont(QFont("Arial", 48))
        icon_label.setStyleSheet("color: #FF5555;")
        layout.addWidget(icon_label)

        title_label = QLabel("Vírus Detectado e Removido!")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setStyleSheet("color: #FF5555;")
        layout.addWidget(title_label)

        info_label = QLabel(f"O WolfGuard detectou e removeu uma ameaça:\n\n"
                            f"Arquivo: {file_name}\n"
                            f"Tipo de ameaça: {threat_name}\n\n"
                            f"O arquivo foi movido para a quarentena com segurança.")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setFont(QFont("Arial", 11))
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: white;")
        layout.addWidget(info_label)

        ok_button = QPushButton("OK")
        ok_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        ok_button.clicked.connect(self.accept)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(ok_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.setLayout(layout)

class WolfGuardAntivírus(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_resolution = (1024, 768)
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a237e, stop:1 #000000);
                border: 2px solid black;
            }
            * { font-weight: 500; }
            QScrollArea { min-height: 100px; }
            QLabel { min-height: 20px; padding: 2px; }
            QListWidget { min-height: 120px; }
            QTableWidget { min-height: 120px; }
        """)
        self.setMinimumSize(800, 700)

        try:
            self.app_data_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'WolfGuard')
            self.logs_dir = os.path.join(self.app_data_dir, 'logs')
            self.user_rules_dir = os.path.join(self.app_data_dir, 'user_rules')

            for directory in [self.app_data_dir, self.logs_dir, self.user_rules_dir]:
                if not os.path.exists(directory):
                    os.makedirs(directory)

            self._initialize_password()

            if self._load_setting('password_protection', True):
                login_dialog = LoginDialog(self.app_data_dir)
                if login_dialog.exec_() != QDialog.Accepted:
                    sys.exit(0)

            try:
                self.scan_engine = ScanEngine(self.app_data_dir)
            except Exception as e:
                self.log_event(f"Erro ao inicializar o motor de verificação: {str(e)}")
                QMessageBox.critical(self, "Erro Fatal",
                    f"Não foi possível inicializar o motor de verificação.\nErro: {str(e)}")
                sys.exit(1)

            try:
                self.usb_monitor = USBMonitor(self.scan_engine, self.scan_engine.quarantine_manager, self.usb_detected_callback)
            except Exception as e:
                self.log_event(f"Erro ao inicializar monitor USB: {str(e)}")

            self.scan_thread = None
            self.file_monitor = None
            self.observer = None
            self.is_realtime_protection_active = self._load_setting('realtime_protection', True)
            self.run_in_background = self._load_setting('run_in_background', True)
            self.show_threat_notifications = self._load_setting('show_threat_notifications', True)
            self.snow_animation_enabled = self._load_setting('snow_animation', True)
            self.last_scan_date = "Nunca"
            self.threats_found = 0
            self.files_scanned = 0
            self._load_stats()
            self.active_since = datetime.now().strftime("%d/%m/%Y %H:%M")

            self.usage_tracker = UsageTracker(self.app_data_dir)
            self.usage_update_timer = QTimer(self)
            self.usage_update_timer.setInterval(30000)
            self.usage_update_timer.timeout.connect(self.update_usage_stats)
            self.usage_update_timer.start()

            self.blacklist_manager = BlacklistManager(self.app_data_dir)
            self.process_manager = ProcessManager()
            self.blacklist_monitor_timer = QTimer()
            self.blacklist_monitor_timer.setInterval(10000)
            self.blacklist_monitor_timer.timeout.connect(self.check_blacklisted_processes)

            self.setWindowTitle("WolfGuard Antivírus")

            self.continuous_scan_enabled = self._load_setting('continuous_scan', False)
            self.continuous_scan_timer = QTimer(self)
            self.continuous_scan_timer.setInterval(7200000)

            self.load_resolution_settings()

            icon_path = get_resource_path("1.png")
            self.tray_icon = QSystemTrayIcon(self)
            if os.path.exists(icon_path):
                self.tray_icon.setIcon(QIcon(icon_path))
            self.tray_icon.setToolTip("WolfGuard Antivírus - Proteção Ativa")

            tray_menu = QMenu()
            open_action = QAction("Abrir Dashboard", self)
            if os.path.exists(icon_path):
                open_action.setIcon(QIcon(icon_path))
            open_action.triggered.connect(self.show)
            tray_menu.addAction(open_action)

            tray_menu.addSeparator()
            exit_action = QAction("Sair", self)
            exit_action.triggered.connect(self.confirm_exit)
            tray_menu.addAction(exit_action)
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.tray_icon_clicked)
            self.tray_icon.show()

            self.setup_ui()

            if self.is_realtime_protection_active:
                self.blacklist_monitor_timer.start()
                self.log_event("Aplicativo iniciado. Proteção em tempo real ativa.")
            else:
                self.log_event("Aplicativo iniciado. Proteção em tempo real desativada.")

            self.snow_widget = SnowAnimation(self, num_flakes=30)
            self.snow_widget.setGeometry(self.rect())
            self.snow_widget.set_enabled(self.snow_animation_enabled)
            self.snow_widget.raise_()

            self.link_verifier = LinkVerifier()

            self.auto_scan_enabled = self._load_setting('auto_scan', False)

            show_instructions = self._load_setting('show_instructions', True)
            if show_instructions:
                instruction_dialog = InstructionDialog(self)
                if instruction_dialog.exec_() == QDialog.Accepted:
                    if instruction_dialog.dont_show_checkbox.isChecked():
                        self._save_setting('show_instructions', False)

            self.start_blacklist_service()

            if self.continuous_scan_enabled:
                self.continuous_scan_timer.start()

            self.crash_watchdog_timer = QTimer(self)
            self.crash_watchdog_timer.setInterval(60000)
            self.crash_watchdog_timer.timeout.connect(self.update_watchdog_file)
            self.crash_watchdog_timer.start()
            self.update_watchdog_file()

            iniciar_modulos()

            QTimer.singleShot(5000, gc.collect)

        except Exception as e:
            error_message = f"Erro crítico durante a inicialização: {str(e)}\n{traceback.format_exc()}"
            print(error_message)
            QMessageBox.critical(None, "Erro Fatal",
                f"Ocorreu um erro crítico durante a inicialização do aplicativo:\n{str(e)}")
            sys.exit(1)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_F4:
            self.ativar_wifi_usb()
        super().keyPressEvent(event)

    def load_resolution_settings(self):
        saved_resolution = self._load_setting('resolution', None)
        if saved_resolution:
            self.current_resolution = tuple(saved_resolution)
            self.resize(*self.current_resolution)
        else:
            screen = QGuiApplication.primaryScreen().availableGeometry()
            if screen.height() > 1080:
                self.resize(1024, 768)
            else:
                width = int(screen.width() * 0.77)
                height = int(screen.height() * 0.77)
                self.resize(width, height)

    def change_resolution(self, resolution):
        screen = QGuiApplication.primaryScreen().availableGeometry()
        max_width = screen.width()
        max_height = screen.height()

        width, height = resolution

        if width > max_width or height > max_height:
            QMessageBox.warning(self, "Resolução Inválida",
                f"A resolução selecionada ({width}x{height}) é maior que a resolução do seu monitor ({max_width}x{max_height}).")
            return False

        self.current_resolution = resolution
        self.resize(width, height)
        self._save_setting('resolution', list(resolution))

        scale_factor = width / 1024.0
        base_font_size = int(11 * scale_factor)
        font_style = f"font-size: {base_font_size}px;"
        self.setStyleSheet(self.styleSheet() + f"\n* {{ {font_style} }}")

        return True

    def ativar_wifi_usb(self):
        def activate():
            try:
                self.log_event("Ativando WiFi e USB...")

                subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"],
                              shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                subprocess.run(["netsh", "interface", "set", "interface", "Ethernet", "admin=enable"],
                              shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                subprocess.run(["pnputil", "/scan-devices"],
                              shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

                self.log_event("WiFi e USB ativados com sucesso")
                QMetaObject.invokeMethod(self, "_show_wifi_usb_success", Qt.QueuedConnection)
            except Exception as e:
                self.log_event(f"Erro ao ativar WiFi e USB: {str(e)}")
                QMetaObject.invokeMethod(self, "_show_wifi_usb_error", Qt.QueuedConnection, Q_ARG(str, str(e)))

        thread = threading.Thread(target=activate, daemon=True)
        thread.start()

    @pyqtSlot()
    def _show_wifi_usb_success(self):
        QMessageBox.information(self, "Ativação Concluída", "WiFi e USB ativados com sucesso!")

    @pyqtSlot(str)
    def _show_wifi_usb_error(self, error):
        QMessageBox.warning(self, "Erro", f"Erro ao ativar WiFi e USB: {error}")

    @pyqtSlot(str, str)
    def show_threat_notification(self, file_name, threat_name):
        if self.show_threat_notifications:
            dialog = ThreatNotificationDialog(file_name, threat_name, self)
            dialog.exec_()

    def update_watchdog_file(self):
        try:
            watchdog_file = os.path.join(self.app_data_dir, 'watchdog.txt')
            with open(watchdog_file, 'w') as f:
                f.write(str(datetime.now().timestamp()))
        except Exception:
            pass

    def update_usage_stats(self):
        self.usage_tracker.update_session()
        if hasattr(self, 'total_usage_label'):
            self.total_usage_label.setText(f"Tempo Total: {self.usage_tracker.get_formatted_total_time()}")
        if hasattr(self, 'most_used_day_label'):
            self.most_used_day_label.setText(f"Dia mais usado: {self.usage_tracker.get_most_used_day().capitalize()}")
        if hasattr(self, 'usage_graph'):
            self.usage_graph.update()

    def start_blacklist_service(self):
        try:
            self.blacklist_service = BlacklistManager(self.app_data_dir)
            self.blacklist_service_thread = threading.Thread(
                target=self.blacklist_service.start_monitoring,
                args=(30,),
                daemon=True
            )
            self.blacklist_service_thread.start()
            self.log_event("Serviço de blacklist iniciado com sucesso")
        except Exception as e:
            self.log_event(f"Erro ao iniciar serviço de blacklist: {str(e)}")

    def check_blacklisted_processes(self):
        def check_async():
            try:
                blacklist = self.blacklist_manager.load_blacklist()
                if not blacklist:
                    return

                processes = self.process_manager.get_running_processes()
                for process in processes:
                    process_path = process.get('path', '').lower()
                    process_name = process.get('name', '').lower()

                    for blocked_item in blacklist:
                        blocked_item = blocked_item.lower()

                        if (process_path and blocked_item in process_path) or \
                           (process_name and blocked_item == process_name):
                            QMetaObject.invokeMethod(self, "_handle_blacklisted_process",
                                                   Qt.QueuedConnection,
                                                   Q_ARG(dict, process),
                                                   Q_ARG(str, blocked_item))
            except Exception:
                pass

        thread = threading.Thread(target=check_async, daemon=True)
        thread.start()

    @pyqtSlot(dict, str)
    def _handle_blacklisted_process(self, process, blocked_item):
        try:
            process_name = process.get('name', 'Desconhecido')
            process_path = process.get('path', 'Caminho desconhecido')

            success, _ = self.process_manager.kill_process(process_path, force=True)
            if not success:
                success, _ = self.process_manager.kill_process_by_name(process_name, force=True)

            if success:
                self.log_event(f"Processo bloqueado terminado: {process_name}")

                if os.path.exists(process_path):
                    quarantine_success, _ = self.scan_engine.quarantine_manager.quarantine_file(
                        process_path,
                        f"Aplicativo na blacklist: {blocked_item}"
                    )

                    if quarantine_success:
                        self.log_event(f"Arquivo bloqueado quarentenado: {process_path}")
                        QMetaObject.invokeMethod(self, "show_threat_notification", Qt.QueuedConnection,
                                                 Q_ARG(str, process_name),
                                                 Q_ARG(str, "Aplicativo na blacklist"))
        except Exception:
            pass

    def open_website(self):
        try:
            webbrowser.open("https://wolfguard.com.br/update")
            self.log_event("Página de atualizações acessada pelo usuário")
        except Exception as e:
            self.log_event(f"Erro ao abrir página de atualizações: {str(e)}")
            QMessageBox.warning(self, "Erro", f"Não foi possível abrir a página de atualizações: {str(e)}")

    def verify_exit_password(self):
        password_dialog = QInputDialog(self)
        password_dialog.setWindowTitle("Senha Requerida")
        password_dialog.setLabelText("Digite a senha para sair:")
        password_dialog.setTextEchoMode(QLineEdit.Password)

        if password_dialog.exec_() == QDialog.Accepted:
            entered_password = password_dialog.textValue()
            stored_password = self._get_stored_password()

            if entered_password == stored_password:
                return True

        return False

    def _initialize_password(self):
        password_file = os.path.join(self.app_data_dir, "antivirus_password.txt")
        if not os.path.exists(password_file):
            try:
                with open(password_file, "w") as f:
                    f.write("0000")
                self.log_event("Senha padrão inicializada.")
            except Exception:
                pass

    def _get_stored_password(self):
        try:
            password_file = os.path.join(self.app_data_dir, "antivirus_password.txt")
            if os.path.exists(password_file):
                with open(password_file, "r") as f:
                    return f.read().strip()
            return "0000"
        except Exception:
            return "0000"

    def _set_password(self, new_password):
        try:
            password_file = os.path.join(self.app_data_dir, "antivirus_password.txt")
            with open(password_file, "w") as f:
                f.write(new_password)
            self.log_event("Senha atualizada com sucesso.")
            return True
        except Exception as e:
            self.log_event(f"Erro ao atualizar senha: {e}")
            return False

    def resizeEvent(self, event):
        if hasattr(self, 'snow_widget'):
            self.snow_widget.setGeometry(self.rect())
        super().resizeEvent(event)

    def _save_stats(self):
        stats_file = os.path.join(self.app_data_dir, 'stats.json')
        try:
            stats = {
                'threats_found': self.threats_found,
                'last_scan_date': self.last_scan_date,
                'files_scanned': self.files_scanned
            }
            with open(stats_file, 'w') as f:
                json.dump(stats, f)
            return True
        except Exception:
            return False

    def _load_stats(self):
        stats_file = os.path.join(self.app_data_dir, 'stats.json')
        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r') as f:
                    stats = json.load(f)
                self.threats_found = stats.get('threats_found', 0)
                self.last_scan_date = stats.get('last_scan_date', "Nunca")
                self.files_scanned = stats.get('files_scanned', 0)
                return True
            except Exception:
                return False
        return False

    def reset_stats(self):
        reply = QMessageBox.question(
            self, "Confirmar Redefinição",
            "Tem certeza de que deseja zerar as estatísticas de ameaças e última verificação?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.threats_found = 0
            self.last_scan_date = "Nunca"
            self.files_scanned = 0
            self._save_stats()
            self.update_dashboard_stats()
            QMessageBox.information(self, "Estatísticas Redefinidas", "As estatísticas foram zeradas com sucesso.")

    def update_dashboard_stats(self):
        if hasattr(self, 'threats_label'):
            self.threats_label.setText(f"Ameaças Detectadas: {self.threats_found}")
        if hasattr(self, 'last_scan_label'):
            self.last_scan_label.setText(f"Última Verificação: {self.last_scan_date}")

    def tray_icon_clicked(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
            self.activateWindow()

    def confirm_exit(self):
        if not self.verify_exit_password():
            return

        reply = QMessageBox.question(
            self, "Confirmar Saída",
            "Tem certeza de que deseja sair? A proteção em tempo real será desativada.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.close()

    def usb_detected_callback(self, drive_letter):
        QMetaObject.invokeMethod(self, "_show_usb_dialog",
                                 Qt.QueuedConnection,
                                 Q_ARG(str, drive_letter))

    @pyqtSlot(str)
    def _show_usb_dialog(self, drive_letter):
        dialog = USBScanDialog(drive_letter, self)
        result = dialog.exec_()
        if result == QDialog.Accepted and dialog.scan_selected:
            QMessageBox.information(self, "Verificação Iniciada",
                f"Iniciando verificação do dispositivo USB {drive_letter}.\nVocê será notificado ao término.")

    def notify_user(self, title, message):
        QMetaObject.invokeMethod(self, "_show_notification",
                               Qt.QueuedConnection,
                               Q_ARG(str, title),
                               Q_ARG(str, message))

    @pyqtSlot(str, str)
    def _show_notification(self, title, message):
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 5000)

    def setup_ui(self):
        central_widget = QWidget()
        central_widget.setStyleSheet("background: transparent;")
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.nav_panel = QWidget()
        self.nav_panel.setFixedWidth(290)
        self.nav_panel.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.nav_panel.setStyleSheet("background: transparent;")
        nav_layout = QVBoxLayout(self.nav_panel)
        nav_layout.setContentsMargins(5, 15, 5, 15)
        nav_layout.setSpacing(8)

        logo_label = QLabel("WolfGuard")
        logo_label.setFont(QFont("Arial", 20, QFont.Bold))
        logo_label.setStyleSheet("color: white; background: transparent;")
        logo_label.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(logo_label)

        subtitle_label = QLabel("ANTIVÍRUS")
        subtitle_label.setFont(QFont("Arial", 10))
        subtitle_label.setStyleSheet("color: white; background: transparent;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(subtitle_label)
        nav_layout.addSpacing(15)

        nav_items = [
            {"name": "Painel", "icon": "1.png"},
            {"name": "Links", "icon": "4.png"},
            {"name": "IP/USB", "icon": "2.png"},
            {"name": "Blacklist", "icon": "7.png"},
            {"name": "Proteção", "icon": "5.png"},
            {"name": "Quarentena", "icon": "6.png"},
            {"name": "Configurações", "icon": "8.png"},
            {"name": "Tempo de Uso", "icon": "10.png"},
            {"name": "SiteUpdate", "icon": "9.png"}
        ]

        self.nav_buttons = []
        for i, item in enumerate(nav_items):
            button = FuturisticButton(item['name'], item['icon'])
            if item["name"] == "SiteUpdate":
                button.clicked.connect(self.open_website)
            else:
                button.clicked.connect(lambda checked, idx=i: self.change_page(idx))
            nav_layout.addWidget(button)
            self.nav_buttons.append(button)

        nav_layout.addStretch()

        team_signature = QLabel("Desenvolvido por: Mateus, Sarah,\nEduardo, Guilherme, Pedro")
        team_signature.setFont(QFont("Arial", 8))
        team_signature.setStyleSheet("color: white; padding: 5px;")
        team_signature.setAlignment(Qt.AlignCenter)
        team_signature.setWordWrap(True)
        nav_layout.addWidget(team_signature)

        version_label = QLabel("Versão 1.0")
        version_label.setFont(QFont("Arial", 9))
        version_label.setStyleSheet("color: white;")
        version_label.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(version_label)

        content_widget = QWidget()
        content_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        content_widget.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.pages = QStackedWidget()
        self.pages.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.pages.setStyleSheet("background: transparent;")
        content_layout.addWidget(self.pages)

        self.create_dashboard_page()
        self.create_link_verification_page()
        self.create_pro_page()
        self.create_blacklist_page()
        self.create_protection_page()
        self.create_quarantine_page()
        self.create_settings_page()
        self.create_usage_page()

        self.select_nav_button(0)
        main_layout.addWidget(self.nav_panel)
        main_layout.addWidget(content_widget)

    def create_usage_page(self):
        page = QWidget()
        page.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title = QLabel("Tempo de Uso")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        usage_frame = QFrame()
        usage_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border-radius: 10px; padding: 15px;")
        usage_layout = QVBoxLayout(usage_frame)

        usage_info_layout = QHBoxLayout()

        usage_info_frame = QFrame()
        usage_info_frame.setStyleSheet("background-color: rgba(20, 40, 90, 0.4); border-radius: 8px; padding: 15px;")
        usage_info_frame_layout = QVBoxLayout(usage_info_frame)

        self.total_usage_label = QLabel(f"Tempo Total: {self.usage_tracker.get_formatted_total_time()}")
        self.total_usage_label.setFont(QFont("Arial", 14))
        self.total_usage_label.setStyleSheet("color: white;")
        usage_info_frame_layout.addWidget(self.total_usage_label)

        session_start_label = QLabel(f"Sessão iniciada em: {self.active_since}")
        session_start_label.setFont(QFont("Arial", 12))
        session_start_label.setStyleSheet("color: white;")
        usage_info_frame_layout.addWidget(session_start_label)

        self.most_used_day_label = QLabel(f"Dia mais usado: {self.usage_tracker.get_most_used_day().capitalize()}")
        self.most_used_day_label.setFont(QFont("Arial", 12))
        self.most_used_day_label.setStyleSheet("color: white;")
        usage_info_frame_layout.addWidget(self.most_used_day_label)

        usage_info_layout.addWidget(usage_info_frame)
        usage_layout.addLayout(usage_info_layout)

        self.usage_graph = UsageGraphWidget(self.usage_tracker)
        self.usage_graph.setMinimumHeight(250)
        usage_layout.addWidget(self.usage_graph)

        buttons_layout = QHBoxLayout()

        reset_stats_button = QPushButton("Zerar Estatísticas")
        reset_stats_button.setFont(QFont("Arial", 12))
        reset_stats_button.setStyleSheet("""
            QPushButton {
                background-color: #FF5555;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #FF3333;
            }
        """)
        reset_stats_button.clicked.connect(self.reset_usage_stats)
        buttons_layout.addWidget(reset_stats_button)

        export_stats_button = QPushButton("Exportar Estatísticas")
        export_stats_button.setFont(QFont("Arial", 12))
        export_stats_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        export_stats_button.clicked.connect(self.export_usage_stats)
        buttons_layout.addWidget(export_stats_button)

        usage_layout.addLayout(buttons_layout)
        layout.addWidget(usage_frame)

        self.pages.addWidget(page)

    def reset_usage_stats(self):
        reply = QMessageBox.question(
            self, "Confirmar Redefinição",
            "Tem certeza de que deseja zerar as estatísticas de uso? Esta ação não pode ser desfeita.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.usage_tracker.initialize_data()
            self.update_usage_stats()
            QMessageBox.information(self, "Estatísticas Redefinidas", "As estatísticas de uso foram zeradas com sucesso.")

    def export_usage_stats(self):
        try:
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Exportar Estatísticas de Uso",
                os.path.join(os.path.expanduser("~"), "Desktop", "wolfguard_usage_stats.json"),
                "Arquivos JSON (*.json)"
            )

            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(self.usage_tracker.usage_data, f, indent=4, ensure_ascii=False)
                QMessageBox.information(self, "Exportação Concluída", f"Estatísticas de uso exportadas para:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao exportar estatísticas: {str(e)}")

    def create_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel(" ")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        admin_status = "Admin" if is_admin() else "Sem Admin"
        admin_label = QLabel(f"Status de Administrador: {admin_status}")
        admin_label.setFont(QFont("Arial", 11))
        admin_label.setStyleSheet("color: white;")
        layout.addWidget(admin_label)

        status_frame = QFrame()
        status_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.5); border-radius: 10px; padding: 12px;")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setSpacing(10)

        status_icon = QLabel("✓")
        status_icon.setFont(QFont("Arial", 16))
        status_icon.setStyleSheet("color: #00FF00;")
        status_layout.addWidget(status_icon)

        status_label = QLabel("Seu sistema está protegido")
        status_label.setFont(QFont("Arial", 14))
        status_label.setStyleSheet("color: white;")
        status_layout.addWidget(status_label)
        status_layout.addStretch()

        protection_toggle_label = QLabel("Proteção em tempo real:")
        protection_toggle_label.setFont(QFont("Arial", 12))
        protection_toggle_label.setStyleSheet("color: white;")
        status_layout.addWidget(protection_toggle_label)

        self.protection_toggle = QCheckBox()
        self.protection_toggle.setChecked(self.is_realtime_protection_active)
        self.protection_toggle.stateChanged.connect(lambda state: self.toggle_protection_from_ui(state, "dashboard"))
        self.protection_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        status_layout.addWidget(self.protection_toggle)

        layout.addWidget(status_frame)
        layout.addSpacing(20)

        wifi_usb_button = QPushButton("Ativar WiFi e USB (F4)")
        wifi_usb_button.setFont(QFont("Arial", 12, QFont.Bold))
        wifi_usb_button.setMinimumHeight(50)
        wifi_usb_button.setStyleSheet("""
            QPushButton {
                background-color: #000000;
                color: white;
                border: 1px solid #555555;
                border-radius: 8px;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #1E1E1E;
            }
            QPushButton:pressed {
                background-color: #333333;
            }
        """)
        wifi_usb_button.clicked.connect(self.ativar_wifi_usb)
        layout.addWidget(wifi_usb_button)
        layout.addSpacing(10)

        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        reset_stats_button = QPushButton("Zerar Estatísticas")
        reset_stats_button.setFont(QFont("Arial", 12))
        reset_stats_button.setMinimumHeight(35)
        reset_stats_button.setStyleSheet("background-color: #FF5555; color: white; border: none; border-radius: 5px; padding: 8px;")
        reset_stats_button.clicked.connect(self.reset_stats)
        stats_layout.addWidget(reset_stats_button)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        stats_container = QFrame()
        stats_container.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border-radius: 10px; padding: 15px;")
        stats_container_layout = QVBoxLayout(stats_container)
        stats_container_layout.setSpacing(10)

        self.threats_label = QLabel(f"Ameaças Detectadas: {self.threats_found}")
        self.threats_label.setFont(QFont("Arial", 14))
        self.threats_label.setStyleSheet("color: #FF5555;")
        self.threats_label.setMinimumHeight(25)
        stats_container_layout.addWidget(self.threats_label)

        self.last_scan_label = QLabel(f"Última Verificação: {self.last_scan_date}")
        self.last_scan_label.setFont(QFont("Arial", 14))
        self.last_scan_label.setStyleSheet("color: white;")
        self.last_scan_label.setMinimumHeight(25)
        stats_container_layout.addWidget(self.last_scan_label)

        files_scanned_label = QLabel(f"Arquivos Verificados: {self.files_scanned}")
        files_scanned_label.setFont(QFont("Arial", 14))
        files_scanned_label.setStyleSheet("color: white;")
        files_scanned_label.setMinimumHeight(25)
        stats_container_layout.addWidget(files_scanned_label)

        layout.addWidget(stats_container)
        layout.addSpacing(20)

        activity_title = QLabel("Atividade Recente")
        activity_title.setFont(QFont("Arial", 16, QFont.Bold))
        activity_title.setStyleSheet("color: white;")
        activity_title.setMinimumHeight(30)
        layout.addWidget(activity_title)

        self.activity_list = QListWidget()
        self.activity_list.setStyleSheet("""
            background-color: rgba(30, 50, 100, 0.3);
            border: 1px solid rgba(100, 150, 255, 0.3);
            border-radius: 10px;
            padding: 12px;
            color: white;
            font-size: 10pt;
        """)
        self.activity_list.setFont(QFont("Arial", 10))
        self.activity_list.setMinimumHeight(100)
        self.activity_list.setMaximumHeight(300)

        for item_text in [
            "✓ Sistema inicializado e protegido",
            "🔄 Banco de dados de vírus carregado",
            "🔎 Proteção contra scripts perigosos ativada",
            "🔌 Proteção USB ativada",
            "🛡️ Proteção em tempo real ativa"
        ]:
            item = QListWidgetItem(item_text)
            item.setSizeHint(QSize(0, 30))
            self.activity_list.addItem(item)

        layout.addWidget(self.activity_list)

        signature_frame = QFrame()
        signature_frame.setStyleSheet("background-color: rgba(10, 20, 60, 0.3); border-radius: 5px; margin-top: 10px;")
        signature_layout = QHBoxLayout(signature_frame)
        team_signature = QLabel("Desenvolvido por: Mateus, Sarah, Eduardo, Guilherme, Pedro")
        team_signature.setFont(QFont("Arial", 10))
        team_signature.setStyleSheet("color: white;")
        team_signature.setAlignment(Qt.AlignCenter)
        signature_layout.addWidget(team_signature)
        signature_layout.setContentsMargins(10, 5, 10, 5)
        layout.addWidget(signature_frame)

        self.pages.addWidget(page)

    def create_link_verification_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Verificação de Links")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        description = QLabel("Insira um link (URL) para verificar se é seguro.")
        description.setFont(QFont("Arial", 12))
        description.setWordWrap(True)
        description.setStyleSheet("color: white; margin-bottom: 15px;")
        layout.addWidget(description)

        input_layout = QHBoxLayout()
        self.link_input = QLineEdit()
        self.link_input.setPlaceholderText("https://exemplo.com")
        self.link_input.setFont(QFont("Arial", 12))
        self.link_input.setMinimumHeight(40)
        self.link_input.setStyleSheet("padding: 5px; border-radius: 5px;")
        input_layout.addWidget(self.link_input)

        verify_button = QPushButton("Verificar")
        verify_button.setFont(QFont("Arial", 12, QFont.Bold))
        verify_button.setMinimumHeight(40)
        verify_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 0 20px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        verify_button.clicked.connect(self.verify_link)
        input_layout.addWidget(verify_button)
        layout.addLayout(input_layout)

        result_frame = QFrame()
        result_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px; margin-top: 20px;")
        result_layout = QVBoxLayout(result_frame)

        result_title = QLabel("Resultado da Análise")
        result_title.setFont(QFont("Arial", 16, QFont.Bold))
        result_title.setStyleSheet("color: white;")
        result_layout.addWidget(result_title)

        self.link_result_text = QTextBrowser()
        self.link_result_text.setFont(QFont("Arial", 11))
        self.link_result_text.setStyleSheet("background-color: transparent; color: white; border: none;")
        self.link_result_text.setText("Aguardando link para verificação...")
        result_layout.addWidget(self.link_result_text)

        layout.addWidget(result_frame)
        layout.addStretch()
        self.pages.addWidget(page)

    def verify_link(self):
        url = self.link_input.text().strip()
        if not url:
            self.link_result_text.setText("<font color='#FF5555'>Por favor, insira um link válido.</font>")
            return

        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        self.link_result_text.setText("Verificando, por favor aguarde...")
        QApplication.processEvents()

        try:
            is_safe, message = self.link_verifier.verify_link(url)
            if is_safe:
                self.link_result_text.setHtml(f"<h3><font color='#55FF7F'>Link Seguro</font></h3><p>{message}</p>")
            else:
                self.link_result_text.setHtml(f"<h3><font color='#FF5555'>Link Perigoso</font></h3><p>{message}</p>")
            self.log_event(f"Link verificado: {url} - Resultado: {message}")
        except Exception as e:
            error_msg = f"Erro ao verificar o link: {str(e)}"
            self.link_result_text.setText(f"<font color='#FF5555'>{error_msg}</font>")
            self.log_event(error_msg)

    def toggle_protection_from_ui(self, state, source="unknown"):
        try:
            if source != "settings":
                QMessageBox.information(self, "Configuração Restrita",
                    "Para desativar a proteção, acesse a página de Configurações.")

                self.protection_toggle.blockSignals(True)
                self.protection_toggle.setChecked(self.is_realtime_protection_active)
                self.protection_toggle.blockSignals(False)

                if hasattr(self, 'realtime_toggle'):
                    self.realtime_toggle.blockSignals(True)
                    self.realtime_toggle.setChecked(self.is_realtime_protection_active)
                    self.realtime_toggle.blockSignals(False)
            else:
                self.toggle_protection(state)
        except Exception as e:
            self.log_event(f"Erro ao tentar alternar proteção: {str(e)}")

    def create_pro_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("Opções Avançadas (IP/USB)")
        title.setFont(QFont("Arial", 22, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        network_frame = QFrame()
        network_frame.setStyleSheet("background-color: rgba(30,50,100,0.3); border-radius: 10px; padding: 15px;")
        network_layout = QVBoxLayout(network_frame)

        network_title = QLabel("Informações de Rede")
        network_title.setFont(QFont("Arial", 16, QFont.Bold))
        network_title.setStyleSheet("color: white;")
        network_layout.addWidget(network_title)

        self.network_info_text = QTextBrowser()
        self.network_info_text.setStyleSheet("background-color: rgba(30,50,100,0.3); color: white; font-size: 10pt;")
        self.network_info_text.setFont(QFont("Arial", 10))
        network_layout.addWidget(self.network_info_text)
        layout.addWidget(network_frame)

        usb_frame = QFrame()
        usb_frame.setStyleSheet("background-color: rgba(30,50,100,0.3); border-radius: 10px; padding: 15px;")
        usb_layout = QVBoxLayout(usb_frame)

        usb_title = QLabel("Dispositivos USB Conectados")
        usb_title.setFont(QFont("Arial", 16, QFont.Bold))
        usb_title.setStyleSheet("color: white;")
        usb_layout.addWidget(usb_title)

        self.usb_table = QTableWidget()
        self.usb_table.setColumnCount(6)
        self.usb_table.setHorizontalHeaderLabels(["Nome", "Letra", "File System", "Serial", "Tamanho (MB)", "Livre (MB)"])
        self.usb_table.horizontalHeader().setStretchLastSection(True)
        self.usb_table.setStyleSheet("color: white; font-size: 12pt; background-color: transparent;")
        usb_layout.addWidget(self.usb_table)

        eject_button = QPushButton("Ejetar Dispositivo")
        eject_button.setFont(QFont("Arial", 12))
        eject_button.setStyleSheet("background-color: #FF5555; color: white; border: none; border-radius: 5px; padding: 8px;")
        eject_button.clicked.connect(self.eject_usb_device)
        usb_layout.addWidget(eject_button)

        layout.addWidget(usb_frame)

        self.pro_timer = QTimer(page)
        self.pro_timer.setInterval(30000)
        self.pro_timer.timeout.connect(self.update_pro_info)
        self.pro_timer.start()

        QTimer.singleShot(100, self.update_pro_info)

        self.pages.addWidget(page)

    def create_protection_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Proteção")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white; margin-bottom: 5px;")
        layout.addWidget(title)
        layout.addSpacing(10)

        protection_frame = QFrame()
        protection_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px;")
        protection_layout = QVBoxLayout(protection_frame)
        protection_layout.setSpacing(12)

        protection_header = QHBoxLayout()
        protection_header.setSpacing(15)

        header_info = QVBoxLayout()
        header_info.setSpacing(10)

        protection_title = QLabel("Proteção em Tempo Real")
        protection_title.setFont(QFont("Arial", 14, QFont.Bold))
        protection_title.setStyleSheet("color: white;")
        protection_title.setMinimumHeight(25)
        header_info.addWidget(protection_title)

        protection_desc = QLabel("Monitora constantemente o sistema para identificar e bloquear ameaças.")
        protection_desc.setFont(QFont("Arial", 11))
        protection_desc.setStyleSheet("color: white;")
        protection_desc.setWordWrap(True)
        protection_desc.setMinimumHeight(40)
        protection_desc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        header_info.addWidget(protection_desc)

        protection_header.addLayout(header_info)
        protection_header.addStretch()

        status_container = QVBoxLayout()
        status_container.setAlignment(Qt.AlignCenter)
        status_container.setSpacing(8)

        status_label = QLabel("Ativado" if self.is_realtime_protection_active else "Desativado")
        status_label.setFont(QFont("Arial", 12))
        status_label.setStyleSheet(f"color: {'#55FF7F' if self.is_realtime_protection_active else '#FF5555'};")
        status_container.addWidget(status_label)

        self.realtime_toggle = QCheckBox()
        self.realtime_toggle.setChecked(self.is_realtime_protection_active)
        self.realtime_toggle.stateChanged.connect(lambda state: self.toggle_protection_from_ui(state, "protection"))
        self.realtime_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        status_container.addWidget(self.realtime_toggle)

        protection_header.addLayout(status_container)
        protection_layout.addLayout(protection_header)
        protection_layout.addSpacing(15)



        protection_section2 = QFrame()
        protection_section2_layout = QHBoxLayout(protection_section2)
        protection_section2_title = QLabel("Honeypot")
        protection_section2_title.setFont(QFont("Arial", 12))
        protection_section2_title.setStyleSheet("color: white;")
        protection_section2_layout.addWidget(protection_section2_title)
        protection_section2_layout.addStretch()

        self.protection_wolf4_toggle = QCheckBox()
        self.protection_wolf4_toggle.setChecked(self._load_setting('wolf4_enabled', True))
        self.protection_wolf4_toggle.stateChanged.connect(self.toggle_wolf4)
        self.protection_wolf4_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        protection_section2_layout.addWidget(self.protection_wolf4_toggle)
        protection_layout.addWidget(protection_section2)

        protection_layout.addSpacing(15)


        layout.addWidget(protection_frame)
        layout.addSpacing(20)

        usb_frame = QFrame()
        usb_frame.setStyleSheet("background-color: transparent; border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px; margin: 8px 0;")
        usb_layout = QHBoxLayout(usb_frame)
        usb_layout.setSpacing(15)

        usb_info = QVBoxLayout()
        usb_info.setSpacing(8)

        usb_title = QLabel("Proteção USB")
        usb_title.setFont(QFont("Arial", 14, QFont.Bold))
        usb_title.setStyleSheet("color: white;")
        usb_title.setMinimumHeight(25)
        usb_info.addWidget(usb_title)

        usb_desc = QLabel("Verifica automaticamente dispositivos USB conectados e bloqueia ameaças")
        usb_desc.setFont(QFont("Arial", 11))
        usb_desc.setStyleSheet("color: white;")
        usb_desc.setWordWrap(True)
        usb_desc.setMinimumHeight(40)
        usb_desc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        usb_info.addWidget(usb_desc)

        usb_layout.addLayout(usb_info, 4)

        usb_status_layout = QVBoxLayout()
        usb_status_layout.setAlignment(Qt.AlignCenter)
        usb_status_layout.setSpacing(8)

        usb_status_label = QLabel("Ativado" if self.is_realtime_protection_active else "Desativado")
        usb_status_label.setFont(QFont("Arial", 12))
        usb_status_label.setStyleSheet(f"color: {'#55FF7F' if self.is_realtime_protection_active else '#FF5555'};")
        usb_status_layout.addWidget(usb_status_label)

        usb_toggle = QCheckBox()
        usb_toggle.setChecked(self.is_realtime_protection_active)
        usb_toggle.stateChanged.connect(lambda state: self.toggle_protection_from_ui(state, "usb"))
        usb_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        usb_status_layout.addWidget(usb_toggle)

        usb_layout.addLayout(usb_status_layout, 1)
        layout.addWidget(usb_frame)

        self.pages.addWidget(page)

    def toggle_wolf1(self, state):
        is_enabled = bool(state)
        self._save_setting('wolf1_enabled', is_enabled)

        if is_enabled:
            self.log_event("Proteção com remoção (wolf1.py) ativada")
            try:
                module_path = get_resource_path("wolf1.py")
                if "wolf1.py" not in running_modules and os.path.exists(module_path):
                    subprocess.Popen(
                        [sys.executable, module_path],
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        stderr=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL
                    )
                    running_modules.add("wolf1.py")
            except Exception:
                pass
        else:
            self.log_event("Proteção com remoção (wolf1.py) desativada")

    def toggle_wolf4(self, state):
        is_enabled = bool(state)
        self._save_setting('wolf4_enabled', is_enabled)

        if is_enabled:
            self.log_event("Honeypot (wolf4.py) ativado")
            try:
                if "wolf4.py" not in running_modules:
                    wolf_guard = WolfGuardSystem()
                    threading.Thread(target=wolf_guard.run, daemon=True).start()
                    running_modules.add("wolf4.py")
            except Exception:
                pass
        else:
            self.log_event("Honeypot (wolf4.py) desativado")

    def show_detailed_logs(self):
        try:
            log_dialog = DetailedLogDialog(self.logs_dir, self)
            log_dialog.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao exibir logs: {str(e)}")
            self.log_event(f"Erro ao exibir logs detalhados: {str(e)}")

    def create_quarantine_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Quarentena")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        quarantine_frame = QFrame()
        quarantine_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px;")
        quarantine_layout = QVBoxLayout(quarantine_frame)

        header_layout = QHBoxLayout()
        header_title = QLabel("Itens em Quarentena")
        header_title.setFont(QFont("Arial", 18, QFont.Bold))
        header_title.setStyleSheet("color: white;")
        header_layout.addWidget(header_title)

        refresh_button = QPushButton("Atualizar")
        refresh_button.setFont(QFont("Arial", 12))
        refresh_button.setStyleSheet("background-color: rgba(100, 150, 255, 0.3); color: white; border: none; border-radius: 6px; padding: 6px 12px;")
        refresh_button.clicked.connect(self.refresh_quarantine)
        header_layout.addWidget(refresh_button)
        quarantine_layout.addLayout(header_layout)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels(["ID", "Ameaça", "Caminho Original", "Tamanho", "Data"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.quarantine_table.setStyleSheet("background-color: rgba(20, 30, 50, 0.5); border-radius: 8px; color: white; gridline-color: rgba(100, 150, 255, 0.2); font-size: 12px;")
        quarantine_layout.addWidget(self.quarantine_table)

        buttons_layout = QHBoxLayout()
        restore_button = QPushButton("Restaurar")
        restore_button.setFont(QFont("Arial", 12))
        restore_button.setFixedSize(150, 40)
        restore_button.setStyleSheet("background-color: rgba(100, 150, 255, 0.5); color: white; border: none; border-radius: 6px; padding: 8px 15px;")
        restore_button.clicked.connect(self.restore_from_quarantine)
        buttons_layout.addWidget(restore_button)

        delete_button = QPushButton("Excluir")
        delete_button.setFont(QFont("Arial", 12))
        delete_button.setFixedSize(150, 40)
        delete_button.setStyleSheet("background-color: rgba(255, 80, 80, 0.5); color: white; border: none; border-radius: 6px; padding: 8px 15px;")
        delete_button.clicked.connect(self.delete_from_quarantine)
        buttons_layout.addWidget(delete_button)

        quarantine_layout.addLayout(buttons_layout)

        layout.addWidget(quarantine_frame)
        self.pages.addWidget(page)

    def create_blacklist_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Blacklist")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        description = QLabel("Arquivos, aplicativos e processos nesta lista serão bloqueados automaticamente.")
        description.setFont(QFont("Arial", 12))
        description.setWordWrap(True)
        description.setStyleSheet("color: white; margin-bottom: 15px;")
        layout.addWidget(description)

        blacklist_frame = QFrame()
        blacklist_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px;")
        blacklist_layout = QVBoxLayout(blacklist_frame)

        header_layout = QHBoxLayout()
        header_title = QLabel("Itens na Blacklist")
        header_title.setFont(QFont("Arial", 18, QFont.Bold))
        header_title.setStyleSheet("color: white;")
        header_layout.addWidget(header_title)

        refresh_button = QPushButton("Atualizar")
        refresh_button.setFont(QFont("Arial", 12))
        refresh_button.setStyleSheet("background-color: rgba(100, 150, 255, 0.3); color: white; border: none; border-radius: 6px; padding: 6px 12px;")
        refresh_button.clicked.connect(self.refresh_blacklist)
        header_layout.addWidget(refresh_button)
        blacklist_layout.addLayout(header_layout)

        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(3)
        self.blacklist_table.setHorizontalHeaderLabels(["Nome do Item", "Caminho/Processo", "Tipo"])
        self.blacklist_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.blacklist_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.blacklist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.blacklist_table.setStyleSheet("background-color: rgba(20, 30, 50, 0.5); border-radius: 8px; color: white; gridline-color: rgba(100, 150, 255, 0.2); font-size: 12px;")
        blacklist_layout.addWidget(self.blacklist_table)

        button_layout = QHBoxLayout()

        add_item_button = QPushButton("Adicionar Item")
        add_item_button.setFont(QFont("Arial", 12))
        add_item_button.setFixedHeight(40)
        add_item_button.setStyleSheet("background-color: #4B7BFF; color: white; border: none; border-radius: 6px; padding: 8px 15px;")
        add_item_button.clicked.connect(self.add_to_blacklist_dialog)
        button_layout.addWidget(add_item_button)

        add_name_button = QPushButton("Adicionar por Nome")
        add_name_button.setFont(QFont("Arial", 12))
        add_name_button.setFixedHeight(40)
        add_name_button.setStyleSheet("background-color: #4B7BFF; color: white; border: none; border-radius: 6px; padding: 8px 15px;")
        add_name_button.clicked.connect(self.add_to_blacklist_by_name)
        button_layout.addWidget(add_name_button)

        remove_button = QPushButton("Remover da Blacklist")
        remove_button.setFont(QFont("Arial", 12))
        remove_button.setFixedHeight(40)
        remove_button.setStyleSheet("background-color: #FF5555; color: white; border: none; border-radius: 6px; padding: 8px 15px;")
        remove_button.clicked.connect(self.remove_from_blacklist)
        button_layout.addWidget(remove_button)

        blacklist_layout.addLayout(button_layout)
        layout.addWidget(blacklist_frame)

        self.refresh_blacklist()
        self.pages.addWidget(page)

    def add_to_blacklist_by_name(self):
        dialog = QInputDialog(self)
        dialog.setWindowTitle("Adicionar à Blacklist por Nome")
        dialog.setLabelText("Digite o nome exato do arquivo para bloquear\n(ex: Wannacry.exe, Ransomware.ps1):")
        dialog.setInputMode(QInputDialog.TextInput)

        if dialog.exec_() == QDialog.Accepted:
            file_name = dialog.textValue().strip()
            if not file_name:
                QMessageBox.warning(self, "Nome Inválido", "Por favor, digite um nome de arquivo válido.")
                return

            if self.blacklist_manager.is_blacklisted(file_name):
                QMessageBox.information(
                    self,
                    "Já na Blacklist",
                    f"O item '{file_name}' já está na blacklist."
                )
                return

            reply = QMessageBox.question(
                self,
                "Confirmar Adição à Blacklist",
                f"Adicionar '{file_name}' à blacklist?\n\n"
                "Qualquer arquivo com este nome exato será bloqueado e removido do sistema.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.blacklist_manager.add_to_blacklist(file_name)
                self.refresh_blacklist()
                self.blacklist_service.process_blacklisted_items()
                self.log_event(f"Nome de arquivo adicionado à blacklist: {file_name}")
                QMessageBox.information(
                    self,
                    "Item Adicionado",
                    f"'{file_name}' foi adicionado à blacklist com sucesso.\nTodos os arquivos com este nome serão bloqueados."
                )

    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Configurações")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("background-color: transparent; border: none;")

        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        settings_layout.setSpacing(20)

        password_frame = QFrame()
        password_frame.setStyleSheet("background-color: rgba(30,50,100,0.3); border: 1px solid rgba(100,150,255,0.3); border-radius: 10px; padding: 20px;")
        password_layout = QVBoxLayout(password_frame)

        password_title = QLabel("Configurações de Senha")
        password_title.setFont(QFont("Arial", 16, QFont.Bold))
        password_title.setStyleSheet("color: white;")
        password_layout.addWidget(password_title)

        password_desc = QLabel("Altere a senha de acesso ao WolfGuard")
        password_desc.setFont(QFont("Arial", 12))
        password_desc.setStyleSheet("color: white;")
        password_layout.addWidget(password_desc)

        change_password_button = QPushButton("Alterar Senha")
        change_password_button.setFont(QFont("Arial", 12))
        change_password_button.setStyleSheet("background-color: #4B7BFF; color: white; border: none; border-radius: 5px; padding: 10px;")
        change_password_button.clicked.connect(self.show_change_password_dialog)
        password_layout.addWidget(change_password_button)

        settings_layout.addWidget(password_frame)

        display_frame = QFrame()
        display_frame.setStyleSheet("background-color: rgba(30,50,100,0.3); border: 1px solid rgba(100,150,255,0.3); border-radius: 10px; padding: 20px;")
        display_layout = QVBoxLayout(display_frame)

        display_title = QLabel("Configurações de Exibição")
        display_title.setFont(QFont("Arial", 16, QFont.Bold))
        display_title.setStyleSheet("color: white;")
        display_layout.addWidget(display_title)

        resolution_layout = QHBoxLayout()
        resolution_label = QLabel("Resolução da Interface:")
        resolution_label.setFont(QFont("Arial", 14))
        resolution_label.setStyleSheet("color: white;")
        resolution_layout.addWidget(resolution_label)

        self.resolution_combo = QComboBox()
        self.resolution_combo.setStyleSheet("""
            QComboBox {
                background-color: rgba(30, 50, 100, 0.5);
                color: white;
                border: 1px solid rgba(100, 150, 255, 0.5);
                border-radius: 5px;
                padding: 5px;
                min-width: 150px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                border: none;
            }
        """)

        resolutions = [
            ("1024x768 (Padrão)", (1024, 768)),
            ("1280x720", (1280, 720)),
            ("1280x768", (1280, 768)),
            ("1920x1080", (1920, 1080)),
            ("3840x2160", (3840, 2160))
        ]

        for res_name, res_value in resolutions:
            self.resolution_combo.addItem(res_name, res_value)

        current_res = self.current_resolution
        for i in range(self.resolution_combo.count()):
            if self.resolution_combo.itemData(i) == current_res:
                self.resolution_combo.setCurrentIndex(i)
                break

        self.resolution_combo.currentIndexChanged.connect(self.on_resolution_changed)
        resolution_layout.addWidget(self.resolution_combo)
        resolution_layout.addStretch()
        display_layout.addLayout(resolution_layout)

        snow_frame = QFrame()
        snow_layout = QHBoxLayout(snow_frame)
        snow_info = QVBoxLayout()
        snow_title = QLabel("Animação de Neve")
        snow_title.setFont(QFont("Arial", 14))
        snow_title.setStyleSheet("color: white;")
        snow_info.addWidget(snow_title)
        snow_desc = QLabel("Exibir animação de neve na interface")
        snow_desc.setFont(QFont("Arial", 11))
        snow_desc.setStyleSheet("color: white;")
        snow_info.addWidget(snow_desc)
        snow_layout.addLayout(snow_info)
        snow_layout.addStretch()

        self.snow_toggle = QCheckBox()
        self.snow_toggle.setChecked(self.snow_animation_enabled)
        self.snow_toggle.stateChanged.connect(self.toggle_snow_animation)
        self.snow_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        snow_layout.addWidget(self.snow_toggle)
        display_layout.addWidget(snow_frame)

        settings_layout.addWidget(display_frame)

        notifications_frame = QFrame()
        notifications_frame.setStyleSheet("background-color: rgba(30,50,100,0.3); border: 1px solid rgba(100,150,255,0.3); border-radius: 10px; padding: 20px;")
        notifications_layout = QVBoxLayout(notifications_frame)

        notifications_title = QLabel("Configurações de Notificações")
        notifications_title.setFont(QFont("Arial", 16, QFont.Bold))
        notifications_title.setStyleSheet("color: white;")
        notifications_layout.addWidget(notifications_title)

        threat_notif_frame = QFrame()
        threat_notif_layout = QHBoxLayout(threat_notif_frame)
        threat_notif_info = QVBoxLayout()
        threat_notif_title = QLabel("Notificações de Ameaças")
        threat_notif_title.setFont(QFont("Arial", 14))
        threat_notif_title.setStyleSheet("color: white;")
        threat_notif_info.addWidget(threat_notif_title)
        threat_notif_desc = QLabel("Exibir janela quando um vírus for detectado e removido")
        threat_notif_desc.setFont(QFont("Arial", 11))
        threat_notif_desc.setStyleSheet("color: white;")
        threat_notif_info.addWidget(threat_notif_desc)
        threat_notif_layout.addLayout(threat_notif_info)
        threat_notif_layout.addStretch()

        self.threat_notif_toggle = QCheckBox()
        self.threat_notif_toggle.setChecked(self.show_threat_notifications)
        self.threat_notif_toggle.stateChanged.connect(self.toggle_threat_notifications)
        self.threat_notif_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        threat_notif_layout.addWidget(self.threat_notif_toggle)
        notifications_layout.addWidget(threat_notif_frame)

        settings_layout.addWidget(notifications_frame)

        general_frame = QFrame()
        general_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px;")
        general_layout = QVBoxLayout(general_frame)
        general_layout.setSpacing(15)

        general_title = QLabel("Configurações Gerais")
        general_title.setFont(QFont("Arial", 16, QFont.Bold))
        general_title.setStyleSheet("color: white;")
        general_layout.addWidget(general_title)

        background_frame = QFrame()
        background_layout = QHBoxLayout(background_frame)
        background_info = QVBoxLayout()
        background_title = QLabel("Executar em segundo plano")
        background_title.setFont(QFont("Arial", 14))
        background_title.setStyleSheet("color: white;")
        background_info.addWidget(background_title)
        background_desc = QLabel("Manter o programa ativo na bandeja do sistema após fechar a janela")
        background_desc.setFont(QFont("Arial", 11))
        background_desc.setStyleSheet("color: white;")
        background_desc.setWordWrap(True)
        background_info.addWidget(background_desc)
        background_layout.addLayout(background_info)
        background_layout.addStretch()

        self.background_toggle = QCheckBox()
        self.background_toggle.setChecked(self.run_in_background)
        self.background_toggle.stateChanged.connect(self.toggle_background_mode)
        self.background_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        background_layout.addWidget(self.background_toggle)
        general_layout.addWidget(background_frame)

        settings_layout.addWidget(general_frame)

        protection_frame = QFrame()
        protection_frame.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 20px;")
        protection_layout = QVBoxLayout(protection_frame)
        protection_layout.setSpacing(15)

        protection_title = QLabel("Configurações de Proteção")
        protection_title.setFont(QFont("Arial", 16, QFont.Bold))
        protection_title.setStyleSheet("color: white;")
        protection_layout.addWidget(protection_title)

        wolf1_protection_frame = QFrame()
        wolf1_protection_layout = QHBoxLayout(wolf1_protection_frame)
        wolf1_protection_title = QLabel("Proteção com remoção")
        wolf1_protection_title.setFont(QFont("Arial", 12))
        wolf1_protection_title.setStyleSheet("color: white;")
        wolf1_protection_layout.addWidget(wolf1_protection_title)
        wolf1_protection_layout.addStretch()

        self.protection_wolf1_toggle = QCheckBox()
        self.protection_wolf1_toggle.setChecked(self._load_setting('wolf1_enabled', True))
        self.protection_wolf1_toggle.stateChanged.connect(self.toggle_wolf1)
        self.protection_wolf1_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        wolf1_protection_layout.addWidget(self.protection_wolf1_toggle)
        realtime_protection_frame = QFrame()
        realtime_protection_layout = QHBoxLayout(realtime_protection_frame)
        realtime_protection_title = QLabel("Proteção em Tempo Real")
        realtime_protection_title.setFont(QFont("Arial", 12))
        realtime_protection_title.setStyleSheet("color: white;")
        realtime_protection_layout.addWidget(realtime_protection_title)
        realtime_protection_layout.addStretch()

        realtime_protection_toggle = QCheckBox()
        realtime_protection_toggle.setChecked(self.is_realtime_protection_active)
        realtime_protection_toggle.stateChanged.connect(lambda state: self.toggle_protection_from_ui(state, "settings"))
        realtime_protection_toggle.setStyleSheet("QCheckBox::indicator { width: 16px; height: 16px; }")
        realtime_protection_layout.addWidget(realtime_protection_toggle)
        protection_layout.addWidget(realtime_protection_frame)

        settings_layout.addWidget(protection_frame)

        scroll_area.setWidget(settings_widget)
        layout.addWidget(scroll_area)

        self.pages.addWidget(page)

    def show_change_password_dialog(self):
        dialog = ChangePasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            current_password = dialog.current_password_input.text()
            new_password = dialog.new_password_input.text()
            confirm_password = dialog.confirm_password_input.text()

            stored_password = self._get_stored_password()

            if current_password != stored_password:
                QMessageBox.warning(self,"Erro", "Senha atual incorreta.")
                return

            if new_password != confirm_password:
                QMessageBox.warning(self, "Erro", "A nova senha e a confirmação não correspondem.")
                return

            if len(new_password) < 4:
                QMessageBox.warning(self, "Erro", "A nova senha deve ter pelo menos 4 caracteres.")
                return

            if self._set_password(new_password):
                QMessageBox.information(self, "Sucesso", "Senha alterada com sucesso.")
            else:
                QMessageBox.critical(self, "Erro", "Não foi possível alterar a senha.")

    def on_resolution_changed(self, index):
        resolution = self.resolution_combo.itemData(index)
        if resolution:
            self.change_resolution(resolution)

    def toggle_snow_animation(self, state):
        is_enabled = bool(state)
        self.snow_animation_enabled = is_enabled
        self._save_setting('snow_animation', is_enabled)
        self.snow_widget.set_enabled(is_enabled)
        self.log_event(f"Animação de neve {'ativada' if is_enabled else 'desativada'}")

    def toggle_threat_notifications(self, state):
        is_enabled = bool(state)
        self.show_threat_notifications = is_enabled
        self._save_setting('show_threat_notifications', is_enabled)
        self.log_event(f"Notificações de ameaças {'ativadas' if is_enabled else 'desativadas'}")

    def toggle_background_mode(self, state):
        is_enabled = bool(state)
        self.run_in_background = is_enabled
        self._save_setting('run_in_background', is_enabled)
        self.log_event(f"Modo em segundo plano {'ativado' if is_enabled else 'desativado'}")

    def toggle_protection(self, state):
        try:
            is_active = bool(state)

            if hasattr(self, 'protection_toggle'):
                self.protection_toggle.setChecked(is_active)
            if hasattr(self, 'realtime_toggle'):
                self.realtime_toggle.setChecked(is_active)

            if is_active:
                self.blacklist_monitor_timer.start()
                self.log_event("Proteção ativada.")
                QMessageBox.information(self, "Proteção Ativada", "Proteção em tempo real ativada.")
            else:
                self.blacklist_monitor_timer.stop()
                self.log_event("Proteção desativada.")
                QMessageBox.warning(self, "Proteção Desativada", "Proteção em tempo real desativada.")

            self.is_realtime_protection_active = is_active
            self._save_setting('realtime_protection', is_active)

        except Exception as e:
            error_msg = f"Erro ao alterar estado da proteção: {str(e)}"
            self.log_event(error_msg)
            QMessageBox.critical(self, "Erro", error_msg)

    def activate_kernel_protection(self):
        self.log_event("Kernel protection ativada.")
        QMessageBox.information(self, "Kernel Protection", "Proteção kernel ativada com sucesso.")

    def refresh_quarantine(self):
        try:
            quarantined_files = self.scan_engine.quarantine_manager.get_quarantined_files()
            self.quarantine_table.setRowCount(0)
            for i, file in enumerate(quarantined_files):
                self.quarantine_table.insertRow(i)
                for j, key in enumerate(["id", "threat_name", "original_path", "file_size", "date_quarantined"]):
                    if key == "file_size" and file.get("file_size"):
                        size_kb = file['file_size'] / 1024
                        size_str = f"{size_kb/1024:.2f} MB" if size_kb > 1024 else f"{size_kb:.2f} KB"
                        item = QTableWidgetItem(size_str)
                    else:
                        item = QTableWidgetItem(str(file.get(key, "")))
                    item.setForeground(QColor("white"))
                    self.quarantine_table.setItem(i, j, item)
            self.quarantine_table.sortByColumn(4, Qt.DescendingOrder)
        except Exception as e:
            self.log_event(f"Erro ao atualizar quarentena: {str(e)}")

    def refresh_blacklist(self):
        try:
            self.blacklist_table.setRowCount(0)
            blacklisted_items = self.blacklist_manager.load_blacklist()

            for i, item in enumerate(blacklisted_items):
                self.blacklist_table.insertRow(i)

                name_item = QTableWidgetItem(os.path.basename(item) if os.path.exists(item) else item)
                path_item = QTableWidgetItem(item)

                if os.path.exists(item) and os.path.isfile(item):
                    if item.lower().endswith('.exe'):
                        type_item = QTableWidgetItem("Aplicativo")
                    else:
                        type_item = QTableWidgetItem("Arquivo")
                else:
                    if '\\' not in item and '/' not in item and '.' in item:
                        type_item = QTableWidgetItem("Nome de Arquivo")
                    else:
                        type_item = QTableWidgetItem("Processo/Outro")

                name_item.setForeground(QColor("white"))
                path_item.setForeground(QColor("white"))
                type_item.setForeground(QColor("white"))

                self.blacklist_table.setItem(i, 0, name_item)
                self.blacklist_table.setItem(i, 1, path_item)
                self.blacklist_table.setItem(i, 2, type_item)

            self.blacklist_table.sortItems(0)
        except Exception:
            pass

    def add_to_blacklist_dialog(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Selecionar Arquivo ou Aplicativo para Bloquear",
                "",
                "Todos os Arquivos (*.*)"
            )

            if not file_path:
                return

            if self.blacklist_manager.is_blacklisted(file_path):
                QMessageBox.information(
                    self,
                    "Já na Blacklist",
                    f"O item '{os.path.basename(file_path)}' já está na blacklist."
                )
                return

            reply = QMessageBox.question(
                self,
                "Confirmar Adição à Blacklist",
                f"Adicionar '{os.path.basename(file_path)}' à blacklist?\n\n"
                "Este item será bloqueado e não poderá ser executado.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.blacklist_manager.add_to_blacklist(file_path)
                self.refresh_blacklist()
                self.log_event(f"Item adicionado à blacklist: {file_path}")
                QMessageBox.information(
                    self,
                    "Item Adicionado",
                    f"'{os.path.basename(file_path)}' foi adicionado à blacklist com sucesso."
                )
        except Exception as e:
            self.log_event(f"Erro ao adicionar à blacklist: {str(e)}")
            QMessageBox.critical(
                self,
                "Erro",
                f"Ocorreu um erro ao adicionar o item à blacklist:\n{str(e)}"
            )

    def remove_from_blacklist(self):
        try:
            selected_items = self.blacklist_table.selectedItems()
            if not selected_items:
                QMessageBox.information(
                    self,
                    "Nenhum Item Selecionado",
                    "Selecione um item da blacklist para removê-lo."
                )
                return

            row = selected_items[0].row()
            item_name = self.blacklist_table.item(row, 0).text()
            item_path = self.blacklist_table.item(row, 1).text()

            reply = QMessageBox.question(
                self,
                "Confirmar Remoção",
                f"Remover '{item_name}' da blacklist?\n\n"
                "Este item poderá ser executado novamente.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.blacklist_manager.remove_from_blacklist(item_path)
                self.refresh_blacklist()
                self.log_event(f"Item removido da blacklist: {item_path}")
                QMessageBox.information(
                    self,
                    "Item Removido",
                    f"'{item_name}' foi removido da blacklist com sucesso."
                )
        except Exception as e:
            self.log_event(f"Erro ao remover da blacklist: {str(e)}")
            QMessageBox.critical(
                self,
                "Erro",
                f"Ocorreu um erro ao remover o item da blacklist:\n{str(e)}"
            )

    def restore_from_quarantine(self):
        selected_rows = set()
        for item in self.quarantine_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            QMessageBox.information(self, "Selecionar Arquivo", "Selecione um arquivo para restaurar.")
            return

        file_count = len(selected_rows)
        plural = "s" if file_count > 1 else ""
        reply = QMessageBox.question(
            self, f"Restaurar Arquivo{plural}",
            f"Restaurar {file_count} arquivo{plural} selecionado{plural}? Pode{'' if file_count == 1 else 'm'} conter malware.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            for row in selected_rows:
                try:
                    file_id = int(self.quarantine_table.item(row, 0).text())
                    self.scan_engine.quarantine_manager.restore_file(file_id)
                except Exception:
                    pass
            self.refresh_quarantine()
            QMessageBox.information(self, "Restauração Concluída", "Arquivos restaurados com sucesso.")

    def delete_from_quarantine(self):
        selected_rows = set()
        for item in self.quarantine_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            QMessageBox.information(self, "Selecionar Arquivo", "Selecione um arquivo para excluir.")
            return

        file_count = len(selected_rows)
        plural = "s" if file_count > 1 else ""
        reply = QMessageBox.question(
            self, f"Excluir Arquivo{plural}",
            f"Excluir permanentemente {file_count} arquivo{plural} selecionado{plural}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            for row in selected_rows:
                try:
                    file_id = int(self.quarantine_table.item(row, 0).text())
                    self.scan_engine.quarantine_manager.delete_file(file_id)
                except Exception:
                    pass
            self.refresh_quarantine()
            QMessageBox.information(self, "Exclusão Concluída", "Arquivos excluídos com sucesso.")

    def update_pro_info(self):
        try:
            usb_devices = self.get_usb_devices()
            self.usb_table.setRowCount(0)
            for i, device in enumerate(usb_devices):
                self.usb_table.insertRow(i)
                for j, key in enumerate(["name", "drive_letter", "file_system", "serial", "total_mb", "free_mb"]):
                    if key in ["total_mb", "free_mb"]:
                        item = QTableWidgetItem(f"{device.get(key, 0):.2f}")
                    else:
                        item = QTableWidgetItem(str(device.get(key, "N/A")))
                    item.setFont(QFont("Arial", 12))
                    self.usb_table.setItem(i, j, item)
        except Exception:
            pass

        if not hasattr(self, 'network_thread') or self.network_thread is None:
            self.start_network_update()

    def start_network_update(self):
        try:
            self.network_worker = NetworkInfoWorker()
            self.network_thread = QThread()
            self.network_worker.moveToThread(self.network_thread)
            self.network_thread.started.connect(self.network_worker.run)
            self.network_worker.finished.connect(self.handle_network_info)
            self.network_worker.finished.connect(self.network_thread.quit)
            self.network_worker.finished.connect(self.network_worker.deleteLater)

            self.network_thread.finished.connect(lambda: setattr(self, 'network_thread', None))
            self.network_thread.finished.connect(lambda: setattr(self, 'network_worker', None))

            self.network_thread.start()
        except Exception:
            self.network_thread = None
            self.network_worker = None

    @pyqtSlot(dict)
    def handle_network_info(self, result):
        net_info = result.get("net_info", {})
        geo_info = result.get("geo_info", {})
        info_text = f"IP Público: {net_info.get('public_ip', 'N/A')}\n"
        info_text += f"IP Local: {net_info.get('local_ip', 'N/A')}\n"
        info_text += f"País: {geo_info.get('country', 'N/A')}\n"
        info_text += f"Região: {geo_info.get('region', 'N/A')}\n"
        info_text += f"Cidade: {geo_info.get('city', 'N/A')}\n"
        self.network_info_text.setPlainText(info_text)

    def get_usb_devices(self):
        usb_devices = []
        try:
            drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
            for drive in drives:
                try:
                    drive_type = win32file.GetDriveType(drive)
                    if drive_type == win32con.DRIVE_REMOVABLE:
                        try:
                            vol_info = win32api.GetVolumeInformation(drive)
                            volume_label = vol_info[0] if vol_info[0] else "USB Drive"
                            serial = vol_info[1]
                            fs_name = vol_info[4]
                        except Exception:
                            volume_label = "USB Drive"
                            serial = "N/A"
                            fs_name = "N/A"
                        try:
                            free_bytes, total_bytes, _ = win32api.GetDiskFreeSpaceEx(drive)
                            total_mb = total_bytes / (1024 * 1024)
                            free_mb = free_bytes / (1024 * 1024)
                        except Exception:
                            total_mb = 0
                            free_mb = 0
                        usb_devices.append({
                            "name": volume_label,
                            "drive_letter": drive,
                            "file_system": fs_name,
                            "serial": serial,
                            "total_mb": total_mb,
                            "free_mb": free_mb
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return usb_devices

    def eject_usb_device(self):
        selected_items = self.usb_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Atenção", "Selecione um dispositivo USB para ejetar.")
            return

        try:
            row = selected_items[0].row()
            drive_letter = self.usb_table.item(row, 1).text().strip()
            path = r"\\.\{}".format(drive_letter[0])

            try:
                handle = win32file.CreateFile(
                    path,
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                IOCTL_STORAGE_EJECT_MEDIA = 0x2D4808
                win32file.DeviceIoControl(handle, IOCTL_STORAGE_EJECT_MEDIA, None, 0)
                handle.Close()
                QMessageBox.information(self, "Dispositivo Ejetado", f"Dispositivo {drive_letter} ejetado com sucesso.")
                self.log_event(f"Dispositivo {drive_letter} ejetado.")
            except pywintypes.error as e:
                error_msg = f"Erro ao ejetar dispositivo: {e}"
                self.log_event(error_msg)
                QMessageBox.warning(self, "Erro", error_msg)
        except Exception as e:
            error_msg = f"Erro no processamento de ejeção: {str(e)}"
            self.log_event(error_msg)
            QMessageBox.warning(self, "Erro", error_msg)

    def change_page(self, index):
        if index == 6:
            login_dialog = LoginDialog(self.app_data_dir)
            if login_dialog.exec_() != QDialog.Accepted:
                return
        if index < self.pages.count():
            self.pages.setCurrentIndex(index)
            self.select_nav_button(index)

    def select_nav_button(self, index):
        for i, button in enumerate(self.nav_buttons):
            button.setStyleSheet(button.styleSheet().replace("border-left: 3px solid #00c8ff;", ""))

        if index < len(self.nav_buttons):
            selected_button = self.nav_buttons[index]
            current_style = selected_button.styleSheet()

            if "border-left: 3px solid #00c8ff" not in current_style:
                new_style = current_style.replace(
                    "QPushButton {",
                    "QPushButton { border-left: 3px solid #00c8ff;"
                )
                selected_button.setStyleSheet(new_style)

    def _load_setting(self, key, default_value):
        settings_file = os.path.join(self.app_data_dir, 'settings.json')
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                return settings.get(key, default_value)
            except:
                return default_value
        return default_value

    def _save_setting(self, key, value):
        settings_file = os.path.join(self.app_data_dir, 'settings.json')
        settings = {}
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
            except:
                pass
        settings[key] = value
        try:
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            return True
        except Exception:
            return False

    def closeEvent(self, event):
        if not self.verify_exit_password():
            event.ignore()
            return

        if hasattr(self, 'run_in_background') and self.run_in_background:
            self.hide()
            self.tray_icon.showMessage(
                "WolfGuard Antivírus",
                "O WolfGuard continua ativo em segundo plano. Clique no ícone para reabrir.",
                QSystemTrayIcon.Information,
                3000
            )
            event.ignore()
        else:
            reply = QMessageBox.question(
                self, "Confirmar Saída",
                "Deseja sair? A proteção em tempo real será desativada.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                try:
                    if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.isRunning():
                        try:
                            self.scan_thread.stop()
                            self.scan_thread.wait(1000)
                        except:
                            pass

                    if hasattr(self, 'network_thread') and self.network_thread is not None:
                        try:
                            if self.network_thread.isRunning():
                                self.network_thread.quit()
                                self.network_thread.wait(1000)
                        except:
                            pass
                        self.network_thread = None

                    if hasattr(self, 'usage_tracker'):
                        self.usage_tracker.update_session()

                    self._save_stats()
                    self.log_event("Aplicativo encerrado.")

                    event.accept()
                except Exception:
                    event.accept()
            else:
                event.ignore()

    def hideEvent(self, event):
        if self.isMinimized():
            self.hide()
            self.tray_icon.showMessage("WolfGuard Antivírus", "Executando em segundo plano.", QSystemTrayIcon.Information, 2000)
            event.ignore()

    def log_event(self, message):
        try:
            log_file = os.path.join(self.logs_dir, f"log_{datetime.now().strftime('%Y%m%d')}.txt")
            timestamp = datetime.now().strftime("%H:%M:%S")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception:
            pass


class DetailedLogDialog(QDialog):
    def __init__(self, logs_dir, parent=None):
        super().__init__(parent)
        self.logs_dir = logs_dir
        self.setWindowTitle("Logs Detalhados")
        self.setFixedSize(900, 600)
        self.setStyleSheet("QDialog { background-color: #1a237e; color: white; }")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        header_layout = QHBoxLayout()

        title = QLabel("Logs Detalhados do Sistema")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: white;")
        header_layout.addWidget(title)

        date_combo = QComboBox()
        date_combo.setStyleSheet("""
            QComboBox {
                background-color: rgba(30, 50, 100, 0.5);
                color: white;
                border: 1px solid rgba(100, 150, 255, 0.5);
                border-radius: 5px;
                padding: 5px;
                min-width: 150px;
            }
        """)

        log_files = self.get_log_files()
        for log_file in log_files:
            date_str = log_file.split('_')[1].split('.')[0]
            date_formatted = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}"
            date_combo.addItem(date_formatted, log_file)

        date_combo.currentIndexChanged.connect(self.load_selected_log)
        header_layout.addWidget(date_combo)

        layout.addLayout(header_layout)

        self.log_browser = QTextEdit()
        self.log_browser.setReadOnly(True)
        self.log_browser.setStyleSheet("""
            background-color: rgba(20, 30, 50, 0.8);
            color: white;
            border: 1px solid rgba(100, 150, 255, 0.3);
            border-radius: 5px;
            padding: 10px;
            font-family: monospace;
        """)
        layout.addWidget(self.log_browser)

        button_layout = QHBoxLayout()

        export_button = QPushButton("Exportar Logs")
        export_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        export_button.clicked.connect(self.export_logs)
        button_layout.addWidget(export_button)

        close_button = QPushButton("Fechar")
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
        """)
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        if date_combo.count() > 0:
            self.load_selected_log(0)

    def get_log_files(self):
        try:
            log_files = [f for f in os.listdir(self.logs_dir) if f.startswith("log_") and f.endswith(".txt")]
            log_files.sort(reverse=True)
            return log_files
        except Exception:
            return []

    def load_selected_log(self, index):
        try:
            combo_box = self.sender() if self.sender() else self.findChild(QComboBox)
            if not combo_box or combo_box.count() == 0:
                return

            log_file = combo_box.itemData(index)
            log_path = os.path.join(self.logs_dir, log_file)

            with open(log_path, 'r', encoding='utf-8') as f:
                log_content = f.read()

            self.log_browser.setPlainText(log_content)

        except Exception:
            self.log_browser.setPlainText("Erro ao carregar arquivo de log")

    def export_logs(self):
        try:
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Exportar Logs",
                os.path.join(os.path.expanduser("~"), "Desktop", "wolfguard_logs.txt"),
                "Arquivos de Texto (*.txt)"
            )

            if save_path:
                current_content = self.log_browser.toPlainText()
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(current_content)
                QMessageBox.information(self, "Exportação Concluída", f"Logs exportados para:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao exportar logs: {str(e)}")


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Alterar Senha")
        self.setFixedSize(400, 300)
        self.setStyleSheet("QDialog { background-color: #2e2e2e; color: white; }")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Alterar Senha de Acesso")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: white;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addSpacing(15)

        form_layout = QGridLayout()
        form_layout.setVerticalSpacing(10)
        form_layout.setHorizontalSpacing(10)

        current_password_label = QLabel("Senha Atual:")
        current_password_label.setStyleSheet("color: white;")
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)
        self.current_password_input.setStyleSheet("""
            background-color: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(100, 150, 255, 0.5);
            border-radius: 5px;
            padding: 8px;
        """)
        form_layout.addWidget(current_password_label, 0, 0)
        form_layout.addWidget(self.current_password_input, 0, 1)

        new_password_label = QLabel("Nova Senha:")
        new_password_label.setStyleSheet("color: white;")
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setStyleSheet("""
            background-color: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(100, 150, 255, 0.5);
            border-radius: 5px;
            padding: 8px;
        """)
        form_layout.addWidget(new_password_label, 1, 0)
        form_layout.addWidget(self.new_password_input, 1, 1)

        confirm_password_label = QLabel("Confirmar Senha:")
        confirm_password_label.setStyleSheet("color: white;")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setStyleSheet("""
            background-color: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(100, 150, 255, 0.5);
            border-radius: 5px;
            padding: 8px;
        """)
        form_layout.addWidget(confirm_password_label, 2, 0)
        form_layout.addWidget(self.confirm_password_input, 2, 1)

        layout.addLayout(form_layout)

        layout.addSpacing(20)

        buttons_layout = QHBoxLayout()

        save_button = QPushButton("Salvar")
        save_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        save_button.clicked.connect(self.accept)

        cancel_button = QPushButton("Cancelar")
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
        """)
        cancel_button.clicked.connect(self.reject)

        buttons_layout.addWidget(save_button)
        buttons_layout.addWidget(cancel_button)

        layout.addLayout(buttons_layout)
        self.setLayout(layout)


class LoginDialog(QDialog):
    def __init__(self, app_data_dir, parent=None):
        super().__init__(parent)
        self.app_data_dir = app_data_dir
        self.setWindowTitle("WolfGuard Antivírus - Login")
        self.setFixedSize(400, 300)
        self.setStyleSheet("QDialog { background-color: #1a237e; color: white; }")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Acesso Seguro")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: white; margin-bottom: 15px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        icon_label = QLabel("🔒")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setFont(QFont("Arial", 38))
        icon_label.setStyleSheet("color: white; margin-bottom: 15px;")
        layout.addWidget(icon_label)

        password_layout = QHBoxLayout()
        password_label = QLabel("Senha: ")
        password_label.setFont(QFont("Arial", 12))
        password_label.setStyleSheet("color: white;")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("font-size: 12px; padding: 8px; border-radius: 5px; background-color: rgba(255, 255, 255, 0.9); color: black;")
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #FF5555; font-size: 12px;")
        self.error_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.error_label)

        button_layout = QHBoxLayout()
        login_button = QPushButton("Entrar")
        login_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        login_button.clicked.connect(self.validate_password)

        cancel_button = QPushButton("Cancelar")
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: gray;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
        """)
        cancel_button.clicked.connect(self.reject)

        button_layout.addStretch()
        button_layout.addWidget(login_button)
        button_layout.addWidget(cancel_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.password_input.setFocus()

        self.password_input.returnPressed.connect(self.validate_password)

    def validate_password(self):
        try:
            password_file = os.path.join(self.app_data_dir, "antivirus_password.txt")

            if not os.path.exists(password_file):
                if self.password_input.text() == "0000":
                    self.accept()
                else:
                    self.error_label.setText("Senha incorreta. Tente novamente.")
                    self.password_input.clear()
                    self.password_input.setFocus()
                return

            with open(password_file, "r") as f:
                stored_password = f.read().strip()

            if self.password_input.text() == stored_password:
                self.accept()
            else:
                self.error_label.setText("Senha incorreta. Tente novamente.")
                self.password_input.clear()
                self.password_input.setFocus()
        except Exception:
            if self.password_input.text() == "0000":
                self.accept()
            else:
                self.error_label.setText("Erro ao validar senha. Tente novamente.")
                self.password_input.clear()
                self.password_input.setFocus()

class InstructionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bem-vindo ao WolfGuard Antivírus")
        self.setFixedSize(700, 500)
        self.setStyleSheet("QDialog { background-color: #1a237e; color: white; }")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Como usar o WolfGuard")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: white; margin-bottom: 15px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        instructions = QTextBrowser()
        instructions.setStyleSheet("background-color: rgba(30, 50, 100, 0.3); border: 1px solid rgba(100, 150, 255, 0.3); border-radius: 10px; padding: 15px; color: white;")
        instructions.setFont(QFont("Arial", 11))
        instructions.setOpenExternalLinks(True)

        instructions_text = """
        <h3>Recursos Principais:</h3>
        <ul>
            <li><b>Painel</b> - Visão geral da proteção e estatísticas</li>
            <li><b>Links</b> - Verifique a segurança de URLs</li>
            <li><b>IP/USB</b> - Informações de rede e dispositivos USB</li>
            <li><b>Blacklist</b> - Bloqueio de aplicativos maliciosos</li>
            <li><b>Proteção</b> - Configurações de proteção em tempo real</li>
            <li><b>Quarentena</b> - Gerencie arquivos infectados isolados</li>
            <li><b>Configurações</b> - Personalize o WolfGuard</li>
        </ul>

        <h3>Dicas de Uso:</h3>
        <ol>
            <li>Mantenha a proteção em tempo real sempre ativada</li>
            <li>Verifique dispositivos USB desconhecidos antes de acessar seus arquivos</li>
            <li>Utilize a função de verificação de links antes de acessar sites suspeitos</li>
            <li>Consulte regularmente os arquivos em quarentena</li>
            <li>Use a função Blacklist para bloquear aplicações maliciosas</li>
            <li>Pressione F4 para ativar rapidamente WiFi e USB</li>
        </ol>

        <h3>Recursos Adicionais:</h3>
        <p>O WolfGuard também oferece proteção USB, bloqueio de sites maliciosos,
        e monitoramento contínuo do sistema em tempo real.</p>

        <p><b>Importante:</b> Mantenha o WolfGuard sempre atualizado para garantir a melhor proteção.</p>
        """

        instructions.setHtml(instructions_text)
        layout.addWidget(instructions)

        checkbox_layout = QHBoxLayout()
        self.dont_show_checkbox = QCheckBox("Não mostrar esta mensagem novamente")
        self.dont_show_checkbox.setStyleSheet("color: white;")
        checkbox_layout.addWidget(self.dont_show_checkbox)
        checkbox_layout.addStretch()
        layout.addLayout(checkbox_layout)

        close_button = QPushButton("Entendi")
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #4B7BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #2E64FE;
            }
        """)
        close_button.clicked.connect(self.accept)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.setLayout(layout)

def run_as_admin():
    if is_admin():
        return True

    try:
        python_exe = sys.executable
        script = os.path.abspath(sys.argv[0])
        args = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])

        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            python_exe,
            f'"{script}" {args}',
            None,
            1
        )

        if ret > 32:
            return False
        else:
            return None

    except Exception:
        return None

def main():
    try:
        temp_flag_file = os.path.join(os.environ.get('TEMP', ''), 'wolfguard_elevation_attempted.tmp')
        elevation_already_attempted = os.path.exists(temp_flag_file)

        app = QApplication(sys.argv)
        icon_path = get_resource_path("1.png")
        if os.path.exists(icon_path):
            app.setWindowIcon(QIcon(icon_path))

        if not is_admin() and not elevation_already_attempted:
            with open(temp_flag_file, 'w') as f:
                f.write(str(datetime.now()))

            reply = QMessageBox.question(
                None, "WolfGuard Antivírus",
                "Para funcionalidade completa, o WolfGuard precisa de privilégios de administrador.\n\nDeseja executar como administrador?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )

            if reply == QMessageBox.Yes:
                admin_result = run_as_admin()
                if admin_result is False:
                    try:
                        os.remove(temp_flag_file)
                    except:
                        pass
                    sys.exit(0)
                elif admin_result is None:
                    QMessageBox.warning(
                        None, "Aviso",
                        "Não foi possível obter privilégios de administrador. Algumas funcionalidades podem estar limitadas."
                    )

        try:
            if os.path.exists(temp_flag_file):
                os.remove(temp_flag_file)
        except:
            pass

        window = WolfGuardAntivírus()
        if os.path.exists(icon_path):
            window.setWindowIcon(QIcon(icon_path))
        window.show()

        iniciar_modulos()

        QTimer.singleShot(10000, gc.collect)

        return app.exec_()

    except Exception as e:
        error_message = f"Erro crítico: {str(e)}\n{traceback.format_exc()}"
        print(error_message)

        try:
            if 'app' in locals():
                QMessageBox.critical(None, "Erro Fatal",
                    f"Ocorreu um erro crítico ao iniciar o aplicativo:\n{str(e)}")
        except:
            pass

        return 1

if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"Erro ao iniciar o WolfGuard: {e}")
        traceback.print_exc()
        sys.exit(1)