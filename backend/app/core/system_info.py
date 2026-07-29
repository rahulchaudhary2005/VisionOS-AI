import platform
import time
from datetime import datetime

import psutil

START_TIME = time.time()


class SystemMonitor:
    """
    Collects runtime and system information.
    """

    @staticmethod
    def uptime() -> str:
        elapsed = int(time.time() - START_TIME)

        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60

        return f"{hours}h {minutes}m {seconds}s"

    @staticmethod
    def cpu_usage() -> float:
        return psutil.cpu_percent(interval=0.2)

    @staticmethod
    def memory_usage() -> float:
        return psutil.virtual_memory().percent

    @staticmethod
    def disk_usage() -> float:
        return psutil.disk_usage("/").percent

    @staticmethod
    def python_version() -> str:
        return platform.python_version()

    @staticmethod
    def operating_system() -> str:
        return platform.system()

    @staticmethod
    def hostname() -> str:
        return platform.node()

    @staticmethod
    def boot_time() -> str:
        return datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
