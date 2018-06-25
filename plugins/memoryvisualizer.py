#import volatility.win32.tasks as tasks
import volatility.plugins.taskmods as taskmods
import volatility.commands as commands
import volatility.utils as utils

class MemoryVisualizer(taskmods.DllList):
    """A step of F1 forensics project: Reads the pages of the memory dump and calculate the physical address and see if it belongs to kernel space"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        self.config = config

    def render_text(self, outfd, data):
        """Displays all the pages used by all processes"""
        for virtual, physical, size, kernel in data:
            print virtual, physical, size, kernel

    def calculate(self):
        """Returns a list of addresses of pages used by processes"""
        addr_space = utils.load_as(self._config)
        tasks = taskmods.DllList.calculate(self)

        for task in tasks:
            if task.UniqueProcessId:
                procSpace = task.get_process_address_space()
                pages = procSpace.get_available_pages(True)
                for p in pages:
                    yield p[1], procSpace.vtop(p[1]), p[2], procSpace.is_supervisor_page(p[0])
