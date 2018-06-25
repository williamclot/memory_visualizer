import volatility.commands as commands
import volatility.utils as utils

class MemoryVisualizer(commands.Command):
    """A step of F1 forensics project: Reads the available pages of the memory dump"""

    def render_text(self, outfd, data):
        """Displays all the available pages"""
        for page, vtop, size, kernel in data:
            print page, vtop, size, kernel

    def calculate(self):
        """Calculate returns the results of the available pages validity"""
        addr_space = utils.load_as(self._config)
        for page, size in addr_space.get_available_pages():
            yield page, addr_space.vtop(page), size, addr_space.is_user_page(page)
