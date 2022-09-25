try:
    from PyQt5 import QtWidgets, QtGui, QtCore
except ImportError:
    print("PySide unavailable, no CodeCaveFinder")
    QtCore = None
    QtGui = None

import idaapi
import ida_kernwin
import idc


class CodeCaveWindow(ida_kernwin.PluginForm):

    def __init__(self):
        super(CodeCaveWindow, self).__init__()
        self.tree = None
        self.parent = None

    def add_entry_to_tree(self, segment, address, size):
        entry = QtWidgets.QTreeWidgetItem(self.tree)
        entry.setText(0, segment)
        entry.setText(1, "0x%x" % address)
        entry.setText(2, ("%d" % size).zfill(10))
        # print dir(entry)

    def populate_tree(self):
        self.tree.clear()
        executable_segments = [
            (idc.get_segm_name(idaapi.getnseg(x).startEA), 0 != (idaapi.getnseg(x).perm & idaapi.SEGPERM_EXEC)) for x in
            range(idaapi.get_segm_qty())]
        for segment in executable_segments:
            if not segment[1]:
                continue
            caves = self.find_code_caves(segment[0])
            for cave in caves:
                self.add_entry_to_tree(segment[0], cave[0], cave[1])

    def on_create(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("Segment", "Address", "Size"))
        self.tree.setColumnWidth(0, 100)
        self.tree.setSortingEnabled(True)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)

        jump = QtWidgets.QPushButton("Jump To")
        jump.clicked.connect(self.jump)
        layout.addWidget(jump)

        search_again = QtWidgets.QPushButton("Go Spelunking")
        search_again.clicked.connect(self.populate_tree)
        layout.addWidget(search_again)

        # self.PopulateTree()
        self.parent.setLayout(layout)

    def jump(self):
        current_item = self.tree.currentItem()
        if current_item:
            ida_kernwin.jumpto(int(current_item.text(1)[2:], 16))

    @staticmethod
    def find_code_caves(segment=".text"):
        start = idc.get_segm_by_sel(idc.selector_by_name(segment))
        if start == idc.BADADDR:
            print("Can't find segment %s" % segment)
            return

        end = idc.get_segm_end(start)

        curr_addr = start
        curr_size = 0
        biggest_addr = idc.BADADDR
        biggest_size = 0
        results = []
        while start < end:
            new_addr = idc.find_text(start + curr_size, idc.SEARCH_DOWN, 0, 0, "align")
            if start == new_addr:
                break
            curr_size = idc.get_item_size(new_addr)
            if curr_size > biggest_size:
                biggest_addr = new_addr
                biggest_size = curr_size
            start = new_addr
            results.append((new_addr, curr_size))

        return results
        # Return never touched
        # return biggest_addr, biggest_size
