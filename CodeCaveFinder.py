try:
    from PySide import QtGui, QtCore
except ImportError:
    print "PySide unavailable, no CodeCaveFinder"
    QtCore = None
    QtGui = None
import idaapi, idc

class CodeCaveWindow(idaapi.PluginForm):
    def findCodeCavez(self, segment=".text"):
        start = idc.SegByBase(idc.SegByName(segment))
        if start == idc.BADADDR:
            print "Can't find segment %s" % (segment)
            return

        end = idc.SegEnd(start)

        curr_addr = start
        curr_size = 0
        biggest_addr = idc.BADADDR
        biggest_size = 0
        results = []
        while start < end:
            new_addr = idc.FindText(start + curr_size, idc.SEARCH_DOWN, 0, 0, "align")
            if start == new_addr:
                break
            curr_size = idc.ItemSize(new_addr)
            if curr_size > biggest_size:
                biggest_addr = new_addr
                biggest_size = curr_size
            start = new_addr
            results.append((new_addr, curr_size))

        return results
        return biggest_addr, biggest_size

    def addEntryToTree(self, segment, address, size):
        entry = QtGui.QTreeWidgetItem(self.tree)
        entry.setText(0, segment)
        entry.setText(1, "0x%x"%(address))
        entry.setText(2, ("%d"%(size)).zfill(10))
        # print dir(entry)

    def PopulateTree(self):
        self.tree.clear()
        executable_segments = [(idc.SegName(idaapi.getnseg(x).startEA), 0!=(idaapi.getnseg(x).perm & idaapi.SEGPERM_EXEC)) for x in range(idaapi.get_segm_qty())]
        for segment in executable_segments:
            if not segment[1]:
                continue
            caves = self.findCodeCavez(segment[0])
            for cave in caves:
                self.addEntryToTree(segment[0], cave[0], cave[1])

    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.tree = QtGui.QTreeWidget()
        self.tree.setHeaderLabels(("Segment","Address","Size"))
        self.tree.setColumnWidth(0, 100)
        self.tree.setSortingEnabled(True)
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tree)

        jump = QtGui.QPushButton("Jump To")
        jump.clicked.connect(self.jump)
        layout.addWidget(jump)

        search_again = QtGui.QPushButton("Go Spelunking")
        search_again.clicked.connect(self.PopulateTree)
        layout.addWidget(search_again)

        # self.PopulateTree()
        self.parent.setLayout(layout)

    def jump(self):
        current_item = self.tree.currentItem()
        if current_item:
            idc.Jump(int(current_item.text(1)[2:], 16))
