# -*- coding: utf-8 -*-
"""
Script tao file Word (.docx) chuan muc hoc thuat, loai bo 100% loi ky tu markdown,
khong trung lap tieu de, tuong thich tuyet doi voi baocaosieuvipskill.
"""

from pathlib import Path
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

ROOT_DIR = Path(__file__).resolve().parent.parent
MD_PATH = ROOT_DIR / "HUONG_DAN_SU_DUNG_VA_KIEM_THU.md"
DOCX_ALL_IN_ONE = ROOT_DIR / "HUONG_DAN_SU_DUNG_VA_KIEM_THU_ALL_IN_ONE.docx"
DOCX_MOI_NHAT = ROOT_DIR / "HUONG_DAN_SU_DUNG_VA_KIEM_THU_MOI_NHAT.docx"
DOCX_GOC = ROOT_DIR / "HUONG_DAN_SU_DUNG_VA_KIEM_THU.docx"

md_text = MD_PATH.read_text(encoding="utf-8")

doc = Document()

# Thiet lap le trang chuan
for section in doc.sections:
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)

# Font mac dinh Segoe UI / Arial
normal_style = doc.styles['Normal']
normal_style.font.name = 'Segoe UI'
normal_style.font.size = Pt(10.5)
normal_style.font.color.rgb = RGBColor(30, 41, 59)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_background(cell, hex_color):
    tcPr = cell._element.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)

def add_styled_runs(paragraph, text, base_font_size=10.5, base_color=RGBColor(30, 41, 59)):
    parts = text.split("**")
    for idx, part in enumerate(parts):
        if not part:
            continue
        run = paragraph.add_run(part)
        run.font.name = 'Segoe UI'
        run.font.size = Pt(base_font_size)
        run.font.color.rgb = base_color
        if idx % 2 == 1:
            run.bold = True

# 1. TIEU DE DUY NHAT DAU TRANG (KHONG TRUNG LAP)
title_p = doc.add_paragraph()
title_p.paragraph_format.space_before = Pt(0)
title_p.paragraph_format.space_after = Pt(2)
title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
t_run = title_p.add_run("TÀI LIỆU HƯỚNG DẪN SỬ DỤNG VÀ KỊCH BẢN KIỂM THỬ HỆ THỐNG")
t_run.font.name = 'Segoe UI'
t_run.font.size = Pt(16)
t_run.font.bold = True
t_run.font.color.rgb = RGBColor(30, 58, 138)

sub_p = doc.add_paragraph()
sub_p.paragraph_format.space_before = Pt(0)
sub_p.paragraph_format.space_after = Pt(14)
sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
s_run = sub_p.add_run("HỆ THỐNG AN NINH MẠNG TỰ HÀNH TỪ TÌNH BÁO MỐI ĐE DỌA CTI (AUTONOMOUS CTI AGENTIC DEFENSE)")
s_run.font.name = 'Segoe UI'
s_run.font.size = Pt(11)
s_run.font.bold = True
s_run.font.color.rgb = RGBColor(37, 99, 235)

# 2. KHUNG THONG TIN TRUY CAP TRUNG TAM DUY NHAT (PORT 8765)
info_tbl = doc.add_table(rows=1, cols=1)
info_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
c = info_tbl.rows[0].cells[0]
set_cell_background(c, "F8FAFC")
set_cell_margins(c, 140, 140, 180, 180)
cp = c.paragraphs[0]
cp.paragraph_format.space_after = Pt(4)

r_h = cp.add_run("THÔNG TIN TRUY CẬP VÀ VẬN HÀNH DUY NHẤT (ALL-IN-ONE):\n")
r_h.bold = True
r_h.font.size = Pt(11)
r_h.font.color.rgb = RGBColor(15, 23, 42)

r_url = cp.add_run("- Giao diện Web Quản Trị Trung Tâm: ")
r_url.font.size = Pt(10)
r_url.font.color.rgb = RGBColor(51, 65, 85)
r_link = cp.add_run("http://127.0.0.1:8765\n")
r_link.bold = True
r_link.font.size = Pt(10.5)
r_link.font.color.rgb = RGBColor(37, 99, 235)

r_cli = cp.add_run("- Lệnh khởi động nhanh tại thư mục bất kỳ: ")
r_cli.font.size = Pt(10)
r_cli.font.color.rgb = RGBColor(51, 65, 85)
r_cmd = cp.add_run("cti  (hoặc cti-defense)\n")
r_cmd.bold = True
r_cmd.font.name = 'Consolas'
r_cmd.font.size = Pt(10)
r_cmd.font.color.rgb = RGBColor(21, 128, 61)

r_note = cp.add_run("- Cơ chế tích hợp: Toàn bộ quy trình quét mã nguồn, thu thập tin tức tình báo CTI, đóng gói bộ kỹ năng tác tử, tương tác với AI và kiểm thử lá chắn WAF đều được gom 100% vào duy nhất 1 giao diện web này.")
r_note.font.size = Pt(9.5)
r_note.font.color.rgb = RGBColor(100, 116, 139)

doc.add_paragraph().paragraph_format.space_after = Pt(8)

# 3. PARSER NOIDUNG MARKDOWN SACH SE
lines = md_text.splitlines()

# Bo qua phan dau (Tieu de da tao o tren)
start_idx = 0
for idx, line in enumerate(lines):
    if line.strip().startswith("## 1. GIỚI THIỆU TỔNG QUAN"):
        start_idx = idx
        break

in_code = False
code_lines = []
table_lines = []

for line in lines[start_idx:]:
    stripped = line.strip()

    # Xu ly code block
    if stripped.startswith("```"):
        if in_code:
            in_code = False
            tbl = doc.add_table(rows=1, cols=1)
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            cell = tbl.rows[0].cells[0]
            set_cell_background(cell, "0F172A")
            set_cell_margins(cell, 90, 90, 150, 150)
            code_p = cell.paragraphs[0]
            code_p.paragraph_format.space_after = Pt(0)
            c_run = code_p.add_run("\n".join(code_lines))
            c_run.font.name = 'Consolas'
            c_run.font.size = Pt(9.5)
            c_run.font.color.rgb = RGBColor(56, 189, 248)
            code_lines = []
            doc.add_paragraph().paragraph_format.space_after = Pt(4)
        else:
            in_code = True
            code_lines = []
        continue

    if in_code:
        code_lines.append(line)
        continue

    # Xu ly bang bieu
    if stripped.startswith("|"):
        if not stripped.startswith("| :---"):
            table_lines.append(stripped)
        continue
    elif table_lines:
        headers = [col.strip() for col in table_lines[0].split("|")[1:-1]]
        rows_data = []
        for tr in table_lines[1:]:
            cols = [col.strip() for col in tr.split("|")[1:-1]]
            if len(cols) == len(headers):
                rows_data.append(cols)

        doc_tbl = doc.add_table(rows=len(rows_data) + 1, cols=len(headers))
        doc_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

        for c_idx, h_text in enumerate(headers):
            cell = doc_tbl.cell(0, c_idx)
            set_cell_background(cell, "1E3A8A")
            set_cell_margins(cell, 80, 80, 120, 120)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(h_text)
            run.font.name = 'Segoe UI'
            run.bold = True
            run.font.size = Pt(10)
            run.font.color.rgb = RGBColor(255, 255, 255)

        for r_idx, r_cols in enumerate(rows_data):
            bg_color = "F8FAFC" if r_idx % 2 == 1 else "FFFFFF"
            for c_idx, col_val in enumerate(r_cols):
                cell = doc_tbl.cell(r_idx + 1, c_idx)
                set_cell_background(cell, bg_color)
                set_cell_margins(cell, 70, 70, 120, 120)
                p = cell.paragraphs[0]
                p.paragraph_format.space_after = Pt(0)
                run = p.add_run(col_val)
                run.font.name = 'Segoe UI'
                run.font.size = Pt(9.5)
                if "ĐẠT" in col_val:
                    run.bold = True
                    run.font.color.rgb = RGBColor(21, 128, 61)

        table_lines = []
        doc.add_paragraph().paragraph_format.space_after = Pt(4)

    # Bo qua dong trong hoac duong ke
    if not stripped or stripped == "---" or stripped in ["#", "##", "###"]:
        continue

    # Xu ly tieu de cap 1 (## )
    if stripped.startswith("## "):
        h1_text = stripped.replace("## ", "").strip()
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(4)
        r = p.add_run(h1_text)
        r.font.name = 'Segoe UI'
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = RGBColor(30, 58, 138)
        continue

    # Xu ly tieu de cap 2 (### )
    if stripped.startswith("### "):
        h2_text = stripped.replace("### ", "").strip()
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(h2_text)
        r.font.name = 'Segoe UI'
        r.font.size = Pt(11.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(15, 23, 42)
        continue

    # Xu ly tieu de cap 3 (#### )
    if stripped.startswith("#### "):
        h3_text = stripped.replace("#### ", "").strip()
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(h3_text)
        r.font.name = 'Segoe UI'
        r.font.size = Pt(10.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(71, 85, 105)
        continue

    # Xu ly gach dau dong
    if stripped.startswith("- ") or stripped.startswith("* "):
        item_text = stripped[2:].strip()
        # Tinh toan do thut dau dong neu line goc co spaces
        leading_spaces = len(line) - len(line.lstrip())
        indent_level = leading_spaces // 2

        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.left_indent = Inches(0.25 * (indent_level + 1))
        
        # Bullet symbol "-"
        b_run = p.add_run("- ")
        b_run.bold = True
        b_run.font.color.rgb = RGBColor(37, 99, 235)

        add_styled_runs(p, item_text, base_font_size=10, base_color=RGBColor(30, 41, 59))
        continue

    # Xu ly danh sach danh so (1. , 2. ...)
    if len(stripped) > 3 and stripped[0].isdigit() and stripped[1] in [".", ")"] and stripped[2] == " ":
        num_prefix = stripped[:3]
        item_text = stripped[3:].strip()

        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.left_indent = Inches(0.3)

        n_run = p.add_run(num_prefix)
        n_run.bold = True
        n_run.font.color.rgb = RGBColor(30, 58, 138)

        add_styled_runs(p, item_text, base_font_size=10, base_color=RGBColor(30, 41, 59))
        continue

    # Doan van ban thong thuong
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.15
    add_styled_runs(p, stripped, base_font_size=10.5, base_color=RGBColor(30, 41, 59))

# Luu file vao cac duong dan
saved_paths = []

for target_path in [DOCX_MOI_NHAT, DOCX_GOC, DOCX_ALL_IN_ONE]:
    try:
        doc.save(str(target_path))
        saved_paths.append(str(target_path))
        print(f"[OK] Da ghi file thanh cong: {target_path.name}")
    except PermissionError:
        print(f"[INFO] File {target_path.name} dang mo boi Word, bo qua.")

print("\n[SUCCESS] Hoan tat tao tai lieu Word chuan!")
