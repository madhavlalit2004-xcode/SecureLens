"""Safe extraction for assessment and knowledge-base uploads."""
from io import BytesIO
from pathlib import Path


SUPPORTED_EXTENSIONS = {".txt", ".md", ".csv", ".json", ".pdf", ".docx", ".xlsx"}


class DocumentError(ValueError):
    pass


def extract_text(filename: str, content: bytes) -> str:
    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise DocumentError(f"Unsupported file type '{extension or 'unknown'}'.")
    if len(content) > 10 * 1024 * 1024:
        raise DocumentError("File exceeds the 10 MB upload limit.")
    if extension in {".txt", ".md", ".csv", ".json"}:
        return content.decode("utf-8", errors="replace")
    if extension == ".pdf":
        try:
            from pypdf import PdfReader
            return "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(content)).pages)
        except ImportError as exc:
            raise DocumentError("PDF support requires pypdf.") from exc
    if extension == ".docx":
        try:
            from docx import Document
            return "\n".join(paragraph.text for paragraph in Document(BytesIO(content)).paragraphs)
        except ImportError as exc:
            raise DocumentError("DOCX support requires python-docx.") from exc
    try:
        from openpyxl import load_workbook
        workbook = load_workbook(BytesIO(content), read_only=True, data_only=True)
        return "\n".join(
            f"[{sheet.title}]\n" + "\n".join(", ".join(str(cell) for cell in row if cell is not None) for row in sheet.iter_rows(values_only=True))
            for sheet in workbook.worksheets
        )
    except ImportError as exc:
        raise DocumentError("XLSX support requires openpyxl.") from exc
