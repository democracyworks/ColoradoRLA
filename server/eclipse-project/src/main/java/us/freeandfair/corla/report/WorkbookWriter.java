/*
 * Colorado RLA System
 */

package us.freeandfair.corla.report;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.List;

import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;

/**
 * Generate a POI Excel workbook containing audit report sheets.
 *
 * Sheets include:
 *
 * - Summary
 */
public class WorkbookWriter {
  /**
   * Font size to use for all cells.
   */
  private static final Short FONT_SIZE = 12;

  /**
   * Internal output stream required for writing out the workbook.
   */
  private final ByteArrayOutputStream baos;


  /**
   * one workbook to hold multiple sheets, another way to say Excel file, xlsx
   **/
  private final Workbook workbook;

  /** regular style **/
  private final CellStyle regStyle;

  /** bold style for headers **/
  private final CellStyle boldStyle;

  /**
   * Initializes the AuditReport
   */
  public WorkbookWriter() {
    this.baos = new ByteArrayOutputStream();
    this.workbook = new XSSFWorkbook();
    this.boldStyle = this.workbook.createCellStyle();
    this.regStyle = this.workbook.createCellStyle();

    setStyles();
  }

  private void setStyles() {
    final Font boldFont = workbook.createFont();
    final Font regFont = workbook.createFont();

    regFont.setFontHeightInPoints(FONT_SIZE);
    this.regStyle.setFont(regFont);

    boldFont.setFontHeightInPoints(FONT_SIZE);
    boldFont.setBold(true);
    this.boldStyle.setFont(boldFont);
  }

  /**
   * Given some raw data, generate the actual POI workbook.
   *
   * @param rows the raw data
   * @return the POI workbook ready for output
   */
  public void addSheet(final String sheetname, final List<List<String>> rows) {
    final Sheet sheet = workbook.createSheet(sheetname);

    for (int i = 0; i < rows.size(); i++) {
      final Row poiRow = sheet.createRow(i);
      final List<String> dataRow = rows.get(i);

      for (int j = 0; j < dataRow.size(); j++) {
        final Cell cell = poiRow.createCell(j);
        cell.setCellValue(dataRow.get(j));
        // Embolden header rows
        if (i == 0) {
          cell.setCellStyle(boldStyle);
        } else {
          cell.setCellStyle(regStyle);
        }
      }
    }
  }

  /**
   * Generate the byte-array representation of this POI workbook.
   *
   * @return the Excel representation of this report
   * @exception IOException if the report cannot be generated.
   */
  public byte[] write() throws IOException {
    this.workbook.write(this.baos);
    this.workbook.close();

    return this.baos.toByteArray();
  }
}
