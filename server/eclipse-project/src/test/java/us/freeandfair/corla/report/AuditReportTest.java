package us.freeandfair.corla.report;

import java.util.ArrayList;
import java.util.List;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.poi.ss.usermodel.Workbook;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import us.freeandfair.corla.report.AuditReport;

import org.testng.annotations.Test;
import static org.testng.Assert.*;

@Test
public class AuditReportTest {

  private AuditReportTest() {};

  @Test
  public void generateTest() throws IOException {
    // log of audit calculation events for a contest
    List<String> headers = Stream.of(
        "dbID",
        "recordType",
        "imprintedID",
        "auditBoard",
        "discrepancy",
        "consensus",
        "comment",
        "revision", // if it had been re-audited
        "re-audit ballot comment"
    ).collect(Collectors.toList());
    List<String> row1 = Stream.of("123", "AUDITOR_ENTERED")
      .collect(Collectors.toList());
    List<String> row2 = Stream.of("456", "AUDITOR_ENTERED")
      .collect(Collectors.toList());

    List<List<String>> rows = Stream.of(headers, row1, row2)
      .collect(Collectors.toList());

    final byte[] report = (new AuditReport()).generate(rows);

    final Workbook wb = new XSSFWorkbook(new ByteArrayInputStream(report));

    assertEquals(wb.getNumberOfSheets(), 1);
    assertEquals(
        wb.getSheet("Summary")
          .getRow(0)
          .getCell(0)
          .getStringCellValue(),
        "dbID"
    );
    assertEquals(wb.getSheet("Summary").getLastRowNum(), 2);
    assertEquals(wb.getSheet("Summary").getRow(0).getLastCellNum(), 9);
    assertEquals(wb.getSheet("Summary").getRow(1).getLastCellNum(), 2);
    assertEquals(wb.getSheet("Summary").getRow(2).getLastCellNum(), 2);
  }
}
