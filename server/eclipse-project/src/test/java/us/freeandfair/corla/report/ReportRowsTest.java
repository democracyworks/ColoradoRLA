package us.freeandfair.corla.controller;

import java.util.ArrayList;
import java.util.List;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import java.io.IOException;

import us.freeandfair.corla.report.ReportRows;

import org.testng.annotations.Test;
import static org.testng.Assert.*;

@Test
public class ReportRowsTest {

  private ReportRowsTest() {};

  @Test
  public void renderRow() throws IOException {
    String[] headers = { "a", "b", "c"};
    ReportRows.Row row = new ReportRows.Row(headers);
    row.put("a", "1");
    assertEquals("1", row.get("a"));
    List result = Stream.of("1", null, null)
      .collect(Collectors.toList());
    assertEquals(row.toArray(), result);
  }
}
