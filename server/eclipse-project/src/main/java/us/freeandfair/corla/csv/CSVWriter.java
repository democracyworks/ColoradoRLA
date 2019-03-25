package us.freeandfair.corla.csv;


import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

/** to render a CSV as an http response  **/
public final class CSVWriter {

  /** no instantiation **/
  private CSVWriter () {}

  /**
   * write rows/records to an output stream, like maybe a Spark response output
   * stream
   **/
  public static void write(final OutputStream os,
                           final List<List<String>> rows) throws IOException {
    final Writer writer = new BufferedWriter(new OutputStreamWriter(os, UTF_8.name()));
    final CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT);

    for (final List<String> row: rows) {
      csvPrinter.printRecord(row);
    }
    writer.flush();
    writer.close();
  }

}
