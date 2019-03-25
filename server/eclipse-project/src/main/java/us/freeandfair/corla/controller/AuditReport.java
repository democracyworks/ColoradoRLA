package us.freeandfair.corla.controller;


import java.io.IOException;

// import java.util.ArrayList;
// import java.util.Arrays;
// import java.util.Comparator;
// import java.util.HashMap;
import java.util.List;
// import java.util.Map;
// import java.util.Optional;
// import java.util.OptionalInt;

// import org.apache.commons.lang3.ArrayUtils;

// import java.time.Instant;
// import java.time.LocalDateTime;
// import java.time.format.DateTimeFormatter;
// import java.util.TimeZone;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import us.freeandfair.corla.report.WorkbookWriter;
import us.freeandfair.corla.report.ReportRows;
// import us.freeandfair.corla.math.Audit;
// import us.freeandfair.corla.model.CastVoteRecord;
// import us.freeandfair.corla.model.CVRAuditInfo;
// import us.freeandfair.corla.model.CVRContestInfo;
// import us.freeandfair.corla.model.ComparisonAudit;
import us.freeandfair.corla.model.DoSDashboard;
// import us.freeandfair.corla.model.Tribute;
import us.freeandfair.corla.persistence.Persistence;
// import us.freeandfair.corla.query.CastVoteRecordQueries;
// import us.freeandfair.corla.query.ComparisonAuditQueries;
// import us.freeandfair.corla.query.CountyQueries;
// import us.freeandfair.corla.query.TributeQueries;

/**
 * Find the data for a report and format it to be rendered into a presentation
 * format elsewhere
 **/
public final class AuditReport {

  /**
   * Class-wide logger
   */
  public static final Logger LOGGER =
    LogManager.getLogger(AuditReport.class);


  /** no instantiation **/
  private AuditReport () {};

  /**
   * Generate a report file and return the bytes
   * activity: a log of acvr submissions for a particular Contest (includes all
   *   participating counties)
   * activity-all: same as above for all targeted contests
   * results: the acvr submissions for each random number that was generated (to
   *   audit this program's calculations)
   * results-all: same as above for all targeted contests
   *
   * Here are the specific differences:
   * - the Activity report is sorted by timestamp, the Audit Report by random
       number sequence
   * - the Activity report shows previous revisions, the Audit Report does not
   * - the Audit Report shows the random number that was generated for
       the CVR (and the position),  the Activity Report does not
   * - the Audit Report shows duplicates(multiplicity), the Activity Report does not
   *
   * contestName is optional if reportType is *-all
   **/
  public static byte[] generate(final String contentType,
                                final String reportType,
                                final String contestName)
    throws IOException {
    // xlsx
    final WorkbookWriter writer = new WorkbookWriter();
    List<List<String>> rows;
    DoSDashboard dosdb;

    switch(reportType) {
    case "activity":
      rows = ReportRows.getContestActivity(contestName);
      writer.addSheet(contestName, rows);
      break;
    case "activity-all":
      dosdb = Persistence.getByID(DoSDashboard.ID, DoSDashboard.class);
      for (final String cName: dosdb.targetedContestNames()) {
        writer.addSheet(cName, ReportRows.getContestActivity(cName));
      }
      break;
    case "results":
      rows = ReportRows.getResultsReport(contestName);
      writer.addSheet(contestName, rows);
      break;
    case "results-all":
      dosdb = Persistence.getByID(DoSDashboard.ID, DoSDashboard.class);
      writer.addSheet("Summary", ReportRows.genSumResultsReport());
      for (final String cName: dosdb.targetedContestNames()) {
        writer.addSheet(cName, ReportRows.getResultsReport(cName));
      }
      break;
    default:
      LOGGER.error("invalid reportType: " + reportType);
      break;

    }

    return writer.write();
  }

}
