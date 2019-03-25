package us.freeandfair.corla.report;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import java.math.BigDecimal;

import org.apache.commons.lang3.ArrayUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.TimeZone;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import us.freeandfair.corla.controller.ContestCounter;
import us.freeandfair.corla.math.Audit;
import us.freeandfair.corla.model.CastVoteRecord;
import us.freeandfair.corla.model.CVRAuditInfo;
import us.freeandfair.corla.model.CVRContestInfo;
import us.freeandfair.corla.model.ComparisonAudit;
import us.freeandfair.corla.model.Tribute;
import us.freeandfair.corla.persistence.Persistence;
import us.freeandfair.corla.query.CastVoteRecordQueries;
import us.freeandfair.corla.query.ComparisonAuditQueries;
import us.freeandfair.corla.query.CountyQueries;
import us.freeandfair.corla.query.TributeQueries;

import us.freeandfair.corla.util.SuppressFBWarnings;

/**
 *  Contains the query-ing and processing of two report types:
 *    activity and results
 **/
// fb and pmd conflict about public static nested constants
@SuppressFBWarnings({"MS_PKGPROTECT"})
public class ReportRows {

  /**
   * Class-wide logger
   */
  public static final Logger LOGGER =
    LogManager.getLogger(ReportRows.class);

  /** the union set of used by activity and results reports **/
  public static final String[] ALL_HEADERS = {
    "county",
    "imprinted id",
    "scanner id",
    "batch id",
    "record id",
    "db id",
    "round",
    "audit board",
    "record type",
    "discrepancy",
    "consensus",
    "comment",
    "random number",
    "random number sequence position",
    "multiplicity",
    "revision",
    "re-audit ballot comment",
    "time of submission"
  };

  /** US local date time **/
  private static final DateTimeFormatter MMDDYYYY =
    DateTimeFormatter.ofPattern("MM/dd/yyyy hh:mm:ss a");

  /** cache of county id to county name **/
  private final static Map<Long,String> countyNames = new HashMap();

  /** an empty error response **/
  @SuppressWarnings({"PMD.NonStaticInitializer"})
  private final static List NOT_FOUND_ROW = new ArrayList() {{
    add("audit has not started or contest name not found");
  }};

  /** no instantiation **/
  private ReportRows() {};

  /**
   * One array to be part of an array of arrays, ie: a table or csv or xlsx.
   * It keeps the headers and fields in order.
   **/
  public static class Row {

    /** composition rather than inheritance **/
    private final Map<String, String> map = new HashMap<String, String>();

    /** hold the headers **/
    private final String[] headers;

    /** new row with haeders **/
    public Row(final String ...headers) {
      this.headers = headers;
    }

    /** get the value for the given header **/
    public String get(final String key) {
      return this.map.get(key);
    }

    /** put the value for the given header **/
    public void put(final String key, final String value) {
      this.map.put(key, value);
    }


    /** loop over headers, spit out values, keeping them in sync **/
    public List<String> toArray() {
      final List<String> a = new ArrayList<String>();
      for (final String h: this.headers) {
        a.add(this.get(h));
      }
      return a;
    }
  }

  /**
   * query for the associated CVRAuditInfo object to access the disc data on the
   * Comparison object. If the acvr has been reaudited, recompute the value
   * because that process loses the association.
   **/
  public static Integer findDiscrepancy(final ComparisonAudit audit, final CastVoteRecord acvr) {
    if (null == acvr.getRevision()) {
      // not a revised/overwritten submission
      final CVRAuditInfo cai = Persistence.getByID(acvr.getCvrId(), CVRAuditInfo.class);
      return audit.getDiscrepancy(cai);
    } else {
      final CastVoteRecord cvr = Persistence.getByID(acvr.getCvrId(), CastVoteRecord.class);
      final OptionalInt disc = audit.computeDiscrepancy(cvr, acvr);
      if (disc.isPresent()) {
        return disc.getAsInt();
      } else {
        return null;
      }
    }
  }

  /** get the county name for the given county id **/
  public static String findCountyName(final Long countyId) {
    String name = countyNames.get(countyId);
    if (null == name) {
      name = CountyQueries.getName(countyId);
      countyNames.put(countyId, name);
      return name;
    } else {
      return name;
    }
  }

  /** render helper **/
  public static String toString(final Object o) {
    if (null == o) {
      return null;
    } else {
      return o.toString();
    }
  }

  /** render helper **/
  public static String renderAuditBoard(final Integer auditBoardIndex) {
    if (null == auditBoardIndex) {
      return null;
    } else {
      final Integer i = auditBoardIndex.intValue() + 1;
      return i.toString();
    }
  }

  /**
   * render helper
   * Prepend a plus sign on positive integers to make it clear that it is positive.
   * Negative numbers will have the negative sign.
   * These don't need to be integers because they are counted, not summed.
   **/
  public static String renderDiscrepancy(final Integer discrepancy) {
    if (discrepancy > 0) {
      return String.format("+%d", discrepancy);
    } else {
      return discrepancy.toString();
    }
  }

  /** render helper US local date time **/
  public static String renderTimestamp(final Instant timestamp) {
    return MMDDYYYY.format(LocalDateTime
                           .ofInstant(timestamp,
                                      TimeZone.getDefault().toZoneId()));
  }

  /** add fields common to both activity and results reports **/
  public static Row addBaseFields(final Row row, final ComparisonAudit audit, final CastVoteRecord acvr) {
    final Integer discrepancy = findDiscrepancy(audit, acvr);
    final Optional<CVRContestInfo> infoMaybe = acvr.contestInfoForContestResult(audit.contestResult());

    if (infoMaybe.isPresent()) {
      final CVRContestInfo info = infoMaybe.get();
      row.put("consensus", toString(info.consensus()));
      row.put("comment", info.comment());
    }

    if (null == discrepancy || 0 == discrepancy) {
      row.put("discrepancy", null);
    } else {
      row.put("discrepancy", renderDiscrepancy(discrepancy));
    }
    row.put("db id", acvr.getCvrId().toString());
    row.put("record type", acvr.recordType().toString());
    row.put("county", findCountyName(acvr.countyID()));
    row.put("audit board", renderAuditBoard(acvr.getAuditBoardIndex()));
    row.put("round", toString(acvr.getRoundNumber()));
    row.put("imprinted id", acvr.imprintedID());
    row.put("scanner id", toString(acvr.scannerID()));
    row.put("batch id", acvr.batchID());
    row.put("record id", toString(acvr.recordID()));
    row.put("time of submission", renderTimestamp(acvr.timestamp()));
    return row;
  }

  /** add fields unique to activity report **/
  public static Row addActivityFields(final Row row, final CastVoteRecord acvr) {
    row.put("revision", toString(acvr.getRevision()));
    row.put("re-audit ballot comment", acvr.getComment());
    return row;
  }

  /** add fields unique to results report **/
  public static Row addResultsFields(final Row row, final Tribute tribute, final Integer multiplicity) {
    row.put("multiplicity", toString(multiplicity));
    return addResultsFields(row, tribute);
  }

  /** add fields unique to activity report, if the multiplicity is unknown **/
  public static Row addResultsFields(final Row row, final Tribute tribute) {
    row.put("random number", toString(tribute.rand));
    row.put("random number sequence position", toString(tribute.randSequencePosition));
    return row;
  }

  /** tie the headers to a row **/
  public static class ActivityReport {
    /** a selection of headers **/
    public static final String[] HEADERS =
      ArrayUtils.removeElements(ArrayUtils.clone(ALL_HEADERS),
                                "random number sequence position",
                                "random number",
                                "multiplicity");

    /** no instantiation **/
    private ActivityReport() {};

    /** new row **/
    public static final Row newRow() {
      return new Row(HEADERS);
    }
  }

  /** tie the headers to a row **/
  public static class ResultsReport {
    /** a selection of headers **/
    public static final String[] HEADERS =
      ArrayUtils.removeElements(ArrayUtils.clone(ALL_HEADERS),
                                "revision",
                                "re-audit ballot comment");

    /** no instantiation **/
    private ResultsReport() {};

    /** new row **/
    public static final Row newRow() {
      return new Row(HEADERS);
    }
  }

  /** tie the headers to a row **/
  public static class SummaryReport {

    /** a selection of headers **/
    public static final String[] HEADERS = {
      "Contest",
      "targeted",
      "Winner",

      "Risk Limit Achieved",
      "diluted margin",
      "disc +2",
      "disc +1",
      "disc -1",
      "disc -2",
      "gamma",

      "ballot count",
      "min margin",
      "votes for winner",
      "votes for runner up",
      "total votes (marked)",
      "disagreement count (included in +2 and +1)"
    };

    /** no instantiation **/
    private SummaryReport() {};

    /** new Row **/
    public static final Row newRow() {
      return new Row(HEADERS);
    }
  }

  /** risk limit achieved according to math.Audit **/
  public static String riskLimitAchieved(final ComparisonAudit ca) {
    final BigDecimal result =  Audit.pValueApproximation(ca.getAuditedSampleCount(),
                                                         ca.getDilutedMargin(),
                                                         ca.getGamma(),
                                                         ca.discrepancyCount(-2),
                                                         ca.discrepancyCount(-1),
                                                         ca.discrepancyCount(1),
                                                         ca.discrepancyCount(2));
    return result.setScale(3, BigDecimal.ROUND_HALF_UP).toString();
  }


  /**
   * for each contest(per row), show all the variables that are interesting or
   * needed to perform the risk limit calculation
   **/
  public static List<List<String>> genSumResultsReport() {
    final List<List<String>> rows = new ArrayList();

    rows.add(Arrays.asList(SummaryReport.HEADERS));
    for (final ComparisonAudit ca: Persistence.getAll(ComparisonAudit.class)) {
      final Row row = SummaryReport.newRow();

      // general info
      row.put("Contest", ca.contestResult().getContestName());
      row.put("targeted", toString(ca.isTargeted()));
      row.put("Winner", toString(ca.contestResult().getWinners().iterator().next()));
      row.put("Risk Limit Sought", toString(ca.getRiskLimit()));
      // to perform calculations:
      row.put("Risk Limit Achieved", riskLimitAchieved(ca));
      row.put("diluted margin", toString(ca.getDilutedMargin()));
      row.put("disc +2", toString(ca.discrepancyCount(2)));
      row.put("disc +1", toString(ca.discrepancyCount(1)));
      row.put("disc -1", toString(ca.discrepancyCount(-1)));
      row.put("disc -2", toString(ca.discrepancyCount(-2)));
      row.put("gamma", toString(ca.getGamma()));

      // very detailed extra info
      row.put("ballot count", toString(ca.contestResult().getBallotCount()));
      row.put("min margin", toString(ca.contestResult().getMinMargin()));
      row.put("votes for winner", toString(ContestCounter.rankTotals(ca.contestResult().getVoteTotals()).get(0).getValue()));
      row.put("votes for runner up", toString(ContestCounter.rankTotals(ca.contestResult().getVoteTotals()).get(1).getValue()));
      row.put("total votes (marked)", toString(ca.contestResult().totalVotes()));
      row.put("disagreement count (included in +2 and +1)", toString(ca.disagreementCount()));

      rows.add(row.toArray());
    }
    return rows;
  }

  /** build a list of rows for a contest based on acvrs **/
  public static List<List<String>> getContestActivity(final String contestName) {
    final List<List<String>> rows = new ArrayList();

    final ComparisonAudit audit = ComparisonAuditQueries.matching(contestName);
    if (null == audit) {
      rows.add(NOT_FOUND_ROW);
      return rows;
    }

    final List<Long> contestCVRIds = audit.getContestCVRIds();
    final List<CastVoteRecord> acvrs = CastVoteRecordQueries.activityReport(contestCVRIds);
    acvrs.sort(Comparator.comparing(CastVoteRecord::timestamp));

    rows.add(Arrays.asList(ActivityReport.HEADERS));
    acvrs.forEach(acvr -> {
        final Row row = ActivityReport.newRow();
        rows.add(addActivityFields(addBaseFields(row, audit, acvr), acvr).toArray());
      });

    return rows;
  }

  /** build a list of rows for a contest based on tributes **/
  public static List<List<String>> getResultsReport(final String contestName) {
    final List<List<String>> rows = new ArrayList();

    final List<Tribute> tributes = TributeQueries.forContest(contestName);
    tributes.sort(Comparator.comparing(t -> t.randSequencePosition));

    final ComparisonAudit audit = ComparisonAuditQueries.matching(contestName);
    if (null == audit) {
      rows.add(NOT_FOUND_ROW);
      return rows;
    }

    final List<Long> contestCVRIds = audit.getContestCVRIds();
    final List<CastVoteRecord> acvrs = CastVoteRecordQueries.resultsReport(contestCVRIds);

    rows.add(Arrays.asList(ResultsReport.HEADERS));

    for (final Tribute tribute: tributes) {
      final Row row = ResultsReport.newRow();
      // get the acvr that was submitted for this tribute
      final String uri = tribute.getUri();
      final String aUri = uri.replaceFirst("^cvr", "acvr");
      final Optional<CastVoteRecord> acvr = acvrs.stream()
        .filter(c -> c.getUri().equals(aUri))
        .findFirst();

      if (acvr.isPresent()) {
        final Integer multiplicity = audit.multiplicity(acvr.get().getCvrId());
        rows.add(addResultsFields(addBaseFields(row, audit, acvr.get()), tribute, multiplicity).toArray());
      } else {
        // not yet audited, and we don't know the multiplicity
        rows.add(addResultsFields(row, tribute).toArray());
      }
    }

    return rows;
  }


}
