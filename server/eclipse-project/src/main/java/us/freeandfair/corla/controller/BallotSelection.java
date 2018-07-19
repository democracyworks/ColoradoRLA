/**
 * Prepare a list of ballot information from a list of random numbers
 **/
package us.freeandfair.corla.controller;

import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.BiFunction;

import us.freeandfair.corla.json.CVRToAuditResponse;
import us.freeandfair.corla.json.CVRToAuditResponse.BallotOrderComparator;
import us.freeandfair.corla.model.BallotManifestInfo;
import us.freeandfair.corla.model.CastVoteRecord;
import us.freeandfair.corla.query.BallotManifestInfoQueries;
import us.freeandfair.corla.query.CastVoteRecordQueries;

public final class BallotSelection {

  private BallotSelection() {
  }

  @FunctionalInterface
  public interface CVRQ {
    public List<CastVoteRecord> apply(List<Long> l, Long c);
  }

  /**
   * Prepare a list of ballot information from random numbers. Asks the
   * ballot_manifest_info table for info and joins in some info from
   * cast_vote_records. We are very intentional about the source of data coming
   * from the ballot_manifest_info and not the cast_vote_records. The
   * cast_vote_records info is merged in as a convenience to find discrepancies
   * as early as possible.
   **/
  public static List<CVRToAuditResponse> selectBallots(final List<Long> rands,
                                                       final Long countyID) {
    return selectBallots(rands,
                         countyID,
                         BallotSelection::queryBallotManifestInfos,
                         BallotSelection::queryCastVoteRecords);
  }

  /**
   * same as above with optional dependency injection
   **/
  public static List<CVRToAuditResponse>
      selectBallots(final List<Long> rands,
                    final Long countyID,
                    final Function<Long,Optional<BallotManifestInfo>> queryBMI,
                    final CVRQ queryCVR) {
    final List<CVRToAuditResponse> a_list = new LinkedList<CVRToAuditResponse>();
    // here we rely on the id of the cvr to match the audit_sequence_number.
    // This is done by incrementing a counter during the file import.
    final List<CastVoteRecord> cvrs = queryCVR.apply(rands, countyID);

    int i = 0;
    for (final Long rand: rands) {
      i++;
      final Optional<BallotManifestInfo> bmiMaybe = queryBMI.apply(rand);

      CastVoteRecord cvr;
      try {
        cvr = cvrs.get(i - 1); // index is 0 based
      } catch (final IndexOutOfBoundsException e) {
        // TODO create a warning or a discrepancy of some kind
        cvr = new CastVoteRecord(CastVoteRecord.RecordType.PHANTOM_RECORD,
                                 null,
                                 0L,
                                 0,
                                 0,
                                 0,
                                 "",
                                 0,
                                 "",
                                 "",
                                 null);
        cvr.setID(0L);
      }

      if (bmiMaybe.isPresent()) {
        a_list.add(toResponse(i, rand, bmiMaybe.get(), cvr));
      } else {
        final String msg = "could not find a ballot manifest for random number: " +
            rand.toString();
        throw new BallotSelection.MissingBallotManifestException(msg);
      }
    }
    a_list.sort(new BallotOrderComparator());
    return a_list;
  }

  /**
   * get ready to render the data
   **/
  public static CVRToAuditResponse toResponse(final int the_audit_sequence_number,
                                              final Long rand,
                                              final BallotManifestInfo bmi,
                                              final CastVoteRecord cvr) {

    return new CVRToAuditResponse(the_audit_sequence_number,
                                  bmi.scannerID(),
                                  bmi.batchID(),
                                  bmi.ballotPosition(rand).intValue(),
                                  bmi.imprintedID(rand),
                                  cvr.cvrNumber(),
                                  cvr.id(),
                                  cvr.ballotType(),
                                  bmi.storageLocation(),
                                  cvr.auditFlag());
  }

  /**
   * query the database for ballot_manifest_info that would hold the given
   * random number
   **/
  public static Optional<BallotManifestInfo> queryBallotManifestInfos(final Long rand) {
    return BallotManifestInfoQueries.holdingSequenceNumber(rand);
  }

  /**
   * query the database for cast_vote_records with sequence_numbers that are in the given
   * list of random numbers
   **/
  public static List<CastVoteRecord> queryCastVoteRecords(final List<Long> rands,
                                                          final Long countyID) {
    return CastVoteRecordQueries.get(countyID,
                                     rands);
  }

  /**
   * this is bad, it could be one of two things:
   * - a random number was generated outside of the number of (theoretical) ballots
   * - there is a gap in the sequence_start and sequence_end values of the
         ballot_manifest_infos
   **/
  public static class MissingBallotManifestException extends RuntimeException {
    /** constructor **/
    public MissingBallotManifestException(final String msg) {
      super(msg);
    }
  }
}
