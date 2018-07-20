/**
 * Prepare a list of ballots from a list of random numbers
 **/
package us.freeandfair.corla.controller;

import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import us.freeandfair.corla.json.CVRToAuditResponse;
import us.freeandfair.corla.json.CVRToAuditResponse.BallotOrderComparator;
import us.freeandfair.corla.model.BallotManifestInfo;
import us.freeandfair.corla.model.CastVoteRecord;
import us.freeandfair.corla.query.BallotManifestInfoQueries;
import us.freeandfair.corla.query.CastVoteRecordQueries;

public final class BallotSelection {

  /** prevent construction **/
  private BallotSelection() {
  }

  /**
   * Prepare a list of ballots from random numbers. Asks the
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
                         BallotManifestInfoQueries::holdingSequenceNumber,
                         CastVoteRecordQueries::atPosition);
  }

  /**
   * same as above with optional dependency injection
   **/
  public static List<CVRToAuditResponse>
      selectBallots(final List<Long> rands,
                    final Long countyID,
                    final Function<Long,Optional<BallotManifestInfo>> queryBMI,
                    final CVRQ queryCVR) {

    // this is what gets added to and returned
    final List<CVRToAuditResponse> a_list = new LinkedList<CVRToAuditResponse>();

    // dedup! are we supposed to be doing this? probably(?):
    // ComparisonAuditController does!
    final List<Long> deduped = dedup(rands);

    Integer audit_sequence_number = 0;
    for (final Long rand: deduped) {
      // could we get them all at once? I'm not sure
      final Optional<BallotManifestInfo> bmiMaybe = queryBMI.apply(rand);
      CastVoteRecord cvr;

      if (bmiMaybe.isPresent()) {
        final BallotManifestInfo bmi = bmiMaybe.get();
        // theoretically we don't need cvrs to render ballot info - practically,
        // though, we need the cvr info for the app to work
        cvr = queryCVR.apply(bmi.countyID(),
                                            bmi.scannerID(),
                                            bmi.batchID(),
                                            bmi.ballotPosition(rand));
        if (cvr == null) {
          // TODO: create a discrepancy when this happens
          cvr = notFoundCVR();
        }
        a_list.add(toResponse(audit_sequence_number, rand, bmi, cvr));
      } else {
        final String msg = "could not find a ballot manifest for random number: "
            + rand;
        throw new BallotSelection.MissingBallotManifestException(msg);
      }

      audit_sequence_number++;
    }
    a_list.sort(new BallotOrderComparator());
    return a_list;
  }

  /** remove duplicates **/
  public static List<Long> dedup(final List<Long> rands) {
    return new LinkedList<Long>(new LinkedHashSet<Long>(rands));
  }

  /** PHANTOM_RECORD conspiracy theory time **/
  public static CastVoteRecord notFoundCVR() {
    final CastVoteRecord cvr = new CastVoteRecord(CastVoteRecord.RecordType.PHANTOM_RECORD,
                                                  null,
                                                  0L,
                                                  0,
                                                  0,
                                                  0,
                                                  "",
                                                  0,
                                                  "",
                                                  "NOT FOUND",
                                                  null);
    // TODO prevent the client from requesting info about this cvr
    cvr.setID(0L);
    return cvr;
  }

  /**
   * get ready to render the data
   **/
  public static CVRToAuditResponse toResponse(final int audit_sequence_number,
                                              final Long rand,
                                              final BallotManifestInfo bmi,
                                              final CastVoteRecord cvr) {

    return new CVRToAuditResponse(audit_sequence_number,
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
   * this is bad, it could be one of two things:
   * - a random number was generated outside of the number of (theoretical) ballots
   * - there is a gap in the sequence_start and sequence_end values of the
   *   ballot_manifest_infos
   **/
  public static class MissingBallotManifestException extends RuntimeException {
    /** constructor **/
    public MissingBallotManifestException(final String msg) {
      super(msg);
    }
  }

 /**
   * a functional interface to pass a function as an argument that takes two
   * arguments
   **/
  public interface CVRQ {

    /** how to query the database **/
    CastVoteRecord apply(Long county_id,
                         Integer scanner_id,
                         String batch_id,
                         Long position);
  }
}
