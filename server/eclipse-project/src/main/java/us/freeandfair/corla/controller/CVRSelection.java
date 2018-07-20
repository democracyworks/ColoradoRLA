/**
 * Prepare a list of cast vote records. This is the old style of ballot selection
 * and is deprecated. We're keeping it around as a fallback until we are
 * confident in the BallotSelection class
 **/
package us.freeandfair.corla.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;

import us.freeandfair.corla.json.CVRToAuditResponse;
import us.freeandfair.corla.json.CVRToAuditResponse.BallotOrderComparator;
import us.freeandfair.corla.model.CastVoteRecord;
import us.freeandfair.corla.model.CountyDashboard;
import us.freeandfair.corla.query.BallotManifestInfoQueries;

public final class CVRSelection {

  private CVRSelection() {
  }

  /**
   * Prepare a list of cast vote records
   **/
  public static List<CVRToAuditResponse>
      selectCVRs(final CountyDashboard cdb,
                 final OptionalInt round_index,
                 final boolean audited,
                 final boolean duplicates,
                 final int ballot_count,
                 final int index) {

    final List<CVRToAuditResponse> response_list = new ArrayList<>();
    final List<CastVoteRecord> cvr_to_audit_list;

    if (round_index.isPresent()) {
      cvr_to_audit_list =
        ComparisonAuditController.ballotsToAudit(cdb, round_index.getAsInt(), audited);
    } else {
      cvr_to_audit_list =
        ComparisonAuditController.computeBallotOrder(cdb, index, ballot_count,
                                                     duplicates, audited);
    }

    for (int i = 0; i < cvr_to_audit_list.size(); i++) {
      final CastVoteRecord cvr = cvr_to_audit_list.get(i);
      final String location = BallotManifestInfoQueries.locationFor(cvr);
      response_list.add(new CVRToAuditResponse(i, cvr.scannerID(),
                                               cvr.batchID(), cvr.recordID(),
                                               cvr.imprintedID(),
                                               cvr.cvrNumber(), cvr.id(),
                                               cvr.ballotType(), location,
                                               cvr.auditFlag()));
    }
    response_list.sort(new BallotOrderComparator());

    return response_list;
  }


}
