/*
 * Free & Fair Colorado RLA System
 *
 * @title ColoradoRLA
 * @created Jul 27, 2017
 * @copyright 2017 Colorado Department of State
 * @license SPDX-License-Identifier: AGPL-3.0-or-later
 * @creator Daniel M. Zimmerman <dmz@freeandfair.us>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.endpoint;

import static us.freeandfair.corla.asm.ASMEvent.AuditBoardDashboardEvent.*;

import java.time.Instant;

import javax.persistence.PersistenceException;

import com.google.gson.JsonParseException;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import spark.Request;
import spark.Response;

import us.freeandfair.corla.Main;
import us.freeandfair.corla.asm.ASMEvent;
import us.freeandfair.corla.controller.ComparisonAuditController;
import us.freeandfair.corla.json.SubmittedAuditCVR;
import us.freeandfair.corla.model.CastVoteRecord;
import us.freeandfair.corla.model.CastVoteRecord.RecordType;
import us.freeandfair.corla.model.CountyDashboard;
import us.freeandfair.corla.persistence.Persistence;

/**
 * The "audit CVR upload" endpoint.
 *
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @version 1.0.0
 */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CyclomaticComplexity"})
// TODO: consider rewriting along the same lines as CVRExportUpload
public class ACVRUpload extends AbstractAuditBoardDashboardEndpoint {
  /**
   * Class-wide logger
   */
  public static final Logger LOGGER =
    LogManager.getLogger(ACVRUpload.class);
  /**
   * The event we will return for the ASM.
   */
  private final ThreadLocal<ASMEvent> my_event = new ThreadLocal<ASMEvent>();

  /**
   * {@inheritDoc}
   */
  @Override
  public EndpointType endpointType() {
    return EndpointType.POST;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String endpointName() {
    return "/upload-audit-cvr";
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected ASMEvent endpointEvent() {
    return my_event.get();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void reset() {
    my_event.set(null);
  }

  /** build new acvr **/
  public CastVoteRecord buildNewAcvr(final SubmittedAuditCVR submission,
                                     final CastVoteRecord cvr,
                                     final CountyDashboard cdb) {
    final CastVoteRecord s = submission.auditCVR();
    final CastVoteRecord newAcvr =
      new CastVoteRecord(RecordType.AUDITOR_ENTERED,
                         Instant.now(),
                         s.countyID(), s.cvrNumber(), null, s.scannerID(),
                         s.batchID(), s.recordID(), s.imprintedID(),
                         s.ballotType(), s.contestInfo());
    newAcvr.setAuditBoardIndex(submission.getAuditBoardIndex());
    newAcvr.setCvrId(submission.cvrID());
    newAcvr.setRoundNumber(cdb.currentRound().number());
    newAcvr.setRand(cvr.getRand());

    return newAcvr;
  }

  /**
   * {@inheritDoc}
   */
  @SuppressWarnings({"PMD.ModifiedCyclomaticComplexity", "PMD.StdCyclomaticComplexity"})
  @Override
  public String endpointBody(final Request the_request, final Response the_response) {
    final CastVoteRecord newAcvr;

    try {
      final SubmittedAuditCVR submission =
        Main.GSON.fromJson(the_request.body(), SubmittedAuditCVR.class);
      if (submission.auditCVR() == null || submission.cvrID() == null) {
        LOGGER.error("empty audit CVR upload");
        badDataContents(the_response, "empty audit CVR upload");
      } else {
        // FIXME extract-fn: handleACVR
        final CountyDashboard cdb =
            Persistence.getByID(Main.authentication().authenticatedCounty(the_request).id(),
                                CountyDashboard.class);
        if (cdb == null) {
          LOGGER.error("could not get audit board dashboard");
          serverError(the_response, "Could not save ACVR to dashboard");
        } else if (submission.isReaudit()) {

          final CastVoteRecord cvr = Persistence.getByID(submission.cvrID(),
                                                         CastVoteRecord.class);
          newAcvr = buildNewAcvr(submission, cvr, cdb);

          if (ComparisonAuditController.reaudit(cdb,cvr,newAcvr, submission.getComment())) {
            ok(the_response, "ACVR reaudited");
          } else {
            invariantViolation(the_response, "CVR has not previously been audited");
          }

        } else if (cdb.ballotsRemainingInCurrentRound() > 0) {

          // Now we have a thing we can give our controller, maybe.
          final CastVoteRecord cvr = Persistence.getByID(submission.cvrID(),
                                                         CastVoteRecord.class);

          // FIXME extract-fn: setupACVR
          final CastVoteRecord acvr = submission.auditCVR();
          acvr.setID(null);

          newAcvr = buildNewAcvr(submission, cvr, cdb);

          Persistence.saveOrUpdate(newAcvr);
          LOGGER.info("Audit CVR for CVR id " + submission.cvrID() +
                           " parsed and stored as id " + newAcvr.id());

          if (cvr == null) {
            LOGGER.error("could not find original CVR");
            // FIXME throw and push HTTP response up.
            this.badDataContents(the_response, "could not find original CVR");
          } else {

            // The positive outcome is a little hard to notice in all the noise
            // FIXME return an appropriate value and push HTTP response up
            if (ComparisonAuditController.submitAuditCVR(cdb, cvr, newAcvr)) {
              LOGGER.debug("ACVR OK");
              Persistence.saveOrUpdate(cdb);
              ok(the_response, "ACVR submitted");
            } else {
              // FIXME throw and push HTTP response up
              LOGGER.error("invalid audit CVR uploaded");
              badDataContents(the_response, "invalid audit CVR uploaded");
            }
          }
        } else {
          // FIXME throw and push HTTP response up
          LOGGER.error("ballot submission with no remaining ballots in round");
          invariantViolation(the_response,
                             "ballot submission with no remaining ballots in round");
        }

        // don't advance state machine if reaudit
        if (!submission.isReaudit()) {
          if (cdb.ballotsRemainingInCurrentRound() == 0) {
            // TODO this has to happen before we can say RISK_LIMIT_ACHIEVED!
            LOGGER.debug("The round is over and set ROUND_COMPLETE_EVENT");
            my_event.set(ROUND_COMPLETE_EVENT);
          } else {
            LOGGER.debug("Some ballots remaining according to the CDB: REPORT_MARKING_EVENT");
            my_event.set(REPORT_MARKINGS_EVENT);
          }
        }
      } // extract-fn: handleACVR will have returned some value or thrown
    } catch (final JsonParseException e) {
      LOGGER.error("malformed audit CVR upload");
      badDataContents(the_response, "malformed audit CVR upload");
    } catch (final PersistenceException e) {
      LOGGER.error("could not save audit CVR");
      serverError(the_response, "Unable to save audit CVR");
    }
    return my_endpoint_result.get();
  }
}
