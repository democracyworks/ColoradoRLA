/*
 * Free & Fair Colorado RLA System
 *
 * @title ColoradoRLA
 * @created Aug 12, 2017
 * @copyright 2017 Colorado Department of State
 * @license SPDX-License-Identifier: AGPL-3.0-or-later
 * @creator Joseph R. Kiniry <kiniry@freeandfair.us>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.endpoint;

import static us.freeandfair.corla.asm.ASMEvent.AuditBoardDashboardEvent.*;
import static us.freeandfair.corla.asm.ASMEvent.DoSDashboardEvent.*;

import static us.freeandfair.corla.asm.ASMEvent.CountyDashboardEvent.COUNTY_AUDIT_COMPLETE_EVENT;

import java.lang.reflect.Type;

import java.util.List;

import javax.persistence.PersistenceException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import com.google.gson.reflect.TypeToken;

import spark.Request;
import spark.Response;

import us.freeandfair.corla.Main;

import us.freeandfair.corla.asm.ASMEvent;
import us.freeandfair.corla.asm.ASMUtilities;
import us.freeandfair.corla.asm.CountyDashboardASM;
import us.freeandfair.corla.asm.DoSDashboardASM;

import us.freeandfair.corla.model.County;
import us.freeandfair.corla.model.CountyDashboard;
import us.freeandfair.corla.model.Elector;
import us.freeandfair.corla.model.Round;

import us.freeandfair.corla.persistence.Persistence;

/**
 * Signs off on the current audit round for a county.
 *
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @version 1.0.0
 */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CyclomaticComplexity",
    "PMD.ModifiedCyclomaticComplexity", "PMD.StdCyclomaticComplexity"})
public class SignOffAuditRound extends AbstractAuditBoardDashboardEndpoint {
  /**
   * The type of the JSON request.
   */
  private static final Type ELECTOR_LIST =
      new TypeToken<List<Elector>>() { }.getType();

  /**
   * The event to return for this endpoint.
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
    return "/sign-off-audit-round";
  }

  /**
   * @return COUNTY authorization is required for this endpoint.
   */
  public AuthorizationType requiredAuthorization() {
    return AuthorizationType.COUNTY;
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

  /**
   * Signs off on the current audit round, regardless of its state of
   * completion.
   *
   * @param request The request.
   * @param response The response.
   */
  @Override
  public String endpointBody(final Request request,
                             final Response response) {
    final County county = Main.authentication().authenticatedCounty(request);

    if (county == null) {
      Main.LOGGER.error("could not get authenticated county");
      unauthorized(response, "not authorized to sign off on the round");
    }

    final JsonParser parser = new JsonParser();
    final JsonObject o;

    try {
      o = parser.parse(request.body()).getAsJsonObject();
      final int auditBoardIndex =
          o.get("audit_board_index").getAsInt();
      final List<Elector> signatories =
          Main.GSON.fromJson(o.get("signatories"), ELECTOR_LIST);

      if (signatories.size() < CountyDashboard.MIN_ROUND_SIGN_OFF_MEMBERS) {
        Main.LOGGER.error("too few signatories for round sign-off sent");
        invariantViolation(response, "too few signatories for round sign-off sent");
      }

      final CountyDashboard cdb = Persistence.getByID(county.id(), CountyDashboard.class);

      if (cdb == null) {
        Main.LOGGER.error("could not get county dashboard");
        serverError(response, "could not get county dashboard");
      }

      if (cdb.currentRound() == null) {
        Main.LOGGER.error("no current round on which to sign off");
        invariantViolation(response, "no current round on which to sign off");
      }

      final Round currentRound = cdb.currentRound();

      currentRound.setSignatories(auditBoardIndex, signatories);

      // If we have not seen all the boards sign off yet, we do not want to end
      // the round.
      if (currentRound.signatories().size() < cdb.auditBoardCount()) {
        Main.LOGGER.info(String.format(
            "%d of %d audit boards have signed off for county %d",
            currentRound.signatories().size(),
            cdb.auditBoardCount(),
            cdb.id()));
      } else {
        // We're done!
        cdb.endRound();

        // update the ASM state for the county and maybe DoS
        if (!DISABLE_ASM) {
          final boolean audit_complete;
          if (cdb.estimatedSamplesToAudit() <= 0) {
            // we've reached the risk limit, so the county is done
            my_event.set(RISK_LIMIT_ACHIEVED_EVENT);
            cdb.endAudits();
            audit_complete = true;
          } else if (cdb.cvrsImported() <= cdb.ballotsAudited()) {
            // there are no more ballots in the county
            my_event.set(BALLOTS_EXHAUSTED_EVENT);
            cdb.endAudits();
            audit_complete = true;
          } else {
            // the round ended normally
            my_event.set(ROUND_SIGN_OFF_EVENT);
            audit_complete = false;
          }

          if (audit_complete) {
            notifyAuditComplete();
          } else {
            notifyRoundComplete(cdb.id());
          }
        }
      }
    } catch (final PersistenceException e) {
      Main.LOGGER.error("unable to sign off on round", e);
      serverError(response, "unable to sign off round: " + e);
    } catch (final JsonParseException e) {
      Main.LOGGER.error("bad data sent in an attempt to sign off on round", e);
      badDataContents(response, "invalid request body attempting to sign off on round");
    }

    ok(response, "audit board signed off");
    return my_endpoint_result.get();
  }

  /**
   * Notifies the DoS dashboard that the round is over if all the counties
   * _except_ for the one identified in the parameter have completed their
   * audit round, or are not auditing (the excluded county is not counted
   * because its transition will not happen until this endpoint returns).
   *
   * @param the_id The ID of the county to exclude.
   */
  private void notifyRoundComplete(final Long the_id) {
    boolean finished = true;
    for (final CountyDashboard cdb : Persistence.getAll(CountyDashboard.class)) {
      if (!cdb.id().equals(the_id)) {
        finished &= cdb.currentRound() == null;
      }
    }

    if (finished) {
      ASMUtilities.step(DOS_ROUND_COMPLETE_EVENT,
                        DoSDashboardASM.class,
                        DoSDashboardASM.IDENTITY);
    }
  }

  /**
   * Notifies the county and DoS dashboards that the audit is complete.
   */
  private void notifyAuditComplete() {
    ASMUtilities.step(COUNTY_AUDIT_COMPLETE_EVENT,
                      CountyDashboardASM.class, my_asm.get().identity());
    // check to see if all counties are complete
    boolean all_complete = true;
    for (final County c : Persistence.getAll(County.class)) {
      final CountyDashboardASM asm =
          ASMUtilities.asmFor(CountyDashboardASM.class, String.valueOf(c.id()));
      all_complete &= asm.isInFinalState();
    }
    if (all_complete) {
      ASMUtilities.step(DOS_AUDIT_COMPLETE_EVENT,
                        DoSDashboardASM.class,
                        DoSDashboardASM.IDENTITY);
    } else {
      ASMUtilities.step(DOS_COUNTY_AUDIT_COMPLETE_EVENT,
                        DoSDashboardASM.class,
                        DoSDashboardASM.IDENTITY);
    }
  }
}
