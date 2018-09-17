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
import static us.freeandfair.corla.asm.ASMEvent.CountyDashboardEvent.*;
import static us.freeandfair.corla.asm.ASMEvent.DoSDashboardEvent.*;
import static us.freeandfair.corla.asm.ASMState.DoSDashboardState.COMPLETE_AUDIT_INFO_SET;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.persistence.PersistenceException;

import com.google.gson.JsonParseException;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import spark.Request;
import spark.Response;

import us.freeandfair.corla.Main;
import us.freeandfair.corla.asm.ASMEvent;
import us.freeandfair.corla.asm.ASMState.CountyDashboardState;
import us.freeandfair.corla.asm.ASMUtilities;
import us.freeandfair.corla.asm.AuditBoardDashboardASM;
import us.freeandfair.corla.asm.CountyDashboardASM;
import us.freeandfair.corla.controller.BallotSelection;
import us.freeandfair.corla.controller.BallotSelection.Segment;
import us.freeandfair.corla.controller.BallotSelection.Selection;
import us.freeandfair.corla.controller.ComparisonAuditController;
import us.freeandfair.corla.controller.ContestCounter;
import us.freeandfair.corla.json.SubmittedAuditRoundStart;
import us.freeandfair.corla.math.Audit;
import us.freeandfair.corla.model.AuditReason;
import us.freeandfair.corla.model.CastVoteRecord;
import us.freeandfair.corla.model.ComparisonAudit;
import us.freeandfair.corla.model.ContestResult;
import us.freeandfair.corla.model.ContestToAudit;
import us.freeandfair.corla.model.CountyDashboard;
import us.freeandfair.corla.model.DoSDashboard;
import us.freeandfair.corla.persistence.Persistence;
import us.freeandfair.corla.util.SuppressFBWarnings;
import us.freeandfair.corla.query.CastVoteRecordQueries;
import us.freeandfair.corla.query.ContestResultQueries;
import us.freeandfair.corla.query.ComparisonAuditQueries;

/**
 * Starts a new audit round for one or more counties.
 *
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @version 1.0.0
 */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.StdCyclomaticComplexity",
                   "PMD.AtLeastOneConstructor", "PMD.ModifiedCyclomaticComplexity",
                   "PMD.NPathComplexity", "PMD.ExcessiveImports"})
public class StartAuditRound extends AbstractDoSDashboardEndpoint {
  /**
   * Class-wide logger
   */
  public static final Logger LOGGER =
      LogManager.getLogger(StartAuditRound.class);

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
    return "/start-audit-round";
  }

  /**
   * @return STATE authorization is necessary for this endpoint.
   */
  public AuthorizationType requiredAuthorization() {
    return AuthorizationType.STATE;
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

  /** Count ContestResults, Create ComparisonAudits and assign them to CountyDashboards **/
  public void initializeAuditData(DoSDashboard dosdb) {
    final List<ContestResult> contestResults = initializeContests(dosdb.contestsToAudit());
    final List<ComparisonAudit> comparisonAudits = initializeAudits(contestResults, dosdb.auditInfo().riskLimit());
    final List<CountyDashboard> cdbs = Persistence.getAll(CountyDashboard.class);
    for (final CountyDashboard cdb : cdbs) {
      initializeCountyDashboard(cdb, comparisonAudits);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String endpointBody(final Request the_request,
                             final Response the_response) {

    final DoSDashboard dosdb = Persistence.getByID(DoSDashboard.ID, DoSDashboard.class);
    if (my_asm.get().currentState() == COMPLETE_AUDIT_INFO_SET) {
      // this is the first round
      // this needs to happen after uploading is done but before the audit is started
      initializeAuditData(dosdb);
    }

    my_event.set(DOS_START_ROUND_EVENT);
    return startRound(the_request, the_response);
  }

  /**
   * Provide the reasons for auditing each targeted contest
   * @return a map of contest name to audit reason
   */
  public Map<String, AuditReason> targetedContestReasons(final Set<ContestToAudit> ctas) {
    final Map<String,List<ContestToAudit>> contestToAudits = ctas.stream()
      .collect(Collectors.groupingBy((ContestToAudit cta) -> cta.contest().name()));

    return contestToAudits
      .entrySet()
      .stream()
      .collect(Collectors.toMap((Map.Entry<String,List<ContestToAudit>> e) -> e.getKey(),
                                // every getValue has at least one because of groupingBy
                                // every ContestToAudit has a reason
                                (Map.Entry<String,List<ContestToAudit>> e) -> e.getValue().get(0).reason()));
  }

  /**
   * Update every - targeted and opportunistic both - contest's
   * voteTotals from the counties. This needs to happen between all
   * counties uploading there data and before the ballot selection
   * happens
   */
  public List<ContestResult> countAndSaveContests(final Set<ContestToAudit> cta) {
    return
      ContestCounter.countAllContests().stream()
      .map(cr -> {cr.setAuditReason(targetedContestReasons(cta)
                                    .getOrDefault(cr.getContestName(),
                                                  AuditReason.OPPORTUNISTIC_BENEFITS));
                  return cr; })
      .map(Persistence::persist)
      .collect(Collectors.toList());
  }

  /**
   * find the first cvr that is not audited and that is how far we are along in
   * the audit, according to theory
   **/
  public Integer auditedPrefixLength(Map<Long,Boolean> cvrsById, List<Long> cvrIds) {
    Integer apl = 0;
    for (int i=0; i > cvrIds.size(); i++) {
      if (!cvrsById.get(cvrIds.get(i))) {
        apl = i;
        break;
      }
    }
    return apl;
  }

  /**
   * sets selection on each contestResult, the results of
   * BallotSelection.randomSelection
   */
  public void makeSelections(final String seed,
                             final BigDecimal riskLimit) {
    final List<ContestResult> contestResults = Persistence.getAll(ContestResult.class);
    for(final ContestResult contestResult: contestResults) {
      // only make selection for targeted contests
      // the only AuditReasons in play are county, state and opportunistic
      if (contestResult.getAuditReason() != AuditReason.OPPORTUNISTIC_BENEFITS) {
        final BigDecimal optimistic =
          Audit.optimistic(riskLimit, contestResult.getDilutedMargin());
        final List<CastVoteRecord> cvrs = CastVoteRecordQueries.get(contestResult.getContestCVRIds());

        LOGGER.debug(String.format("[makeSelections for ContestResult: contestName=%s, contestCVRIds=%s]",
                                   contestResult.getContestName(),
                                   contestResult.getContestCVRIds()));

        final Map cvrsById = new HashMap<>();
        for (final CastVoteRecord cvr : cvrs) {
          LOGGER.debug(String.format("Adding selection: ", cvr));
          cvrsById.put(cvr.id(), cvr.isAudited());
        }

        final Integer startIndex = auditedPrefixLength(cvrsById, contestResult.getContestCVRIds());
        final Integer endIndex = optimistic.intValue() - 1;

        Selection selection = BallotSelection.randomSelection(contestResult,
                                                              seed,
                                                              startIndex,
                                                              endIndex);
        LOGGER.info("makeSelections selection= " + selection);
        LOGGER.info("makeSelections contestCVRIds= " + selection.contestCVRIds());
        selection.riskLimit = riskLimit;
        contestResult.selection = selection;
        contestResult.setContestCVRIds(selection.contestCVRIds());
      } else {
        Selection selection = new Selection();
        selection.riskLimit = riskLimit;
        contestResult.selection = selection;
      }
    }
  }

  /**
   * All contests for county and their selections combined into a
   * single segment
   **/
  public Segment combinedSegment(CountyDashboard cdb) {
    List<Segment> countyContestSegments = cdb.comparisonAudits().stream()
      .map(ca -> (Segment)ca.contestResult().selection.forCounty(cdb.county().id()))
      .collect(Collectors.toList());
    return Selection.combineSegments(countyContestSegments);
  }

  public List<ContestResult> initializeContests(Set<ContestToAudit> contestsToAudit) {
    LOGGER.debug(String.format("[initializeContests: contestsToAudit=%s]", contestsToAudit));
    // FIXME improve this check for "have all contests been counted?"
    final List<ContestResult> persistedContestResults = countAndSaveContests(contestsToAudit);
    LOGGER.debug(String.format("[initializeContests: persistedContestResults=%s]",
                               persistedContestResults));
    return persistedContestResults;
  }

  /**
   * Warning: Contains Side Effects
   */
  public List<ComparisonAudit> initializeAudits(final List<ContestResult> contestResults,
                                                final BigDecimal riskLimit) {
    // fixme: just looking
    final List<ContestResult> targetedContestResults = contestResults.stream()
      .filter(cr -> cr.getAuditReason() != AuditReason.OPPORTUNISTIC_BENEFITS)
      .collect(Collectors.toList());

    List<ComparisonAudit> comparisonAudits = contestResults.stream()
      .map(cr -> ComparisonAuditController.createAudit(cr, riskLimit))
      .collect(Collectors.toList());
    LOGGER.debug(String.format("[initializeAudits: contestResults=%s, targetedContestResults=%s, comparisonAudits=%s]",
                               contestResults, targetedContestResults, comparisonAudits));

    return comparisonAudits;
  }

  public void initializeCountyDashboard(final CountyDashboard cdb,
                                        final List<ComparisonAudit> comparisonAudits) {
    final Set<String> drivingContestNames = comparisonAudits.stream()
      .filter(ca -> ca.contestResult().getAuditReason() != AuditReason.OPPORTUNISTIC_BENEFITS)
      .map(ca -> ca.contestResult().getContestName())
      .collect(Collectors.toSet());

    cdb.setAuditedSampleCount(0);
    cdb.setAuditedPrefixLength(0);
    cdb.setDrivingContestNames(drivingContestNames);

    Set<ComparisonAudit> countyAudits = new HashSet<>();
    if (cdb.getAudits().isEmpty()) {
      countyAudits =
        comparisonAudits.stream()
        .filter(ca -> ca.isForCounty(cdb.county().id()))
        .collect(Collectors.toSet());
      cdb.setAudits(countyAudits);
    }
    LOGGER.debug(String.format("[initializeCountyDashboard: cdb=%s, comparisonAudits=%s, drivingContestNames=%s, countyAudits=%s]",
                               cdb, comparisonAudits, drivingContestNames, countyAudits));
  }

  /**
   * Starts the first audit round.
   *
   * @param the_request The HTTP request.
   * @param the_response The HTTP response.
   * @return the result for endpoint.
   */
  // FIXME With some refactoring, we won't have excessive method length.
  @SuppressWarnings({"PMD.ExcessiveMethodLength"})
  public String startRound(final Request the_request, final Response the_response) {
    final DoSDashboard dosdb = Persistence.getByID(DoSDashboard.ID, DoSDashboard.class);
    final BigDecimal riskLimit = dosdb.auditInfo().riskLimit();
    final String seed = dosdb.auditInfo().seed();

    makeSelections(seed, riskLimit);    // sets Selections on contestResults

    // Nothing in this try-block should know about HTTP requests / responses
    // update every county dashboard with a list of ballots to audit
    try {
      final List<CountyDashboard> cdbs = Persistence.getAll(CountyDashboard.class);

      // this flag starts off true if we're going to conjoin it with all the ASM
      // states, and false otherwise as we just assume audit reasonableness in the
      // absence of ASMs
      boolean audit_complete = !DISABLE_ASM;

      for (final CountyDashboard cdb : cdbs) {
        try {
          // FIXME predicate might be better off state based....MOVE THIS TO INITIALIZE_COUNTY_DASHBOARD
          if (cdb.cvrFile() == null || cdb.manifestFile() == null) {
            LOGGER.info(String.format("[County %s missed the file upload deadline" +
                                      " moving to COUNTY_DEADLINE_MISSED_EVENT]",
                                      cdb.county()));
          } else {

            // Selections for all contests that this county is participating in
            final Segment segment = combinedSegment(cdb);

            LOGGER.debug(String.format("[startRoundOne:"
                                       + " county=%s, segment.auditSequence()=%s,"
                                       + " segment.ballotSequence()=%s,"
                                       + " cdb.comparisonAudits=%s,",
                                       cdb.county(), segment.auditSequence(),
                                       segment.ballotSequence(), cdb.comparisonAudits()));
            final boolean started =
              ComparisonAuditController.startRound(cdb,
                                                   cdb.comparisonAudits(),
                                                   segment.auditSequence(),
                                                   segment.ballotSequence());

            if (started) {
              LOGGER.info("County " + cdb.id() + " estimated to audit " +
                          cdb.estimatedSamplesToAudit() + " ballots in round 1");
            } else if (cdb.drivingContestNames().isEmpty()) {
              LOGGER.info("County " + cdb.id() + " has no driving contests, its " +
                          "audit is complete.");
            } else if (cdb.estimatedSamplesToAudit() == 0) {
              LOGGER.info("County "  + cdb.id() + " needs to audit 0 ballots to " +
                          "achieve its risk limit, its audit is complete.");
            } else {
              LOGGER.error("unable to start audit for county " + cdb.id());
            }
            Persistence.saveOrUpdate(cdb);
          }
          // FIXME extract-fn: updateASMs(dashboardID, ,,,)
          // update the ASMs for the county and audit board
          if (!DISABLE_ASM) {
            final CountyDashboardASM asm =
                ASMUtilities.asmFor(CountyDashboardASM.class, String.valueOf(cdb.id()));
            asm.stepEvent(COUNTY_START_AUDIT_EVENT);
            final ASMEvent audit_event;
            if (asm.currentState().equals(CountyDashboardState.COUNTY_AUDIT_UNDERWAY)) {
              if (cdb.comparisonAudits().isEmpty()) {
                // the county made its deadline but was assigned no contests to audit
                audit_event = NO_CONTESTS_TO_AUDIT_EVENT;
                asm.stepEvent(COUNTY_AUDIT_COMPLETE_EVENT);
              } else if (cdb.estimatedSamplesToAudit() <= 0) {
                // the county made its deadline but has already achieved its risk limit
                audit_event = RISK_LIMIT_ACHIEVED_EVENT;
                asm.stepEvent(COUNTY_AUDIT_COMPLETE_EVENT);
              } else {
                // the audit started normally
                audit_event = ROUND_START_EVENT;
              }
            } else {
              // the county missed its deadline
              audit_event = COUNTY_DEADLINE_MISSED_EVENT;
            }
            ASMUtilities.step(audit_event, AuditBoardDashboardASM.class,
                              String.valueOf(cdb.id()));
            ASMUtilities.save(asm);

            // figure out whether this county is done, or whether there's an audit to run
            audit_complete &= asm.isInFinalState();
          }
        // FIXME hoist me; we don't need to know about HTTP requests or
        // responses at this level.
        } catch (final IllegalArgumentException e) {
          e.printStackTrace(System.out);
          serverError(the_response, "could not start round 1 for county " +
                      cdb.id());
          LOGGER.info("could not start round 1 for county " + cdb.id());
        } catch (final IllegalStateException e) {
          illegalTransition(the_response, e.getMessage());
        }
      }
      // FIXME hoist me
      if (audit_complete) {
        my_event.set(DOS_AUDIT_COMPLETE_EVENT);
        ok(the_response, "audit complete");
      } else {
        ok(the_response, "round 1 started");
      }
      // end of extraction. Now we can talk about HTTP requests / responses again!
    } catch (final PersistenceException e) {
      serverError(the_response, "could not start round 1");
    }

    return my_endpoint_result.get();
  }

  /**
   * Given a request to start a round thingy, return the dashboards to start.
   */
  public List<CountyDashboard> dashboardsToStart(final SubmittedAuditRoundStart sars) {
    final List<CountyDashboard> cdbs;

    if (sars.countyBallots() == null || sars.countyBallots().isEmpty()) {
      cdbs = Persistence.getAll(CountyDashboard.class);
    } else {
      cdbs = new ArrayList<>();
      for (final Long id : sars.countyBallots().keySet()) {
        cdbs.add(Persistence.getByID(id, CountyDashboard.class));
      }
    }
    return cdbs;
  }


  // /**
  //  * Starts a subsequent audit round.
  //  *
  //  * @param the_request The HTTP request.
  //  * @param the_response The HTTP response.
  //  * @return the result for endpoint.
  //  */
  // // FindBugs thinks there's a possible NPE, but there's not because
  // // badDataContents() would bail on the method before it happened.
  // public static boolean startSubsequentRound(final CountyDashboard cdb,
  //                                            final Set<ComparisonAudit> audits,
  //                                            final List<Long> auditSequence,
  //                                            final List<Long> ballotSequence) {
  //   cdb.startRound(ballotSequence.size(),
  //                  auditSequence.size(),
  //                  auditSequence.size() + 1, // LIE!
  //                  ballotSequence,
  //                  auditSequence);
  //   // FIXME These were private to ComparisonAuditController; maybe this
  //   // method belongs back there.
  //   ComparisonAuditController.updateRound(cdb, cdb.currentRound());
  //   ComparisonAuditController.updateCVRUnderAudit(cdb);

  //   // if the round was started there will be ballots to count
  //   return cdb.ballotsRemainingInCurrentRound() > 0;
  // }

  @SuppressFBWarnings("NP_NULL_ON_SOME_PATH")
  public String startSubsequentRound(final Request the_request, final Response the_response) {
    SubmittedAuditRoundStart start = null;
    try {
      start = Main.GSON.fromJson(the_request.body(), SubmittedAuditRoundStart.class);
      if (start == null) {
        badDataContents(the_response, "malformed request data");
      }
    } catch (final JsonParseException e) {
      badDataContents(the_response, "malformed request data: " + e.getMessage());
    }

    try {
      // first, figure out what counties we need to do this for, if the
      // list is limited.
      final List<CountyDashboard> cdbs = dashboardsToStart(start);

      for (final CountyDashboard cdb : cdbs) {
        final AuditBoardDashboardASM asm = ASMUtilities.asmFor(AuditBoardDashboardASM.class, cdb.id().toString());
        if (asm.isInInitialState() || asm.isInFinalState()) {
          // there is no audit happening in this county, so go to the next one
          LOGGER.debug("no audit ongoing in county " + cdb.id() +
                           ", skipping round start");
          continue;
        }

        // if the county is in the middle of a round, error out
        if (cdb.currentRound() != null) {
          invariantViolation(the_response,
                             "audit round already in progress for county " + cdb.id());
        }

        final ASMEvent audit_event;
        boolean round_started = false;
        final BigDecimal multiplier;
        if (start.multiplier() == null) {
          multiplier = BigDecimal.ONE;
        } else {
          multiplier = start.multiplier();
        }

        final Segment segment = combinedSegment(cdb);

        LOGGER.info("county = " + cdb.county() + " subsequence = " + segment.auditSequence());

        // FIXME we need an index into the audit/ballot sequences to
        // pick up where we left off?
        round_started = ComparisonAuditController.startSubsequentRound(cdb,
                                                                       cdb.comparisonAudits(),
                                                                       segment.auditSequence(),
                                                                       segment.ballotSequence());

        if (round_started) {
          LOGGER.debug("round started for county " + cdb.id());
          audit_event = ROUND_START_EVENT;
        } else {
          // we don't know why the round didn't start, so we need to abort the audit
          LOGGER.debug("no round started for county " + cdb.id());
          audit_event = ABORT_AUDIT_EVENT;
        }

        // update the ASM for the audit board
        if (!DISABLE_ASM) {
          asm.stepEvent(audit_event);
          ASMUtilities.save(asm);
        }
      }
      ok(the_response, "new audit round started");
    } catch (final PersistenceException e) {
      serverError(the_response, "could not start new audit round");
    }

    return my_endpoint_result.get();
  }
}
