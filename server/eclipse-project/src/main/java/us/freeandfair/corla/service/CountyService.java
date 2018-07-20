/*
 * Colorado Risk Limiting Audit System
 *
 * @title       ColoradoRLA
 * @created     Jul 12, 2018
 * @copyright   2018 Colorado Department of State
 * @license     SPDX-License-Identifier: AGPL-3.0-or-later
 * @creator     Democracy Works, Inc. <dev@democracy.works>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.service;

import java.util.LinkedList;
import java.util.List;
import java.util.OptionalLong;

import java.util.stream.Collectors;

import us.freeandfair.corla.crypto.PseudoRandomNumberGenerator;
import us.freeandfair.corla.model.CastVoteRecord.RecordType;
import us.freeandfair.corla.model.County;
import us.freeandfair.corla.model.DoSDashboard;
import us.freeandfair.corla.persistence.Persistence;
import us.freeandfair.corla.query.CastVoteRecordQueries;

/**
 * Service layer for County model objects.
 *
 * @author Democracy Works, Inc. <dev@democracy.works>
 */
public final class CountyService {
  /**
   * The County that this service is acting on.
   */
  private final County county;

  /**
   * Create a new CountyService given a County.
   *
   * @param county a County for the service to act on
   */
  public CountyService(final County the_county) {
    this.county = the_county;
  }

  /**
   * Returns a slice of pseudo-random numbers for the given county based on the
   * defined audit seed.
   *
   * @param  minIndex the 0-based start point for the sequence of random numbers
   * @param  maxIndex the 0-based end point for the sequence of random numbers
   * @return          a list of pseudo-random numbers whose values are
   *                  between 1 and the count of the ballots belonging to
   *                  the county, inclusive
   */
  public List<Long> getRandomNumbers(final int minIndex, final int maxIndex) {
    // TODO: Query the ballot manifest rather than the CVR.
    final OptionalLong count =
        CastVoteRecordQueries.countMatching(this.county.id(), RecordType.UPLOADED);

    if (!count.isPresent()) {
      throw new IllegalStateException("unable to count ballots for county " +
                                      this.county.id());
    }

    final String seed =
        Persistence.getByID(DoSDashboard.ID, DoSDashboard.class)
          .auditInfo()
          .seed();

    final boolean withReplacement = true;
    // 1-based index, taking cues from the literature
    final int minimum = 1;
    final int maximum = (int) count.getAsLong();

    final PseudoRandomNumberGenerator prng =
        new PseudoRandomNumberGenerator(seed, withReplacement, minimum, maximum);

    return prng.getRandomNumbers(minIndex, maxIndex)
       .stream()
       // Convert to longs in advance of modifying the underlying PRNG.
       .map(Integer::toUnsignedLong)
       .collect(Collectors.toCollection(LinkedList::new));
  }
}
