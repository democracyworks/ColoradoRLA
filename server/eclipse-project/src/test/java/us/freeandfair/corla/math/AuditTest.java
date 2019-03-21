package us.freeandfair.corla.math;

import java.math.BigDecimal;
import java.math.MathContext;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public final class AuditTest {
  @Test()
  public void testOptimistic() {

    final BigDecimal riskLimit = BigDecimal.valueOf(0.5);
    final BigDecimal dilutedMargin = BigDecimal.valueOf(0.05);
    final BigDecimal gamma = BigDecimal.valueOf(1.2);
    final int twoUnder = 0;
    final int oneUnder = 0;
    final int oneOver = 0;
    final int twoOver = 0;

    BigDecimal result = Audit.optimistic(riskLimit,
                                         dilutedMargin,
                                         gamma,
                                         twoUnder,
                                         oneUnder,
                                         oneOver,
                                         twoOver);
    assertEquals(34, result.intValue());
  }

  @Test()
  public void testPValueApproximation() {
    // Values from table 3 of Stark's paper:
    // https://www.usenix.org/legacy/event/evtwote10/tech/full_papers/Stark.pdf

    int auditedBallots = 500;
    BigDecimal dilutedMargin = BigDecimal.valueOf(0.02);
    BigDecimal gamma = BigDecimal.valueOf(1.01);
    int oneUnder = 0;
    int twoUnder = 0;
    int oneOver = 0;
    int twoOver = 0;

    BigDecimal result = Audit.pValueApproximation(
        auditedBallots,
        dilutedMargin,
        gamma,
        oneUnder,
        twoUnder,
        oneOver,
        twoOver
    );

    assertEquals(
        result.setScale(3, BigDecimal.ROUND_HALF_UP),
        BigDecimal.valueOf(0.007)
    );

    oneOver = 3;
    twoOver = 0;

    result = Audit.pValueApproximation(
        auditedBallots,
        dilutedMargin,
        gamma,
        oneUnder,
        twoUnder,
        oneOver,
        twoOver
    );

    assertEquals(
        result.setScale(3, BigDecimal.ROUND_HALF_UP),
        BigDecimal.valueOf(0.054)
    );

    oneOver = 0;
    twoOver = 1;

    result = Audit.pValueApproximation(
        auditedBallots,
        dilutedMargin,
        gamma,
        oneUnder,
        twoUnder,
        oneOver,
        twoOver
    );

    assertEquals(
        result.setScale(3, BigDecimal.ROUND_HALF_UP),
        BigDecimal.valueOf(0.698)
    );

    oneOver = 0;
    twoOver = 2;

    result = Audit.pValueApproximation(
        auditedBallots,
        dilutedMargin,
        gamma,
        oneUnder,
        twoUnder,
        oneOver,
        twoOver
    );

    assertEquals(
        result.setScale(3, BigDecimal.ROUND_HALF_UP),
        BigDecimal.valueOf(1.000).setScale(3)
    );
  }
}
