# Immunefi Classification Rules Reference

## 1. Chain Rollbacks

**Core Principle:** Chain rollbacks are an extremely heavy-handed emergency measure. If a project must perform a rollback to prevent a hack, the bug is catastrophic enough to merit the **highest Critical payout**.

**Key Rules:**
- Immunefi **strongly recommends** projects do NOT downgrade a bug report's impact, severity, or payout because the bug's impact may be limited by performing a chain rollback.
- If a project intends to use chain rollbacks as a safety mechanism, they must account for this in their bug bounty program by adjusting reward amounts for the severities/impacts they intend to prevent via rollback — they cannot arbitrarily downgrade a report after the fact.
- Chain rollbacks are a **feasibility limitation**, not an impact calculation factor. Impact is calculated independently from feasibility limitations.
- Primacy of Impact (in-scope impact on out-of-scope asset → in-scope) does NOT govern how impact is calculated; impact and feasibility limitations are assessed separately.

**Bottom Line:** A bug requiring a chain rollback to stop = Critical severity, full Critical payout.

---

## 2. Pre-Impact Bug Monitoring

**Core Principle:** Only fully automated tools that prevent exploit with **100% certainty** are valid grounds to downgrade a report by one severity level.

**Key Rules:**

**Auto-block tools (valid downgrade basis):**
- An "auto-block tool" is automated tooling that detects a specific bug exploit **before** its impact is achieved and **fully prevents** it with 100% certainty.
- If a project can objectively prove such a tool would prevent the specific bug exploit with 100% certainty, Immunefi considers this a valid reason to **downgrade the reward by one severity level** (not eliminate it).

**Human action + automated detection (case-by-case):**
- If prevention requires a combination of human action responding to an automated detection tool, Immunefi evaluates on a case-by-case basis.
- To downgrade, the project must provide 100% objective certainty that they would fully prevent the exploit AND objective proof that the automated detection tool would catch the specific exploit with 100% certainty.

**Human detection alone (never valid):**
- Human means of detecting exploits (community members, developers, privileged addresses like Validators noticing unusual activity) are **not** sufficient to downgrade a report.
- If detection cannot be done with 100% certainty, it is an invalid reason to downgrade.

**Bottom Line:** Only fully automated prevention with provable 100% detection rate justifies a one-level severity downgrade. Human monitoring never qualifies.

---

## 3. Attack Investment Amount

**Core Principle:** High cost to execute an attack is generally **not** a valid reason to downgrade a bug report.

**Key Rules:**

**12-month acquisition threshold:**
- If an attacker could acquire the funds needed for the attack over 12 months, the attack is considered **valid and feasible**.
- If it would take longer than 12 months or there are unusual circumstances, Immunefi evaluates case-by-case.

**High investment amounts:**
- Immunefi generally does **not** consider high investment amounts as a valid reason to downgrade. Historical precedent: attackers have successfully deployed millions of USD (e.g., Venus Protocol Hack).

**$100M exception:**
- Attacks requiring **$100 million USD or more** to execute are evaluated on a case-by-case basis as an exception to the general principle.

**Profitability and griefing:**
- If an attack is **not profitable** for the attacker, it may be downgraded to the impact of **Griefing**.
- Financial risk to the attacker is only a valid downgrade reason when the risk **extremely outweighs** the reward.

**Bottom Line:** Cost alone does not justify downgrade. Only unprofitable attacks (where cost far exceeds any gain) can shift severity toward Griefing.

---

## 4. Attacks With A Financial Risk To The Attacker

**Core Principle:** Financial risk to the attacker is only a valid downgrade reason when the risk **extremely outweighs** the reward.

**Key Rules:**

**General standard:**
- The mere existence of financial risk to the attacker does **not** justify downgrading a bug report's severity or payout.
- This is a high bar — "extremely outweighs" means the attacker stands to lose far more than they could ever gain from the exploit.

**Relationship to profitability:**
- If the attack is not profitable (attacker spends more than they gain), the impact may be downgraded to **Griefing** rather than the originally claimed severity.
- This rule works in conjunction with the Attack Investment Amount standards: both unprofitability and extreme financial risk can combine to support a downgrade, but neither alone is typically sufficient unless the imbalance is extreme.

**Not a blanket defense:**
- Projects cannot use "attacker takes on financial risk" as a routine defense to reduce payouts. The standard requires the risk to be objectively extreme relative to any possible reward.
- Immunefi evaluates the attacker's potential indirect profit and second-order damage when making this determination.

**Bottom Line:** Financial risk to attacker justifies downgrade only when extreme and objectively disproportionate to any possible gain. Routine financial risk does not affect severity.

---

## 5. When Is An Impactful Attack Downgraded To Griefing

**Core Principle:** Griefing applies when an attacker can only cause disproportionately small damage relative to their attack cost, and does not profit from the attack.

**Key Rules:**

**Definition of Griefing:**
- An attack is classified as Griefing when the attacker spends resources to damage a protocol but cannot profit from doing so, and the damage-to-cost ratio is low.

**Threshold: Griefing (downgrade applies):**
- Cost-to-damage ratio of **$1 spent → $10 or less in damage**: Attack is classified as Griefing.
- The attacker must also **not profit** from the attack for this classification to apply.

**Threshold: NOT Griefing (downgrade does not apply):**
- Cost-to-damage ratio of **$1 spent → $100 or more in damage**: The attack is sufficiently impactful to motivate a malicious actor; this is **not** Griefing.

**Gray zone (case-by-case):**
- Attacks falling between the $1:$10 and $1:$100 ratios, attacks that do not directly put funds at risk, or attacks not otherwise covered by the thresholds are evaluated case-by-case.
- Immunefi investigates: (a) whether the attacker could **indirectly profit** from the attack, and (b) how serious the **second-order damage** is (e.g., reputation harm, cascading protocol failures).

**DoS attacks:**
- Denial-of-service attacks can be classified as Griefing if they meet the cost-to-damage ratio criteria and the attacker does not profit.

**Bottom Line:**
- $1 cost → ≤$10 damage, no profit = Griefing downgrade.
- $1 cost → ≥$100 damage, no profit = NOT Griefing, original severity holds.
- Between those bounds = case-by-case, considering indirect profit and second-order effects.

---

## Sources

1. [Chain Rollbacks](https://immunefisupport.zendesk.com/hc/en-us/articles/16913153448721-Chain-Rollbacks)
2. [Pre-Impact Bug Monitoring](https://immunefisupport.zendesk.com/hc/en-us/articles/19430444320401-Pre-Impact-Bug-Monitoring)
3. [Attack Investment Amount](https://immunefisupport.zendesk.com/hc/en-us/articles/17243068885265-Attack-Investment-Amount)
4. [Attacks With A Financial Risk To The Attacker](https://immunefisupport.zendesk.com/hc/en-us/articles/17454897136401-Attacks-With-A-Financial-Risk-To-The-Attacker)
5. [When Is An Impactful Attack Downgraded To Griefing?](https://immunefisupport.zendesk.com/hc/en-us/articles/17455102268305-When-Is-An-Impactful-Attack-Downgraded-To-Griefing)
