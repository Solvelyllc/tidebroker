import { describe, expect, it } from "vitest";
import {
  defineServicePrincipalId,
  humanPrincipal,
  principalKey,
  servicePrincipal,
  trustedActorFromHostContext,
} from "./identity.js";

describe("trusted actor identity", () => {
  it("preserves and namespaces an identity asserted by host context", () => {
    const result = trustedActorFromHostContext({
      requesterSenderId: "  OperatorA@Example.Test  ",
      messageChannel: "webchat",
      agentAccountId: "primary",
    });

    expect(result).toEqual({
      ok: true,
      actorId: '["webchat","primary","OperatorA@Example.Test"]',
    });
  });

  it.each([undefined, null, {}, { requesterSenderId: "   " }])(
    "rejects missing host identity: %j",
    (context) => {
      expect(trustedActorFromHostContext(context)).toMatchObject({
        ok: false,
        code: "MISSING_TRUSTED_ACTOR",
      });
    },
  );

  it("rejects unsafe identity syntax", () => {
    expect(
      trustedActorFromHostContext({ requesterSenderId: "operator-a\nadmin" }),
    ).toMatchObject({ ok: false, code: "INVALID_TRUSTED_ACTOR" });
  });

  it("does not collide identical sender ids across channels or accounts", () => {
    const web = trustedActorFromHostContext({
      requesterSenderId: "123",
      messageChannel: "webchat",
      agentAccountId: "company",
    });
    const slack = trustedActorFromHostContext({
      requesterSenderId: "123",
      messageChannel: "slack",
      agentAccountId: "company",
    });
    const otherAccount = trustedActorFromHostContext({
      requesterSenderId: "123",
      messageChannel: "webchat",
      agentAccountId: "personal",
    });
    expect(web.ok).toBe(true);
    expect(slack.ok).toBe(true);
    expect(otherAccount.ok).toBe(true);
    if (!web.ok || !slack.ok || !otherAccount.ok) return;
    expect(web.actorId).not.toBe(slack.actorId);
    expect(web.actorId).not.toBe(otherAccount.actorId);
  });

  it("does not merge case-sensitive provider subjects", () => {
    const upper = trustedActorFromHostContext({ requesterSenderId: "UserA" });
    const lower = trustedActorFromHostContext({ requesterSenderId: "usera" });
    expect(upper.ok).toBe(true);
    expect(lower.ok).toBe(true);
    if (!upper.ok || !lower.ok) return;
    expect(upper.actorId).not.toBe(lower.actorId);
  });

  it("keeps human and service principal namespaces distinct", () => {
    const actor = trustedActorFromHostContext({ requesterSenderId: "reports" });
    expect(actor.ok).toBe(true);
    if (!actor.ok) return;

    expect(principalKey(humanPrincipal(actor.actorId))).toBe(
      'human:[null,null,"reports"]',
    );
    expect(
      principalKey(servicePrincipal(defineServicePrincipalId("reports"))),
    ).toBe("service:reports");
  });
});
