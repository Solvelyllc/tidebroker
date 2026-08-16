import { describe, expect, it } from "vitest";
import {
  defineServicePrincipalId,
  humanPrincipal,
  servicePrincipal,
  trustedActorFromHostContext,
  type ExecutionPrincipal,
} from "./identity.js";
import {
  defineAccountId,
  defineConnectorId,
  defineCredentialHandle,
  defineWorkspaceId,
  resolveAccountBinding,
  type AccountBinding,
  type BrokerPolicy,
} from "./policy.js";
import { executionContextFromBinding } from "./connector.js";

const company = defineWorkspaceId("company");
const personal = defineWorkspaceId("personal");
const google = defineConnectorId("google");

function actor(value: string): ExecutionPrincipal {
  const result = trustedActorFromHostContext({ requesterSenderId: value });
  if (!result.ok) throw new Error("test actor invalid");
  return humanPrincipal(result.actorId);
}

function binding(
  principal: ExecutionPrincipal,
  workspaceId = company,
  account = "primary",
): AccountBinding {
  return {
    principal,
    workspaceId,
    connectorId: google,
    accountId: defineAccountId(account),
    credentialHandle: defineCredentialHandle(`${account}-handle`),
  };
}

function policy(
  principals: readonly ExecutionPrincipal[],
  bindings: readonly AccountBinding[],
): BrokerPolicy {
  return {
    workspaceAccess: principals.map((principal) => ({
      principal,
      workspaceId: company,
    })),
    accountBindings: bindings,
  };
}

describe("fail-closed account resolution", () => {
  const operatorA = actor("operator-a@example.test");
  const operatorB = actor("operator-b@example.test");

  it("rejects a run with no trusted or explicit principal", () => {
    expect(
      resolveAccountBinding(policy([], []), {
        workspaceId: company,
        connectorId: google,
      }),
    ).toMatchObject({ ok: false, code: "MISSING_PRINCIPAL" });
  });

  it("returns only the requesting actor's exact binding", () => {
    const operatorABinding = binding(operatorA, company, "operator-a-google");
    const operatorBBinding = binding(operatorB, company, "operator-b-google");
    const result = resolveAccountBinding(
      policy([operatorA, operatorB], [operatorABinding, operatorBBinding]),
      { principal: operatorA, workspaceId: company, connectorId: google },
    );

    expect(result).toEqual({ ok: true, binding: operatorABinding });
    expect(result.ok && Object.isFrozen(result.binding)).toBe(true);
    expect(result.ok && Object.isFrozen(result.binding.principal)).toBe(true);
  });

  it("returns an immutable authorization snapshot", () => {
    const mutable = binding(operatorA, company, "original") as {
      -readonly [K in keyof AccountBinding]: AccountBinding[K];
    };
    const result = resolveAccountBinding(policy([operatorA], [mutable]), {
      principal: operatorA,
      workspaceId: company,
      connectorId: google,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    mutable.accountId = defineAccountId("changed");
    expect(result.binding.accountId).toBe(defineAccountId("original"));
  });

  it("derives execution identity from the authorized binding", () => {
    const authorized = binding(operatorA, company, "operator-a-google");
    const context = executionContextFromBinding(authorized);

    expect(context.principal).toEqual(operatorA);
    expect(context.accountId).toBe(authorized.accountId);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.principal)).toBe(true);
  });

  it("does not fall back to another actor's account", () => {
    expect(
      resolveAccountBinding(policy([operatorA, operatorB], [binding(operatorB)]), {
        principal: operatorA,
        workspaceId: company,
        connectorId: google,
      }),
    ).toMatchObject({ ok: false, code: "ACCOUNT_NOT_BOUND" });
  });

  it("denies an actor/workspace mismatch before account lookup", () => {
    const personalBinding = binding(operatorA, personal);
    expect(
      resolveAccountBinding(policy([operatorB], [personalBinding]), {
        principal: operatorA,
        workspaceId: personal,
        connectorId: google,
      }),
    ).toMatchObject({ ok: false, code: "WORKSPACE_ACCESS_DENIED" });
  });

  it("requires service principals to be explicitly allowed and bound", () => {
    const service = servicePrincipal(
      defineServicePrincipalId("solvely-calendar"),
    );
    const serviceBinding = binding(service, company, "company-calendar");

    expect(
      resolveAccountBinding(policy([], [serviceBinding]), {
        principal: service,
        workspaceId: company,
        connectorId: google,
      }),
    ).toMatchObject({ ok: false, code: "WORKSPACE_ACCESS_DENIED" });

    expect(
      resolveAccountBinding(policy([service], [serviceBinding]), {
        principal: service,
        workspaceId: company,
        connectorId: google,
      }),
    ).toEqual({ ok: true, binding: serviceBinding });
  });

  it("never treats a service principal as the human actor with the same id", () => {
    const humanReports = actor("reports");
    const serviceReports = servicePrincipal(defineServicePrincipalId("reports"));

    expect(
      resolveAccountBinding(
        policy([humanReports, serviceReports], [binding(humanReports)]),
        {
          principal: serviceReports,
          workspaceId: company,
          connectorId: google,
        },
      ),
    ).toMatchObject({ ok: false, code: "ACCOUNT_NOT_BOUND" });
  });

  it("does not fall back across connectors", () => {
    expect(
      resolveAccountBinding(policy([operatorA], [binding(operatorA)]), {
        principal: operatorA,
        workspaceId: company,
        connectorId: defineConnectorId("github"),
      }),
    ).toMatchObject({ ok: false, code: "ACCOUNT_NOT_BOUND" });
  });

  it("denies ambiguous duplicate bindings", () => {
    expect(
      resolveAccountBinding(policy([operatorA], [binding(operatorA), binding(operatorA)]), {
        principal: operatorA,
        workspaceId: company,
        connectorId: google,
      }),
    ).toMatchObject({ ok: false, code: "AMBIGUOUS_ACCOUNT_BINDING" });
  });
});
