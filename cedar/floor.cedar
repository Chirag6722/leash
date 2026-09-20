// The floor, as one policy set: everything the leash may EVER allow, under any policy version.
//
// This file is not enforced. It is the specification the enforced policies are proved against:
// verify/ asks the Cedar symbolic compiler (cedar-policy-symcc) and the cvc5 SMT solver whether
// every request the enforced policies allow is also allowed here, for EVERY possible request in
// every request environment the schema admits, not for a sample of them. If any request escapes,
// the solver returns it as a counterexample and the check fails.
//
// Read it as the promises in the README: only the three remediation actions, never on prod,
// never on a resource without an env tag, and never a scale as far as 10. Terminate and delete
// have no permit here at all, so any policy version that allowed them would fail the proof.

@id("FloorRemediation")
permit (
    principal,
    action in [Leash::Action::"cleanDisk", Leash::Action::"restartService"],
    resource
) when { resource.env != "prod" && resource.env != "unknown" };

@id("FloorScale")
permit (
    principal,
    action == Leash::Action::"scaleGroup",
    resource
) when { resource.env != "prod" && resource.env != "unknown" && context.desiredCapacity < 10 };
