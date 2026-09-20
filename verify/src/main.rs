//! leash-prove: the floor, proved for every possible request.
//!
//! The Python floor (src/common/floor.py) samples ten concrete requests. This program asks the
//! Cedar symbolic compiler and the cvc5 SMT solver a stronger question: for EVERY request the
//! schema admits (every principal, action, resource, env string, capacity value), is every
//! request the enforced policies ALLOW also allowed by cedar/floor.cedar? That is policy-set
//! implication (leash ⊆ floor), decided exactly, not tested.
//!
//! Usage: leash-prove <cedar dir> [--json]
//!   <cedar dir> holds schema.json, floor.cedar and policies/*.cedar (the repo's cedar/, or a
//!   directory synced from the policy bucket). Exit 0 when the floor holds, 1 with the first
//!   counterexample request per environment when it does not, 2 on a setup error.
//! Needs CVC5=<path to cvc5 1.3.1> in the environment (scripts/prove-floor.sh sets it).

use std::{env, fs, path::Path, process::exit, str::FromStr};

use anyhow::{anyhow, Context, Result};
use cedar_policy::{Authorizer, Decision, PolicySet, Schema};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler, SymEnv, WellTypedPolicies};

fn read_policy_set(dir: &Path) -> Result<PolicySet> {
    let mut text = String::new();
    let mut names = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir.join("policies"))
        .with_context(|| format!("reading {}", dir.join("policies").display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "cedar").unwrap_or(false))
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_stem().unwrap().to_string_lossy().to_string();
        let body = fs::read_to_string(&p)?;
        // strip any @id the file already carries, then give it the file's name
        let body = body.lines().filter(|l| !l.trim_start().starts_with("@id(")).collect::<Vec<_>>().join("\n");
        text.push_str(&format!("@id(\"{}\")\n{}\n", name, body));
        names.push(name);
    }
    eprintln!("enforced policies: {}", names.join(", "));
    PolicySet::from_str(&text).map_err(|e| anyhow!("parsing enforced policies: {e}"))
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(true) => exit(0),
        Ok(false) => exit(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            exit(2)
        }
    }
}

async fn run() -> Result<bool> {
    let args: Vec<String> = env::args().collect();
    let dir = Path::new(args.get(1).map(String::as_str).unwrap_or("cedar"));
    let json_out = args.iter().any(|a| a == "--json");

    let schema_text = fs::read_to_string(dir.join("schema.json")).with_context(|| "reading schema.json")?;
    let schema = Schema::from_json_str(&schema_text).map_err(|e| anyhow!("parsing schema: {e}"))?;
    let floor = PolicySet::from_str(&fs::read_to_string(dir.join("floor.cedar")).with_context(|| "reading floor.cedar")?)
        .map_err(|e| anyhow!("parsing floor.cedar: {e}"))?;
    let leash = read_policy_set(dir)?;

    let cvc5 = LocalSolver::cvc5().map_err(|e| anyhow!("starting cvc5 (set CVC5=<path to cvc5 1.3.1>): {e}"))?;
    let mut compiler = CedarSymCompiler::new(cvc5).map_err(|e| anyhow!("symbolic compiler: {e}"))?;

    let mut envs = 0usize;
    let mut failures = Vec::new();
    let mut report = Vec::new();
    for req_env in schema.request_envs() {
        envs += 1;
        let label = format!("{} / {} / {}", req_env.principal(), req_env.action(), req_env.resource());
        let sym_env = SymEnv::new(&schema, &req_env).map_err(|e| anyhow!("{label}: symbolic env: {e}"))?;
        let typed_leash = WellTypedPolicies::from_policies(&leash, &req_env, &schema)
            .map_err(|e| anyhow!("{label}: enforced policies do not type-check: {e}"))?;
        let typed_floor = WellTypedPolicies::from_policies(&floor, &req_env, &schema)
            .map_err(|e| anyhow!("{label}: floor does not type-check: {e}"))?;

        // leash ⊆ floor: every request the leash allows, the floor allows. Exact, over all requests.
        let cex = compiler
            .check_implies_with_counterexample(&typed_leash, &typed_floor, &sym_env)
            .await
            .map_err(|e| anyhow!("{label}: solver: {e}"))?;

        // Sanity: also record whether the leash can allow anything at all in this environment,
        // so the report distinguishes "proved safe because nothing is ever allowed here"
        // (terminate, delete) from "proved safe within the envelope" (the remediation actions).
        let always_denies = compiler
            .check_always_denies(&typed_leash, &sym_env)
            .await
            .map_err(|e| anyhow!("{label}: solver: {e}"))?;

        match cex {
            None => {
                eprintln!("proved  {label}  ({})", if always_denies { "never allows anything" } else { "allows only inside the floor" });
                report.push(serde_json::json!({"env": label, "holds": true, "always_denies": always_denies}));
            }
            Some(cex) => {
                // Confirm the counterexample with the concrete authorizer: the leash allows it,
                // the floor does not. (Belt and braces on the symbolic result.)
                let auth = Authorizer::new();
                let leash_says = auth.is_authorized(&cex.request, &leash, &cex.entities).decision();
                let floor_says = auth.is_authorized(&cex.request, &floor, &cex.entities).decision();
                eprintln!("ESCAPE  {label}");
                eprintln!("        request:  {}", cex.request);
                eprintln!("        leash says {:?}, floor says {:?}", leash_says, floor_says);
                failures.push(label.clone());
                report.push(serde_json::json!({
                    "env": label, "holds": false,
                    "counterexample": cex.request.to_string(),
                    "confirmed": leash_says == Decision::Allow && floor_says == Decision::Deny,
                }));
            }
        }
    }

    let holds = failures.is_empty();
    if json_out {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "holds": holds, "environments": envs, "escapes": failures.len(), "results": report,
        }))?);
    }
    eprintln!(
        "\n{}: {} request environments, {} escape(s). {}",
        if holds { "FLOOR HOLDS" } else { "FLOOR BROKEN" },
        envs,
        failures.len(),
        if holds { "Every request the leash can ever allow is inside the floor." } else { "The requests above are allowed by the enforced policies and forbidden by the floor." }
    );
    Ok(holds)
}
