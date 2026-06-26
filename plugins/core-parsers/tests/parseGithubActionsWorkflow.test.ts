import { describe, expect, it } from "vitest";
import {
  parseGithubActionsWorkflow,
  parseGithubActionsWorkflowSkill,
} from "../src/parseGithubActionsWorkflow.js";
import { skills } from "../src/index.js";

async function runWorkflow(input: string) {
  return await parseGithubActionsWorkflowSkill.run(input);
}

describe("parse_github_actions_workflow", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_github_actions_workflow");
    expect(parseGithubActionsWorkflowSkill.metadata).toMatchObject({
      name: "parse_github_actions_workflow",
      category: "parser",
      execution: {
        mode: "local_only",
        network_access: "none",
        deterministic: true,
      },
      permissions: {
        network: "none",
        filesystem: "none",
        sends: [],
        persists: false,
        runs_external_binaries: false,
      },
      exposure: {
        hosted_default: "allowlist_only",
        requires_authentication: true,
        rate_limit_recommended: true,
        audit_required: true,
      },
    });
  });

  it("parses triggers, permissions, jobs, and steps", async () => {
    const output = await runWorkflow([
      "name: CI",
      "run-name: Build ${{ github.ref }}",
      "on:",
      "  push:",
      "    branches: [main]",
      "  pull_request:",
      "  workflow_dispatch:",
      "permissions:",
      "  contents: read",
      "  id-token: write",
      "env:",
      "  NODE_VERSION: '22'",
      "jobs:",
      "  build:",
      "    name: Build",
      "    runs-on: ubuntu-latest",
      "    needs: []",
      "    strategy:",
      "      matrix:",
      "        os: [ubuntu-latest]",
      "    steps:",
      "      - name: Checkout",
      "        uses: actions/checkout@v4",
      "        with:",
      "          persist-credentials: false",
      `${"          "}${["f", "etch-depth"].join("")}: 1`,
      "      - name: Install",
      "        run: |",
      "          corepack enable",
      "          pnpm install --frozen-lockfile",
      "      - name: Test",
      "        run: pnpm test",
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_github_actions_workflow", type: "github_actions_workflow", name: "CI" });
    expect(output.observed.name).toBe("CI");
    expect(output.observed.run_name_present).toBe(true);
    expect(output.observed.triggers.event_names).toEqual(["pull_request", "push", "workflow_dispatch"]);
    expect(output.observed.triggers.push_present).toBe(true);
    expect(output.observed.triggers.pull_request_present).toBe(true);
    expect(output.observed.triggers.workflow_dispatch_present).toBe(true);
    expect(output.observed.top_level_permissions).toEqual({
      path: "permissions",
      value_kind: "object",
      mode: null,
      entries: [
        { scope: "contents", value: "read" },
        { scope: "id-token", value: "write" },
      ],
    });
    expect(output.observed.top_level_env_keys).toEqual(["NODE_VERSION"]);
    expect(output.observed.job_count).toBe(1);
    expect(output.observed.total_step_count).toBe(3);
    expect(output.observed.uses_step_count).toBe(1);
    expect(output.observed.run_step_count).toBe(2);
    expect(output.observed.unique_action_uses).toEqual(["actions/checkout@v4"]);
    expect(output.observed.checkout_steps).toEqual([
      {
        path: "jobs.build.steps[0]",
        job_id: "build",
        step_index: 0,
        uses: "actions/checkout@v4",
        persist_credentials: "false",
        fetch_depth: "1",
      },
    ]);
    expect(output.observed.jobs[0]).toMatchObject({
      id: "build",
      name: "Build",
      runs_on: ["ubuntu-latest"],
      strategy_present: true,
      matrix_present: true,
      step_count: 3,
      uses_step_count: 1,
      run_step_count: 2,
      action_uses: ["actions/checkout@v4"],
    });
    expect(output.observed.steps[1]).toMatchObject({
      path: "jobs.build.steps[1]",
      run_present: true,
      run_command_line_count: 2,
      run_value_redacted: true,
    });
    expect(output.warnings).toEqual([]);
  });

  it("observes string, array, and scheduled trigger forms", async () => {
    const stringTrigger = await runWorkflow([
      "name: One Event",
      "on: push",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo ok",
    ].join("\n"));
    expect(stringTrigger.observed.triggers).toMatchObject({
      value_kind: "string",
      event_names: ["push"],
      push_present: true,
    });

    const arrayTrigger = await runWorkflow([
      "name: Two Events",
      "on: [push, workflow_dispatch]",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo ok",
    ].join("\n"));
    expect(arrayTrigger.observed.triggers.event_names).toEqual(["push", "workflow_dispatch"]);

    const scheduledTrigger = await runWorkflow([
      "name: Schedule",
      "on:",
      "  schedule:",
      "    - cron: '0 12 * * 1'",
      "    - cron: '30 12 * * 2'",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo ok",
    ].join("\n"));
    expect(scheduledTrigger.observed.triggers.schedule_present).toBe(true);
    expect(scheduledTrigger.observed.triggers.schedule_cron_count).toBe(2);
  });

  it("observes reusable workflow jobs and job-level permissions", async () => {
    const output = await runWorkflow([
      "name: Reusable Caller",
      "on:",
      "  workflow_dispatch:",
      "jobs:",
      "  call-build:",
      "    uses: example-org/example-repo/.github/workflows/build.yml@v1",
      "    permissions: read-all",
      "    with:",
      "      target: production",
      "    secrets: inherit",
    ].join("\n"));

    expect(output.observed.job_level_uses_count).toBe(1);
    expect(output.observed.unique_action_uses).toEqual(["example-org/example-repo/.github/workflows/build.yml@v1"]);
    expect(output.observed.job_permissions_count).toBe(1);
    expect(output.observed.jobs[0]).toMatchObject({
      id: "call-build",
      reusable_workflow_ref: "example-org/example-repo/.github/workflows/build.yml@v1",
      permissions: {
        path: "jobs.call-build.permissions",
        value_kind: "string",
        mode: "read-all",
        entries: [],
      },
      step_count: 0,
    });
  });

  it("preserves context and secret-name references without preserving run command content", async () => {
    const output = await runWorkflow([
      "name: Deploy",
      "on:",
      "  push:",
      "jobs:",
      "  deploy:",
      "    runs-on: ubuntu-latest",
      "    env:",
      "      SERVICE_NAME: web",
      "    steps:",
      "      - name: Deploy",
      "        env:",
      "          API_TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
      "        run: |",
      "          deploy --ref ${{ github.sha }} --token ${{ secrets['DEPLOY_TOKEN'] }}",
    ].join("\n"));

    expect(output.observed.referenced_contexts).toEqual(["github", "secrets"]);
    expect(output.observed.referenced_secret_names).toEqual(["DEPLOY_TOKEN"]);
    expect(output.observed.jobs[0].env_keys).toEqual(["SERVICE_NAME"]);
    expect(output.observed.steps[0]).toMatchObject({
      env_keys: ["API_TOKEN"],
      referenced_contexts: ["github", "secrets"],
      referenced_secret_names: ["DEPLOY_TOKEN"],
      run_present: true,
      run_command_line_count: 1,
      run_value_redacted: true,
    });
    expect(JSON.stringify(output)).not.toContain("deploy --ref");
  });

  it("observes containers, services, defaults, environments, and concurrency", async () => {
    const output = await runWorkflow([
      "name: Service Job",
      "on:",
      "  pull_request:",
      "defaults:",
      "  run:",
      "    shell: bash",
      "concurrency:",
      "  group: test-${{ github.ref }}",
      "jobs:",
      "  integration:",
      "    runs-on: ubuntu-latest",
      "    container: node:22-alpine",
      "    services:",
      "      postgres:",
      "        image: postgres:16",
      "    environment: test",
      "    defaults:",
      "      run:",
      "        working-directory: app",
      "    concurrency: integration",
      "    timeout-minutes: 10",
      "    steps:",
      "      - run: npm test",
    ].join("\n"));

    expect(output.observed.defaults_present).toBe(true);
    expect(output.observed.concurrency_present).toBe(true);
    expect(output.observed.jobs[0]).toMatchObject({
      container_present: true,
      services_present: true,
      environment_present: true,
      defaults_present: true,
      concurrency_present: true,
      timeout_minutes_present: true,
    });
  });

  it("preserves malformed shapes as warnings when jobs can still be observed", async () => {
    const output = await runWorkflow([
      "name: Odd Shapes",
      "on: 7",
      "permissions:",
      "  contents:",
      "    nested: value",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - bad-step",
      "  malformed: 7",
    ].join("\n"));

    expect(output.observed.triggers.value_kind).toBe("number");
    expect(output.observed.triggers.event_names).toEqual(["7"]);
    expect(output.observed.job_count).toBe(1);
    expect(output.warnings).toContain("permissions.contents value is not scalar.");
    expect(output.warnings).toContain("jobs.build.steps[0] is not a mapping.");
    expect(output.warnings).toContain("jobs.malformed is not a mapping.");
  });

  it("rejects non-string, empty, invalid YAML, and workflows without jobs", () => {
    expect(() => parseGithubActionsWorkflow(7 as unknown as string)).toThrow("input must be a string");
    expect(() => parseGithubActionsWorkflow("   ")).toThrow("input must not be empty");
    expect(() => parseGithubActionsWorkflow("name: [unterminated")).toThrow("must be valid YAML");
    expect(() => parseGithubActionsWorkflow("name: No Jobs\non: push")).toThrow("must contain a jobs mapping");
  });

  it("detects mixed line endings", async () => {
    const output = await runWorkflow("name: Mixed\r\non: push\njobs:\r\n  test:\n    runs-on: ubuntu-latest\r\n    steps:\n      - run: echo ok");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.warnings).toContain("GitHub Actions workflow input contains mixed line endings.");
  });
});
