import { describe, expect, it } from "vitest";
import { parseDockerfile, parseDockerfileSkill } from "../src/parseDockerfile.js";
import { skills } from "../src/index.js";

async function runDockerfile(input: string) {
  return await parseDockerfileSkill.run(input);
}

describe("parse_dockerfile", () => {
  it("exports the parser skill with local-only permissions", () => {
    expect(skills.map((skill) => skill.metadata.name)).toContain("parse_dockerfile");
    expect(parseDockerfileSkill.metadata).toMatchObject({
      name: "parse_dockerfile",
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

  it("parses a multi-stage Dockerfile into stage and instruction observations", async () => {
    const output = await runDockerfile([
      "# syntax=docker/dockerfile:1",
      "FROM node:22-alpine AS build",
      "WORKDIR /app",
      "COPY package.json pnpm-lock.yaml ./",
      "RUN corepack enable && pnpm install --frozen-lockfile",
      "COPY . .",
      "RUN pnpm build",
      "FROM nginx:1.27-alpine",
      "COPY --from=build /app/dist /usr/share/nginx/html",
      "EXPOSE 8080/tcp",
      "USER nginx",
      "HEALTHCHECK CMD wget -qO- http://localhost:8080/health || exit 1",
      'CMD ["nginx", "-g", "daemon off;"]',
    ].join("\n"));

    expect(output.artifact).toEqual({ id: "artifact_dockerfile", type: "dockerfile" });
    expect(output.observed.parser_directives).toEqual([
      { line: 1, name: "syntax", value: "docker/dockerfile:1" },
    ]);
    expect(output.observed.stage_count).toBe(2);
    expect(output.observed.final_stage_index).toBe(1);
    expect(output.observed.stages).toEqual([
      {
        index: 0,
        line: 2,
        base_image: "node:22-alpine",
        image: "node",
        tag: "22-alpine",
        digest: null,
        alias: "build",
        platform: null,
        uses_tag: true,
        uses_digest: false,
      },
      {
        index: 1,
        line: 8,
        base_image: "nginx:1.27-alpine",
        image: "nginx",
        tag: "1.27-alpine",
        digest: null,
        alias: null,
        platform: null,
        uses_tag: true,
        uses_digest: false,
      },
    ]);
    expect(output.observed.instruction_counts).toMatchObject({
      CMD: 1,
      COPY: 3,
      EXPOSE: 1,
      FROM: 2,
      HEALTHCHECK: 1,
      RUN: 2,
      USER: 1,
      WORKDIR: 1,
    });
    expect(output.observed.exposed_ports).toEqual(["8080/tcp"]);
    expect(output.observed.declared_users).toEqual(["nginx"]);
    expect(output.observed.final_user).toBe("nginx");
    expect(output.observed.workdirs).toEqual(["/app"]);
    expect(output.observed.healthcheck_present).toBe(true);
    expect(output.observed.healthcheck_disabled).toBe(false);
    expect(output.observed.cmd_present).toBe(true);
    expect(output.observed.command_forms.run).toEqual({ shell_form_count: 2, json_array_form_count: 0 });
    expect(output.observed.command_forms.cmd).toEqual({ shell_form_count: 0, json_array_form_count: 1 });
    expect(output.observed.copied_paths).toHaveLength(3);
    expect(output.observed.copied_paths[2]).toMatchObject({
      line: 9,
      instruction: "COPY",
      sources: ["/app/dist"],
      destination: "/usr/share/nginx/html",
      flags: ["--from=build"],
      json_array_form: false,
    });
    expect(output.warnings).toEqual([]);
  });

  it("observes image digest, platform, and missing tag separately", async () => {
    const output = await runDockerfile("FROM --platform=linux/amd64 registry.example.com:5000/app@sha256:abc123 AS final");

    expect(output.observed.stages).toEqual([
      {
        index: 0,
        line: 1,
        base_image: "registry.example.com:5000/app@sha256:abc123",
        image: "registry.example.com:5000/app",
        tag: null,
        digest: "sha256:abc123",
        alias: "final",
        platform: "linux/amd64",
        uses_tag: false,
        uses_digest: true,
      },
    ]);
  });

  it("redacts sensitive-looking ENV and ARG values while preserving keys", async () => {
    const output = await runDockerfile([
      "ARG API_TOKEN=example-token",
      "FROM node:22-alpine",
      "ENV NODE_ENV=production API_KEY=example-key",
      "ENV PASSWORD example-password",
      "ARG BUILD_MODE=release",
    ].join("\n"));

    expect(output.observed.arg_keys).toEqual(["API_TOKEN", "BUILD_MODE"]);
    expect(output.observed.env_keys).toEqual(["API_KEY", "NODE_ENV", "PASSWORD"]);
    expect(output.observed.args).toEqual([
      { line: 1, key: "API_TOKEN", value_present: true, value_redacted: true },
      { line: 5, key: "BUILD_MODE", value_present: true, value_redacted: false, value: "release" },
    ]);
    expect(output.observed.env).toEqual([
      { line: 3, key: "NODE_ENV", value_present: true, value_redacted: false, value: "production" },
      { line: 3, key: "API_KEY", value_present: true, value_redacted: true },
      { line: 4, key: "PASSWORD", value_present: true, value_redacted: true },
    ]);
    expect(output.observed.instructions.map((instruction) => instruction.value)).toContain(
      "NODE_ENV=production API_KEY=[REDACTED]"
    );
    expect(output.observed.instructions.map((instruction) => instruction.value)).toContain(
      "PASSWORD [REDACTED]"
    );
  });

  it("parses ADD and COPY operands, flags, URL-like ADD sources, and JSON-array path form", async () => {
    const output = await runDockerfile([
      "FROM scratch",
      "ADD https://downloads.example.com/archive.tar.gz /tmp/archive.tar.gz",
      'COPY ["dist/app", "/opt/app"]',
      "COPY --chown=1000:1000 config/app.conf /etc/app.conf",
    ].join("\n"));

    expect(output.observed.added_paths).toEqual([
      {
        line: 2,
        instruction: "ADD",
        sources: ["https://downloads.example.com/archive.tar.gz"],
        destination: "/tmp/archive.tar.gz",
        flags: [],
        json_array_form: false,
        url_like_source_count: 1,
      },
    ]);
    expect(output.observed.add_url_like_sources).toEqual([
      "https://downloads.example.com/archive.tar.gz",
    ]);
    expect(output.observed.copied_paths).toEqual([
      {
        line: 3,
        instruction: "COPY",
        sources: ["dist/app"],
        destination: "/opt/app",
        flags: [],
        json_array_form: true,
        url_like_source_count: 0,
      },
      {
        line: 4,
        instruction: "COPY",
        sources: ["config/app.conf"],
        destination: "/etc/app.conf",
        flags: ["--chown=1000:1000"],
        json_array_form: false,
        url_like_source_count: 0,
      },
    ]);
  });

  it("combines continued physical lines into one logical instruction", async () => {
    const output = await runDockerfile([
      "FROM alpine:3.20",
      "RUN apk add --no-cache \\",
      "    ca-certificates \\",
      "    curl",
    ].join("\n"));

    const runInstruction = output.observed.instructions.find((instruction) => instruction.instruction === "RUN");
    expect(runInstruction).toMatchObject({
      line: 2,
      end_line: 4,
      instruction: "RUN",
      stage_index: 0,
    });
    expect(runInstruction?.value).toBe("apk add --no-cache ca-certificates curl");
    expect(output.observed.logical_instruction_count).toBe(2);
  });

  it("preserves unknown instructions and malformed instruction warnings", async () => {
    const output = await runDockerfile([
      "FROM alpine:3.20",
      "BOGUS value",
      "123-not-an-instruction",
    ].join("\n"));

    expect(output.observed.unknown_instructions).toEqual([
      {
        line: 2,
        end_line: 2,
        instruction: "BOGUS",
        known_instruction: false,
        value: "value",
        value_redacted: false,
        stage_index: 0,
      },
    ]);
    expect(output.warnings).toEqual([
      "Dockerfile line 2 uses unmodeled instruction BOGUS.",
      "Dockerfile line 3 does not start with a valid instruction name.",
    ]);
  });

  it("reports mixed line endings and missing FROM without rejecting otherwise valid input", () => {
    const output = parseDockerfile("ARG NAME=value\r\nENV NODE_ENV=production\n");

    expect(output.observed.line_ending).toBe("mixed");
    expect(output.observed.stage_count).toBe(0);
    expect(output.warnings).toContain("Dockerfile input contains no FROM instruction.");
    expect(output.warnings).toContain("Dockerfile input contains mixed line endings.");
  });

  it("rejects empty input", () => {
    expect(() => parseDockerfile("")).toThrow("parse_dockerfile input must not be empty");
  });

  it("rejects input with no valid Dockerfile instructions", () => {
    expect(() => parseDockerfile("# comment only\n\n# syntax=docker/dockerfile:1")).toThrow(
      "parse_dockerfile input did not contain any valid Dockerfile instructions"
    );
  });

  it("rejects non-string input", () => {
    expect(() => parseDockerfileSkill.run(123 as unknown as string)).toThrow(
      "parse_dockerfile input must be a string"
    );
  });
});
