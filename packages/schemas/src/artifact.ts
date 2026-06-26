import type { JsonObject, SensitivityLevel } from "./json.js";

export const artifactKinds = [
  "text",
  "json",
  "csv",
  "yaml",
  "xml",
  "url",
  "jwt",
  "email_headers",
  "package_json",
  "browser_extension_manifest",
  "pem_certificate",
  "sbom",
  "lockfile",
  "unknown",
] as const;

export type ArtifactKind = (typeof artifactKinds)[number];

export const artifactSources = ["inline", "file", "derived", "pipeline", "unknown"] as const;
export type ArtifactSource = (typeof artifactSources)[number];

export interface ArtifactSummary {
  readonly id: string;
  readonly type: ArtifactKind | string;
  readonly source?: ArtifactSource;
  readonly name?: string;
  readonly mime_type?: string;
  readonly encoding?: string;
  readonly size_bytes?: number;
  readonly sha256?: string;
  readonly sensitivity?: SensitivityLevel;
  readonly labels?: readonly string[];
  readonly metadata?: JsonObject;
}

export function isArtifactKind(value: unknown): value is ArtifactKind {
  return typeof value === "string" && artifactKinds.includes(value as ArtifactKind);
}

export function isArtifactSource(value: unknown): value is ArtifactSource {
  return typeof value === "string" && artifactSources.includes(value as ArtifactSource);
}
