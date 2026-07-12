#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const failures = [];

function readRepoFile(path) {
  return readFileSync(resolve(repoRoot, path), "utf8");
}

function recordFailure(message) {
  failures.push(message);
}

function requireText(path, requiredText, reason) {
  const text = readRepoFile(path);
  if (!text.includes(requiredText)) {
    recordFailure(`${path}: missing ${reason}`);
  }
}

function rejectText(path, rejectedText, reason) {
  const text = readRepoFile(path);
  if (text.includes(rejectedText)) {
    recordFailure(`${path}: contains stale ${reason}`);
  }
}

function cargoMetadata() {
  const result = spawnSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return JSON.parse(result.stdout);
}

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

function parseVersion(version) {
  const parts = version.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const parsed = parts.map((part) => Number.parseInt(part, 10));
  if (parsed.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    return null;
  }

  return {
    major: parsed[0],
    minor: parsed[1],
    patch: parsed[2],
  };
}

function isCaretReqSatisfied(req, version) {
  if (!req.startsWith("^")) {
    return req === `=${version}` || req === version;
  }

  const minimum = parseVersion(req.slice(1));
  const actual = parseVersion(version);
  if (minimum === null || actual === null) {
    return false;
  }

  if (actual.major !== minimum.major) {
    return false;
  }

  if (minimum.major === 0 && actual.minor !== minimum.minor) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  return actual.minor !== minimum.minor || actual.patch >= minimum.patch;
}

function checkWorkspacePackagePolicy(metadata) {
  const workspacePackageIds = new Set(metadata.workspace_members);
  const workspacePackages = metadata.packages.filter((pkg) => workspacePackageIds.has(pkg.id));
  const publishable = new Map();

  for (const pkg of workspacePackages) {
    const manifestPath = relative(repoRoot, pkg.manifest_path);
    const manifest = readFileSync(pkg.manifest_path, "utf8");

    if (!manifest.includes("[lints]\nworkspace = true")) {
      recordFailure(`${manifestPath}: member crate must inherit workspace lints`);
    }

    if (isPublishablePackage(pkg)) {
      publishable.set(pkg.name, pkg);
      if (!manifest.includes("include = [")) {
        recordFailure(`${manifestPath}: publishable crate must use an include allowlist`);
      }
    }
  }

  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (dep.source !== null || typeof dep.path !== "string") {
        continue;
      }

      const depName = dep.package ?? dep.name;
      const target = publishable.get(depName);
      if (target === undefined) {
        continue;
      }

      if (!isCaretReqSatisfied(dep.req, target.version)) {
        recordFailure(
          `${pkg.name}: stale publishable path dependency ${depName} ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }
}

function checkRepositoryPolicy() {
  requireText("Cargo.toml", 'publish = false', "root package publish=false");
  requireText("Cargo.toml", 'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]', "package include allowlist");
  requireText("Cargo.toml", 'unsafe_code = "deny"', "unsafe_code deny lint");
  requireText("Cargo.toml", 'unwrap_used = "deny"', "unwrap_used deny lint");
  requireText("Cargo.toml", 'expect_used = "deny"', "expect_used deny lint");
  requireText("Cargo.toml", 'panic = "deny"', "panic deny lint");
  requireText("Cargo.toml", 'wildcard_imports = "deny"', "wildcard_imports deny lint");
  requireText("Cargo.toml", 'buffa = { version = "0.8.1"', "Buffa dependency");
  requireText("Cargo.toml", 'connectrpc = { version = "0.8.1"', "Connect dependency");
  requireText("Cargo.toml", 'reallyme-codec = { version = "0.1.1", default-features = false }', "registry ReallyMe codec dependency");
  requireText("Cargo.toml", 'reallyme-crypto = { version = "0.1.6", default-features = false }', "registry ReallyMe crypto dependency");
  rejectText("Cargo.toml", "[patch.crates-io]", "local crates.io patch bridge");
  rejectText("Cargo.toml", 'path = "../crypto"', "local ReallyMe crypto path dependency");
  rejectText("fuzz/Cargo.toml", "[patch.crates-io]", "fuzz local crates.io patch bridge");
  requireText("deny.toml", 'wildcards = "deny"', "cargo-deny wildcard dependency policy");
  requireText("deny.toml", 'unknown-registry = "deny"', "cargo-deny registry policy");
  requireText("deny.toml", 'unknown-git = "deny"', "cargo-deny git policy");
  requireText("README.md", "OpenID4VP 1.0 final", "final-spec positioning");
  requireText("README.md", "conformance/README.md", "conformance runbook link");
  requireText("README.md", "scripts/check-release-readiness.mjs", "release-readiness validation command");
}

function checkDeletedDocumentationIsNotReferenced() {
  const publicFiles = [
    "README.md",
    "COMPLIANCE_MAP.md",
    "THREAT_MODEL.md",
    "PACKAGING.md",
    "conformance/README.md",
    "conformance/reports/agents-style-audit.json",
    "conformance/requirements/eudi-presentation.json",
  ];
  const deletedDocs = [
    "AGENTS.md",
    "IDENTITY_SDK_INTEGRATION.md",
    "JWE_DEPENDENCIES.md",
    "MEPROTO_PORT_AUDIT.md",
    "OPENID4VP_COMPLIANCE_CHECKLIST.md",
    "REFACTOR-BRIEF.md",
    "SDK_INTEGRATION.md",
    "SPEC_MAP.md",
    "TODO.md",
    "llms.txt",
    "openidvp-considerations.md",
  ];

  for (const path of publicFiles) {
    for (const deletedDoc of deletedDocs) {
      rejectText(path, deletedDoc, `deleted documentation reference ${deletedDoc}`);
    }
  }
}

const headerCheckedExtensions = new Set([
  ".md",
  ".mjs",
  ".proto",
  ".py",
  ".rs",
  ".sh",
  ".toml",
  ".yaml",
  ".yml",
]);

const headerCheckedNames = new Set([".gitignore"]);
const skippedDirectories = new Set([
  ".git",
  ".idea",
  ".vscode",
  "target",
  "node_modules",
  "corpus",
  "artifacts",
]);

function extensionOf(path) {
  const lastSlash = path.lastIndexOf("/");
  const fileName = lastSlash === -1 ? path : path.slice(lastSlash + 1);
  const lastDot = fileName.lastIndexOf(".");
  if (lastDot <= 0) {
    return "";
  }

  return fileName.slice(lastDot);
}

function shouldCheckHeader(relativePath) {
  const fileName = relativePath.slice(relativePath.lastIndexOf("/") + 1);
  return headerCheckedNames.has(fileName) || headerCheckedExtensions.has(extensionOf(relativePath));
}

function walkFiles(relativeDir) {
  const absoluteDir = resolve(repoRoot, relativeDir);
  const files = [];
  for (const entry of readdirSync(absoluteDir)) {
    if (skippedDirectories.has(entry)) {
      continue;
    }

    const relativePath = relativeDir === "" ? entry : `${relativeDir}/${entry}`;
    const absolutePath = resolve(repoRoot, relativePath);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) {
      files.push(...walkFiles(relativePath));
      continue;
    }

    if (stat.isFile()) {
      files.push(relativePath);
    }
  }

  return files;
}

function checkSpdxHeaders() {
  for (const path of walkFiles("")) {
    if (!shouldCheckHeader(path)) {
      continue;
    }

    const text = readRepoFile(path);
    if (!text.includes("SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved")) {
      recordFailure(`${path}: missing ReallyMe SPDX copyright header`);
    }
    if (!text.includes("SPDX-License-Identifier: Apache-2.0")) {
      recordFailure(`${path}: missing Apache-2.0 SPDX license header`);
    }
  }
}

const metadata = cargoMetadata();
checkRepositoryPolicy();
checkWorkspacePackagePolicy(metadata);
checkDeletedDocumentationIsNotReferenced();
checkSpdxHeaders();

if (failures.length !== 0) {
  console.error("release readiness checks failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("release readiness checks passed");
