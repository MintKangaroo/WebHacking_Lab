import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:8080";
const screenshotDirectory = resolve("../docs/screenshots");
await mkdir(screenshotDirectory, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
const suffix = Date.now();
const projectName = `Authorized CTF Review ${suffix}`;

const projectResponse = await page.request.post(`${baseURL}/api/projects`, {
  data: {
    name: projectName,
    description: "Explicitly authorized CTF target with bounded read-only validation.",
    mode: "ctf",
  },
});
if (!projectResponse.ok()) throw new Error(await projectResponse.text());
const project = await projectResponse.json();
const workspace = project.workspaces[0];

const scopeResponse = await page.request.post(
  `${baseURL}/api/projects/${project.id}/scope`,
  {
    data: {
      scheme: "https",
      hostname: "ctf.example",
      port: 443,
      path_prefix: "/challenge",
      allow_subdomains: false,
      max_requests_per_minute: 5,
      max_concurrency: 1,
      authorization_confirmed: true,
      authorization_notes: "Competition organizer authorized this exact CTF challenge scope.",
    },
  },
);
if (!scopeResponse.ok()) throw new Error(await scopeResponse.text());

const enableResponse = await page.request.post(
  `${baseURL}/api/workspaces/${workspace.id}/execution/enable`,
  {
    data: {
      authorization_confirmed: true,
      confirmation_phrase: "ENABLE CONTROLLED REQUESTS",
      expected_use: "Read-only review of the registered CTF challenge endpoint.",
      version: workspace.version,
    },
  },
);
if (!enableResponse.ok()) throw new Error(await enableResponse.text());

const scannerScopeResponse = await page.request.post(
  `${baseURL}/api/projects/${project.id}/scope`,
  {
    data: {
      scheme: "http",
      hostname: "backend",
      port: 8000,
      path_prefix: "/api",
      allow_subdomains: false,
      max_requests_per_minute: 10,
      max_concurrency: 1,
      authorization_confirmed: true,
      authorization_notes: "Screenshot scan is limited to this Compose application's health API.",
    },
  },
);
if (!scannerScopeResponse.ok()) throw new Error(await scannerScopeResponse.text());

const scanResponse = await page.request.post(`${baseURL}/api/scans`, {
  data: {
    project_id: project.id,
    workspace_id: workspace.id,
    target: "http://backend:8000/api/health?probe=1&next=%2Fapi%2Fhealth",
    profile: "safe",
    crawl_policy: {
      max_depth: 1,
      max_pages: 1,
      max_requests: 1,
      max_response_bytes: 2000000,
      requests_per_second: 5,
      concurrency: 1,
      include_subdomains: false,
      respect_logout_routes: true,
      execute_javascript: false,
    },
    active_test_policy: {
      enabled: true,
      max_tests: 6,
      max_tests_per_parameter: 6,
      allow_limited_timing: false,
    },
    authorization_confirmed: true,
    confirmation_phrase: "START SAFE SCAN",
    expected_use: "Local screenshot of exact-request SAFE planning and approval.",
  },
});
if (!scanResponse.ok()) throw new Error(await scanResponse.text());
const scan = await scanResponse.json();
let plannedTestsCount = 0;
for (let attempt = 0; attempt < 40; attempt += 1) {
  const statusResponse = await page.request.get(`${baseURL}/api/scans/${scan.id}`);
  if (!statusResponse.ok()) throw new Error(await statusResponse.text());
  const scanStatus = await statusResponse.json();
  if (["waiting_for_approval", "completed", "cancelled", "failed", "blocked"].includes(scanStatus.status)) {
    plannedTestsCount = scanStatus.planned_tests_count;
    break;
  }
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
}

const codeProjectResponse = await page.request.post(`${baseURL}/api/code-projects`, {
  data: {
    project_id: project.id,
    name: "Flask Storefront Source",
    description: "Authorized CTF source reviewed without execution.",
    authorization_confirmed: true,
    authorization_notes: "Competition organizer authorized this exact source review.",
    confirmation_phrase: "UPLOAD INERT SOURCE",
  },
});
if (!codeProjectResponse.ok()) throw new Error(await codeProjectResponse.text());
const codeProject = await codeProjectResponse.json();
const source = `from flask import Flask, request

app = Flask(__name__)
API_KEY = "screenshot-demo-secret"

@app.route("/product/<int:item_id>", methods=["GET"])
@login_required
def product(item_id):
    query = request.args.get("q")
    return {"item_id": item_id, "query": query}
`;
const codeUploadResponse = await page.request.post(`${baseURL}/api/code-projects/upload`, {
  multipart: {
    code_project_id: codeProject.id,
    files: {
      name: "app.py",
      mimeType: "text/x-python",
      buffer: Buffer.from(source),
    },
  },
});
if (!codeUploadResponse.ok()) throw new Error(await codeUploadResponse.text());
const codeAnalysisResponse = await page.request.post(
  `${baseURL}/api/code-projects/${codeProject.id}/analyze`,
);
if (!codeAnalysisResponse.ok()) throw new Error(await codeAnalysisResponse.text());

await page.goto(`${baseURL}/`);
await page.getByRole("heading", { name: "Security analysis, under control." }).waitFor();
await page.screenshot({ path: resolve(screenshotDirectory, "dashboard.png"), fullPage: true });

await page.goto(`${baseURL}/code-analysis`);
await page.getByLabel("Parent project").selectOption({ label: projectName });
await page.getByLabel("Code project").selectOption({ label: "Flask Storefront Source" });
await page.getByText("app.py").first().waitFor();
await page.getByText("/product/<int:item_id>").waitFor();
await page.getByRole("button", { name: /GET.*product/ }).click();
await page.getByText(/product · app.py:8/).waitFor();
await page.getByText(/redacted-secret/).first().waitFor({ timeout: 15000 });
await page.screenshot({
  path: resolve(screenshotDirectory, "code-analysis.png"),
  fullPage: true,
});

await page.goto(`${baseURL}/projects/${project.id}`);
await page.getByText("Scope registry").waitFor();
await page.screenshot({
  path: resolve(screenshotDirectory, "project-scope.png"),
  fullPage: true,
});

await page.goto(`${baseURL}/scans`);
await page.getByLabel("Project").selectOption({ label: projectName });
await page.getByLabel("Scan profile").selectOption("safe");
await page.getByLabel("Starting URL").fill("http://backend:8000/api/health?probe=1&next=/api/health");
await page.getByLabel("Maximum depth").fill("1");
await page.getByLabel("Maximum pages").fill("1");
await page.getByLabel("Maximum requests").fill("1");
await page.getByText(/http:\/\/backend:8000\/api\/health/).first().waitFor();
await page.screenshot({
  path: resolve(screenshotDirectory, "url-scanner.png"),
  fullPage: true,
});
await page.getByRole("button", { name: `Review ${plannedTestsCount} previews` }).click();
await page.getByText("Inert HTML reflection marker").waitFor();
await page.screenshot({
  path: resolve(screenshotDirectory, "safe-test-approval.png"),
  fullPage: false,
});

const har = JSON.stringify({
  log: {
    entries: [
      {
        request: {
          method: "GET",
          url: "https://ctf.example/challenge/search?q=hello",
          headers: [
            { name: "Accept", value: "text/html" },
            { name: "Authorization", value: "Bearer screenshot-demo-only" },
          ],
        },
        response: {
          status: 500,
          statusText: "Internal Server Error",
          time: 18.4,
          headers: [
            { name: "Content-Type", value: "text/html; charset=utf-8" },
            { name: "Access-Control-Allow-Origin", value: "*" },
            { name: "Access-Control-Allow-Credentials", value: "true" },
            { name: "Set-Cookie", value: "session=screenshot-demo-only" },
          ],
          content: {
            text: "<main><h1>Search</h1><p>hello</p></main> You have an error in your SQL syntax",
          },
        },
      },
    ],
  },
});

await page.goto(`${baseURL}/repeater`);
await page.getByLabel("Project").selectOption({ label: projectName });
await page
  .getByLabel("Workspace")
  .selectOption({ label: "Primary Workspace · controlled" });
await page.getByRole("button", { name: "har" }).click();
await page.getByLabel("HAR input").fill(har);
await page.getByLabel("Save for analysis").check();
await page.getByRole("button", { name: "Import & save" }).click();
await page.getByText("Imported response · 500").waitFor();
await page.screenshot({
  path: resolve(screenshotDirectory, "http-repeater.png"),
  fullPage: true,
});

await page.getByRole("button", { name: "Run 6 analyzers" }).click();
await page.getByText("Passive analysis workflow").waitFor();
const analysisCard = page
  .getByText("Passive analysis workflow")
  .locator("xpath=ancestor::div[contains(@class,'overflow-hidden')][1]");
await analysisCard.screenshot({
  path: resolve(screenshotDirectory, "analysis-results.png"),
});
await page.locator(".react-flow").screenshot({
  path: resolve(screenshotDirectory, "analysis-flow.png"),
});

await browser.close();
