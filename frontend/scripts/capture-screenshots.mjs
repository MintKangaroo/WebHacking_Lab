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

await page.goto(`${baseURL}/`);
await page.getByRole("heading", { name: "Security analysis, under control." }).waitFor();
await page.screenshot({ path: resolve(screenshotDirectory, "dashboard.png"), fullPage: true });

await page.goto(`${baseURL}/projects/${project.id}`);
await page.getByText("Scope registry").waitFor();
await page.screenshot({
  path: resolve(screenshotDirectory, "project-scope.png"),
  fullPage: true,
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
