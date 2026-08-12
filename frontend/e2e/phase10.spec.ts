import { expect, test } from "@playwright/test";

test("upload inert Flask source, extract a route, and view redacted code", async ({
  page,
  request,
}) => {
  const suffix = Date.now();
  const projectName = `Source Review ${suffix}`;
  const projectResponse = await request.post("/api/projects", {
    data: {
      name: projectName,
      description: "Authorized local source review",
      mode: "ctf",
    },
  });
  expect(projectResponse.ok()).toBeTruthy();

  await page.goto("/code-analysis");
  await page.getByLabel("Parent project").selectOption({ label: projectName });
  await page.getByLabel("Analysis name").fill("E2E Flask source");
  await page.getByLabel("Source files").setInputFiles({
    name: "app.py",
    mimeType: "text/x-python",
    buffer: Buffer.from(`from flask import Flask, request

app = Flask(__name__)
API_KEY = "e2e-secret-value"

@app.get("/search")
def search():
    value = request.args.get("q")
    query = f"SELECT * FROM products WHERE name = '{value}'"
    return cursor.execute(query)
`),
  });
  await page.getByLabel("Confirm source authorization").check();
  await page.getByRole("button", { name: "Validate & index" }).click();
  await expect(page.getByText("app.py").first()).toBeVisible();
  await expect(page.getByText("Secrets masked")).toBeVisible();
  await expect(page.getByText(/redacted-secret/).first()).toBeVisible();

  await page.getByRole("button", { name: "Analyze source flows" }).click();
  await expect(page.getByText("/search").first()).toBeVisible();
  await expect(page.getByText("Potential SQL Injection").first()).toBeVisible();
  await page.getByRole("button", { name: /Potential SQL Injection/ }).click();
  await expect(page.getByLabel("Source-to-Sink data flow")).toBeVisible();
  await expect(page.getByText("Safe remediation diff")).toBeVisible();
  await page.getByRole("button", { name: /GET.*search/ }).click();
  await expect(page.getByText(/search · app.py:7/)).toBeVisible();
  await expect(page.getByText("query:q")).toBeVisible();
});
