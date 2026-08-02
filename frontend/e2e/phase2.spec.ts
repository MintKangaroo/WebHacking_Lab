import { expect, test } from "@playwright/test";

test("create a local project, redact a request, and run passive analysis", async ({ page }) => {
  const projectName = `Playwright Local Lab ${Date.now()}`;
  await page.goto("/projects");
  await page.getByLabel("Project name").fill(projectName);
  await page
    .getByLabel("Description")
    .fill("Local-only E2E workspace created without target HTTP execution.");
  await page.getByRole("button", { name: "Create analysis project" }).click();

  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();

  await page.goto("/repeater");
  await expect(page.getByText("Normalized preview appears here")).toBeVisible();
  await page.getByRole("button", { name: "Import safely" }).click();

  await expect(page.getByText("Normalized request")).toBeVisible();
  await expect(page.getByText(/\[REDACTED\]/)).toBeVisible();

  await page.getByLabel("Project").selectOption({ label: projectName });
  await page
    .getByLabel("Workspace")
    .selectOption({ label: "Primary Workspace · analysis only" });
  await page.getByLabel("Save for analysis").check();
  await page.getByRole("button", { name: "Import & save" }).click();
  await page.getByRole("button", { name: "Run 6 analyzers" }).click();

  await expect(page.getByText("Passive analysis workflow")).toBeVisible();
  await expect(page.getByText("Candidates are observations", { exact: false })).toBeVisible();
});
