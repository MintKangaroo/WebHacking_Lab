import { expect, test } from "@playwright/test";

test("create a local project and preview a redacted request", async ({ page }) => {
  const projectName = `Playwright Local Lab ${Date.now()}`;
  await page.goto("/projects");
  await page.getByLabel("Project name").fill(projectName);
  await page
    .getByLabel("Description")
    .fill("Local-only E2E workspace created without target HTTP execution.");
  await page.getByRole("button", { name: "Create analysis project" }).click();

  await expect(page.getByRole("heading", { name: projectName })).toBeVisible();

  await page.goto("/repeater");
  await expect(page.getByText("Preview only")).toBeVisible();
  await page.getByRole("button", { name: "Import safely" }).click();

  await expect(page.getByText("Normalized request")).toBeVisible();
  await expect(page.getByText(/\[REDACTED\]/)).toBeVisible();
  await expect(page.getByText("no network request is sent", { exact: false })).toBeVisible();
});
